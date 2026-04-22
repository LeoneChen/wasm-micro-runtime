#pragma once

/* Workflow harness: chains the full WASM lifecycle inside the enclave.
 *
 * The random single-command harness (harness_ecall_handle_command) rarely
 * reaches deep paths because most handlers early-return when !runtime_inited.
 * This harness solves that by establishing runtime state first, then
 * exercising the full init→load→instantiate→execute→cleanup lifecycle
 * with fuzzed WASM module bytes.
 *
 * CMD enum (from app.h / Enclave.cpp):
 *   CMD_INIT_RUNTIME         = 0
 *   CMD_LOAD_MODULE          = 1
 *   CMD_INSTANTIATE_MODULE   = 2
 *   CMD_LOOKUP_FUNCTION      = 3
 *   CMD_CREATE_EXEC_ENV      = 4
 *   CMD_CALL_WASM            = 5
 *   CMD_EXEC_APP_FUNC        = 6
 *   CMD_EXEC_APP_MAIN        = 7
 *   CMD_GET_EXCEPTION        = 8
 *   CMD_DEINSTANTIATE_MODULE = 9
 *   CMD_UNLOAD_MODULE        = 10
 *   CMD_DESTROY_RUNTIME      = 11
 *   CMD_SET_WASI_ARGS        = 12
 *   CMD_SET_LOG_LEVEL        = 13
 *   CMD_GET_VERSION          = 14
 */

/* Error buffer for load/instantiate calls */
static char g_workflow_error_buf[256];

/* Helper: send a command with uint64 args array */
static void workflow_send_cmd(unsigned int cmd, uint64_t *args, uint32_t argc) {
    ecall_handle_command(__g_harness_eid, cmd,
                         (unsigned char *)args, argc * sizeof(uint64_t));
}

static void harness_workflow_full_lifecycle(void)
{
    /* ---- Phase 0: Fuzz decision flags ---- */
    bool do_exec_func   = g_fdp->ConsumeBool();
    bool do_get_except  = g_fdp->ConsumeBool();
    bool do_set_log     = g_fdp->ConsumeBool();
    bool do_get_version = g_fdp->ConsumeBool();
    bool do_lookup_func = g_fdp->ConsumeBool();
    bool do_double_init = g_fdp->ConsumeBool();
    bool do_invalid_cmd = g_fdp->ConsumeBool();
    /* Fuzz stack/heap sizes for instantiation (within reasonable range) */
    uint32_t stack_size = g_fdp->ConsumeIntegralInRange<uint32_t>(8192, 1 << 20);
    uint32_t heap_size  = g_fdp->ConsumeIntegralInRange<uint32_t>(8192, 1 << 20);
    /* Thread count for runtime init */
    uint32_t max_threads = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 16);

    /* ---- Phase 1: CMD_INIT_RUNTIME ---- */
    {
        uint64_t args[1];
        args[0] = (uint64_t)max_threads;
        workflow_send_cmd(0 /* CMD_INIT_RUNTIME */, args, 1);
    }

    /* ---- Phase 1b: Double init (test idempotency) ---- */
    if (do_double_init) {
        uint64_t args[1];
        args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 32);
        workflow_send_cmd(0 /* CMD_INIT_RUNTIME */, args, 1);
    }

    /* ---- Phase 2: CMD_SET_LOG_LEVEL (optional, lightweight) ---- */
    if (do_set_log) {
        uint64_t args[1];
        args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<unsigned int>(0, 4);
        workflow_send_cmd(13 /* CMD_SET_LOG_LEVEL */, args, 1);
    }

    /* ---- Phase 3: CMD_GET_VERSION (optional, lightweight) ---- */
    if (do_get_version) {
        uint64_t args[3] = {0, 0, 0};
        workflow_send_cmd(14 /* CMD_GET_VERSION */, args, 3);
    }

    /* ---- Phase 3b: Random invalid cmd (test default case) ---- */
    if (do_invalid_cmd) {
        unsigned int bad_cmd = g_fdp->ConsumeIntegralInRange<unsigned int>(17, 255);
        uint64_t args[2] = {0, 0};
        workflow_send_cmd(bad_cmd, args, 2);
    }

    /* ---- Phase 4: CMD_LOAD_MODULE with WASM bytes ---- */
    uint32_t module_handle_id = 0;
    bool do_set_wasi = g_fdp->ConsumeBool();
    {
        uint32_t load_mode = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 5);
        uint8_t *wasm_buf = NULL;
        uint32_t wasm_size = 0;

        if (load_mode == 0) {
            /* Mode 0: Valid minimal WASM with "_start" export.
             * Works for WASI path when SET_WASI_ARGS is called. */
            static const uint8_t s_valid_minimal[] = {
                0x00, 0x61, 0x73, 0x6d,  /* magic */
                0x01, 0x00, 0x00, 0x00,  /* version */
                /* Type section: 1 type, () -> () */
                0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
                /* Function section: 1 func, type 0 */
                0x03, 0x02, 0x01, 0x00,
                /* Export section: "_start" = func 0 */
                0x07, 0x09, 0x01, 0x06,
                0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
                0x00, 0x00,
                /* Code section: 1 body, size=2, 0 locals, end */
                0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
            };
            wasm_size = sizeof(s_valid_minimal);
            wasm_buf = (uint8_t *)calloc(1, wasm_size);
            if (!wasm_buf) return;
            memcpy(wasm_buf, s_valid_minimal, wasm_size);
        } else if (load_mode == 1) {
            /* Mode 1: Valid WASM with correct WASI import signatures.
             * Imports args_get (i32,i32)->i32 and fd_write (i32,i32,i32,i32)->i32.
             * _start body calls both to trigger OCall wrappers.
             * Func indices: 0=args_get, 1=fd_write, 2=_start */
            static const uint8_t s_valid_wasi_exec[] = {
                0x00, 0x61, 0x73, 0x6d,
                0x01, 0x00, 0x00, 0x00,
                /* Type section: 3 types */
                0x01, 0x12, 0x03,
                0x60, 0x00, 0x00,              /* type 0: () -> () */
                0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,  /* type 1: (i32,i32) -> i32 */
                0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,  /* type 2: (i32,i32,i32,i32) -> i32 */
                /* Import section: 2 WASI imports */
                0x02, 0x43, 0x02,
                0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
                0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
                0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
                0x08, 0x61, 0x72, 0x67, 0x73, 0x5f, 0x67, 0x65, 0x74,
                0x00, 0x01,
                0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
                0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
                0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
                0x08, 0x66, 0x64, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65,
                0x00, 0x02,
                /* Function section: 1 local func, type 0 */
                0x03, 0x02, 0x01, 0x00,
                /* Export section: "_start" = func 2 */
                0x07, 0x09, 0x01, 0x06,
                0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
                0x00, 0x02,
                /* Code section: 1 body — calls args_get and fd_write */
                0x0a, 0x16, 0x01,
                0x14, 0x00,              /* body size=20, 0 locals */
                0x41, 0x00,              /* i32.const 0 */
                0x41, 0x00,              /* i32.const 0 */
                0x10, 0x00,              /* call 0 (args_get) */
                0x1a,                    /* drop */
                0x41, 0x01,              /* i32.const 1 */
                0x41, 0x00,              /* i32.const 0 */
                0x41, 0x00,              /* i32.const 0 */
                0x41, 0x00,              /* i32.const 0 */
                0x10, 0x01,              /* call 1 (fd_write) */
                0x1a,                    /* drop */
                0x0b,                    /* end */
            };
            wasm_size = sizeof(s_valid_wasi_exec);
            wasm_buf = (uint8_t *)calloc(1, wasm_size);
            if (!wasm_buf) return;
            memcpy(wasm_buf, s_valid_wasi_exec, wasm_size);
        } else if (load_mode == 2) {
            /* Mode 2: Valid template with memory section.
             * Tests memory-related paths in wasm_runtime_load/instantiate. */
            static const uint8_t s_valid_memory[] = {
                0x00, 0x61, 0x73, 0x6d,
                0x01, 0x00, 0x00, 0x00,
                0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
                0x03, 0x02, 0x01, 0x00,
                0x05, 0x03, 0x01, 0x00, 0x01,
                0x07, 0x11, 0x02,
                0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
                0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
                0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
            };
            wasm_size = sizeof(s_valid_memory);
            wasm_buf = (uint8_t *)calloc(1, wasm_size);
            if (!wasm_buf) return;
            memcpy(wasm_buf, s_valid_memory, wasm_size);
        } else if (load_mode == 3) {
            /* Mode 3: Fully fuzzed WASM bytes (original behavior).
             * Covers error paths in wasm_runtime_load.
             * Max size kept small (256) to avoid data budget exhaustion —
             * cov regression from 861→818 traced to mode 3 consuming
             * up to 8192 bytes and starving other harnesses. */
            wasm_size = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 256);
            wasm_buf = (uint8_t *)calloc(1, wasm_size);
            if (!wasm_buf) return;

            /* ~40% chance to prepend valid WASM magic header */
            if (g_fdp->ConsumeProbability<double>() < 0.4 && wasm_size >= 8) {
                wasm_buf[0] = 0x00; wasm_buf[1] = 'a';
                wasm_buf[2] = 's';  wasm_buf[3] = 'm';
                wasm_buf[4] = 0x01; wasm_buf[5] = 0x00;
                wasm_buf[6] = 0x00; wasm_buf[7] = 0x00;
                if (wasm_size > 8)
                    g_fdp->ConsumeData(wasm_buf + 8, wasm_size - 8);
            } else {
                g_fdp->ConsumeData(wasm_buf, wasm_size);
            }
        } else if (load_mode == 4) {
            /* Mode 4: WASI with memory + fd_write (correct signature).
             * Import 0: fd_write (type 0: (i32,i32,i32,i32) -> i32)
             * Local 1: _start (type 1: () -> ()) */
            static const uint8_t s_valid_wasi_mem[] = {
                0x00, 0x61, 0x73, 0x6d,
                0x01, 0x00, 0x00, 0x00,
                /* Type section: 2 types */
                0x01, 0x0c, 0x02,
                0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,  /* type 0: (i32,i32,i32,i32) -> i32 */
                0x60, 0x00, 0x00,              /* type 1: () -> () */
                /* Import section: 1 WASI import (fd_write) */
                0x02, 0x1a, 0x01,
                0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
                0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
                0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
                0x08, 0x66, 0x64, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65,
                0x00, 0x00,
                /* Function section: 1 local func, type 1 */
                0x03, 0x02, 0x01, 0x01,
                /* Memory section: 1 memory, min=1 */
                0x05, 0x03, 0x01, 0x00, 0x01,
                /* Export section: "_start" = func 1, "memory" = memory 0 */
                0x07, 0x11, 0x02,
                0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01,
                0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
                /* Code section: stores to memory, calls fd_write with 4 args */
                0x0a, 0x16, 0x01,
                0x14, 0x00,                    /* body size=20, 0 locals */
                0x41, 0x00,                    /* i32.const 0 (addr) */
                0x41, 0x48,                    /* i32.const 72 ('H') */
                0x36, 0x02, 0x00,              /* i32.store offset=0 */
                0x41, 0x01,                    /* i32.const 1 (fd) */
                0x41, 0x00,                    /* i32.const 0 (iovs) */
                0x41, 0x00,                    /* i32.const 0 (iovs_len) */
                0x41, 0x00,                    /* i32.const 0 (nwritten) */
                0x10, 0x00,                    /* call 0 (fd_write) */
                0x1a,                          /* drop */
                0x0b,                          /* end */
            };
            wasm_size = sizeof(s_valid_wasi_mem);
            wasm_buf = (uint8_t *)calloc(1, wasm_size);
            if (!wasm_buf) return;
            memcpy(wasm_buf, s_valid_wasi_mem, wasm_size);
        } else if (load_mode == 5) {
            /* Mode 5: Non-WASI "main" export for non-WASI execute_main path.
             * Exports "main" with type () -> (). When SET_WASI_ARGS is skipped,
             * execute_main looks for "main" instead of "_start".
             * This bypasses WASI entirely. */
            static const uint8_t s_valid_main[] = {
                0x00, 0x61, 0x73, 0x6d,
                0x01, 0x00, 0x00, 0x00,
                /* Type section: 1 type, () -> () */
                0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
                /* Function section: 1 func, type 0 */
                0x03, 0x02, 0x01, 0x00,
                /* Export section: "main" = func 0 */
                0x07, 0x08, 0x01, 0x04,
                0x6d, 0x61, 0x69, 0x6e,  /* "main" */
                0x00, 0x00,
                /* Code section: 1 body, size=2, 0 locals, end */
                0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
            };
            wasm_size = sizeof(s_valid_main);
            wasm_buf = (uint8_t *)calloc(1, wasm_size);
            if (!wasm_buf) return;
            memcpy(wasm_buf, s_valid_main, wasm_size);
        }

        uint64_t args[4];
        args[0] = (uint64_t)(uintptr_t)wasm_buf;    /* wasm_file pointer */
        args[1] = (uint64_t)wasm_size;               /* wasm_file_size */
        args[2] = (uint64_t)(uintptr_t)g_workflow_error_buf; /* error_buf */
        args[3] = (uint64_t)sizeof(g_workflow_error_buf);    /* error_buf_size */

        workflow_send_cmd(1 /* CMD_LOAD_MODULE */, args, 4);
        module_handle_id = (uint32_t)args[0];
    }

    if (module_handle_id == 0) {
        /* Load failed, try to destroy runtime and return */
        workflow_send_cmd(11 /* CMD_DESTROY_RUNTIME */, NULL, 0);
        return;
    }

    /* ---- Phase 5: CMD_SET_WASI_ARGS (conditional) ---- */
    if (do_set_wasi) {
        /* Call SET_WASI_ARGS when we have a valid module handle.
         * This enables WASI mode; execute_main will look for "_start".
         * When skipped, execute_main looks for "main" (non-WASI path).
         * Both paths are now exercised depending on load_mode + do_set_wasi. */
        uint32_t dir_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);
        uint32_t env_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);
        uint32_t argv_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);

        /* dir_list: array of char* followed by string data.
         * Buffer sizes kept small (16b) to avoid data budget exhaustion. */
        char **dir_list = NULL;
        char dir_bufs[2][16];
        if (dir_count > 0) {
            dir_list = (char **)calloc(dir_count, sizeof(char *));
            if (dir_list) {
                for (uint32_t i = 0; i < dir_count; i++) {
                    g_fdp->ConsumeData(dir_bufs[i], sizeof(dir_bufs[i]) - 1);
                    dir_bufs[i][sizeof(dir_bufs[i]) - 1] = '\0';
                    dir_list[i] = dir_bufs[i];
                }
            }
        }

        /* env_list: array of char* followed by string data */
        char **env_list = NULL;
        char env_bufs[2][16];
        if (env_count > 0) {
            env_list = (char **)calloc(env_count, sizeof(char *));
            if (env_list) {
                for (uint32_t i = 0; i < env_count; i++) {
                    g_fdp->ConsumeData(env_bufs[i], sizeof(env_bufs[i]) - 1);
                    env_bufs[i][sizeof(env_bufs[i]) - 1] = '\0';
                    env_list[i] = env_bufs[i];
                }
            }
        }

        /* wasi_argv: array of char* */
        char **wasi_argv = NULL;
        char argv_bufs[2][16];
        if (argv_count > 0) {
            wasi_argv = (char **)calloc(argv_count, sizeof(char *));
            if (wasi_argv) {
                for (uint32_t i = 0; i < argv_count; i++) {
                    g_fdp->ConsumeData(argv_bufs[i], sizeof(argv_bufs[i]) - 1);
                    argv_bufs[i][sizeof(argv_bufs[i]) - 1] = '\0';
                    wasi_argv[i] = argv_bufs[i];
                }
            }
        }

        uint64_t args[12];
        memset(args, 0, sizeof(args));
        args[0] = (uint64_t)module_handle_id;    /* module_handle_id */
        args[1] = (uint64_t)(uintptr_t)dir_list;  /* dir_list */
        args[2] = (uint64_t)dir_count;             /* dir_list_size */
        args[3] = (uint64_t)(uintptr_t)env_list;  /* env_list */
        args[4] = (uint64_t)env_count;             /* env_list_size */
        args[5] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(-1, 10); /* stdinfd */
        args[6] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(-1, 10); /* stdoutfd */
        args[7] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(-1, 10); /* stderrfd */
        args[8] = (uint64_t)(uintptr_t)wasi_argv; /* wasi_argv */
        args[9] = (uint64_t)argv_count;            /* wasi_argc */
        args[10] = 0;                              /* addr_pool_list (NULL) */
        args[11] = 0;                              /* addr_pool_list_size */
        workflow_send_cmd(12 /* CMD_SET_WASI_ARGS */, args, 12);
    }

    /* ---- Phase 6: CMD_INSTANTIATE_MODULE ---- */
    uint32_t instance_handle_id = 0;
    {
        uint64_t args[5];
        args[0] = (uint64_t)module_handle_id;
        args[1] = (uint64_t)stack_size;
        args[2] = (uint64_t)heap_size;
        args[3] = (uint64_t)(uintptr_t)g_workflow_error_buf;
        args[4] = (uint64_t)sizeof(g_workflow_error_buf);

        workflow_send_cmd(2 /* CMD_INSTANTIATE_MODULE */, args, 5);
        instance_handle_id = (uint32_t)args[0];
    }

    if (instance_handle_id == 0) {
        /* Instantiation failed, cleanup module and runtime */
        {
            uint64_t args[1];
            args[0] = (uint64_t)module_handle_id;
            workflow_send_cmd(10 /* CMD_UNLOAD_MODULE */, args, 1);
        }
        workflow_send_cmd(11 /* CMD_DESTROY_RUNTIME */, NULL, 0);
        return;
    }

    /* ---- Phase 6b: CMD_LOOKUP_FUNCTION (optional) ---- */
    if (do_lookup_func) {
        /* lookup_function needs: instance_handle_id, function_name pointer */
        char func_name[32];
        g_fdp->ConsumeData(func_name, sizeof(func_name) - 1);
        func_name[sizeof(func_name) - 1] = '\0';
        uint64_t args[2];
        args[0] = (uint64_t)instance_handle_id;
        args[1] = (uint64_t)(uintptr_t)func_name;
        workflow_send_cmd(3 /* CMD_LOOKUP_FUNCTION */, args, 2);
    }

    /* ---- Phase 7: CMD_EXEC_APP_MAIN (always call when instance valid) ---- */
    {
        /* Always attempt EXEC_APP_MAIN with a valid instance.
         * This targets wasm_application_execute_main (0/3 edges),
         * execute_main (0/31 edges), check_main_func_type (0/12 edges). */
        uint32_t app_argc = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 8);
        uint64_t args[3];
        args[0] = (uint64_t)instance_handle_id;
        args[1] = (uint64_t)app_argc;
        args[2] = (uint64_t)(uintptr_t)"a"; /* argv[0] */
        workflow_send_cmd(7 /* CMD_EXEC_APP_MAIN */, args, 3);
    }

    /* ---- Phase 8: CMD_EXEC_APP_FUNC (optional) ---- */
    if (do_exec_func) {
        char func_name[16];
        g_fdp->ConsumeData(func_name, sizeof(func_name) - 1);
        func_name[sizeof(func_name) - 1] = '\0';

        uint64_t args[4];
        args[0] = (uint64_t)instance_handle_id;
        args[1] = (uint64_t)(uintptr_t)func_name;
        args[2] = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 8); /* app_argc */
        args[3] = 0;
        workflow_send_cmd(6 /* CMD_EXEC_APP_FUNC */, args, 4);
    }

    /* ---- Phase 9: CMD_GET_EXCEPTION (optional) ---- */
    if (do_get_except) {
        char except_buf[128];
        uint64_t args[3];
        args[0] = (uint64_t)instance_handle_id;
        args[1] = (uint64_t)(uintptr_t)except_buf;
        args[2] = (uint64_t)sizeof(except_buf);
        workflow_send_cmd(8 /* CMD_GET_EXCEPTION */, args, 3);
    }

    /* ---- Phase 10: Duplicate cleanup attempt (test robustness) ---- */
    if (g_fdp->ConsumeProbability<double>() < 0.2) {
        /* Try to deinstantiate before normal cleanup to test double-free */
        uint64_t args[1];
        args[0] = (uint64_t)instance_handle_id;
        workflow_send_cmd(9 /* CMD_DEINSTANTIATE_MODULE */, args, 1);
    }

    /* ---- Phase 11: Cleanup ---- */
    {
        uint64_t args[1];
        args[0] = (uint64_t)instance_handle_id;
        workflow_send_cmd(9 /* CMD_DEINSTANTIATE_MODULE */, args, 1);
    }
    {
        uint64_t args[1];
        args[0] = (uint64_t)module_handle_id;
        workflow_send_cmd(10 /* CMD_UNLOAD_MODULE */, args, 1);
    }

    /* ---- Phase 11b: Double destroy test ---- */
    if (g_fdp->ConsumeBool()) {
        /* Try to unload already-unloaded module */
        uint64_t args[1];
        args[0] = (uint64_t)module_handle_id;
        workflow_send_cmd(10 /* CMD_UNLOAD_MODULE */, args, 1);
    }

    workflow_send_cmd(11 /* CMD_DESTROY_RUNTIME */, NULL, 0);

    /* ---- Phase 11c: Use-after-destroy test ---- */
    if (g_fdp->ConsumeProbability<double>() < 0.15) {
        /* Try commands after runtime is destroyed */
        uint64_t args[3] = {0, 0, 0};
        workflow_send_cmd(14 /* CMD_GET_VERSION */, args, 3);
        workflow_send_cmd(8 /* CMD_GET_EXCEPTION */, args, 3);
    }
}

HARNESS_REGISTER(harness_workflow_full_lifecycle, 25)
