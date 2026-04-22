#pragma once

/* Harness that crafts WASM module bytes with valid magic header.
 *
 * Motivation: The workflow harness generates random WASM bytes that almost
 * always fail at "magic header not detected" in wasm_runtime_load_ex (28% cov).
 * This harness prepends the correct \0asm header and constructs plausible
 * section structures to exercise deeper loading/validation paths.
 *
 * Targets:
 *   - handle_cmd_load_module (36% cov → higher)
 *   - wasm_runtime_load_ex (28% cov → higher)
 *   - is_xip_file (12% cov → higher via AoT-style inputs)
 *   - wasm_runtime_full_init_internal (33% cov)
 */

static void harness_load_wasm_magic(void)
{
    /* ---- Phase 1: Init runtime ---- */
    {
        uint64_t args[1];
        args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 8);
        ecall_handle_command(__g_harness_eid, 0 /* CMD_INIT_RUNTIME */,
                             (unsigned char *)args, sizeof(args));
    }

    /* ---- Phase 2: Craft WASM bytes with valid header ---- */
    uint32_t module_handle_id = 0;
    {
        /* Choose module format: WASM or AoT-style */
        bool use_aot = g_fdp->ConsumeProbability<double>() < 0.2;

        uint32_t wasm_size = g_fdp->ConsumeIntegralInRange<uint32_t>(8, 512);
        uint8_t *wasm_buf = (uint8_t *)calloc(1, wasm_size);
        if (!wasm_buf) goto cleanup;

        if (use_aot) {
            /* AoT format: start with different magic to exercise is_xip_file */
            wasm_buf[0] = 0x00;
            wasm_buf[1] = 'a';
            wasm_buf[2] = 'o';
            wasm_buf[3] = 't';
            /* version */
            wasm_buf[4] = 0x01;
            wasm_buf[5] = 0x00;
            wasm_buf[6] = 0x00;
            wasm_buf[7] = 0x00;
            /* Fill rest with fuzzed data */
            if (wasm_size > 8)
                g_fdp->ConsumeData(wasm_buf + 8, wasm_size - 8);
        } else {
            /* Valid WASM magic header */
            wasm_buf[0] = 0x00;
            wasm_buf[1] = 'a';
            wasm_buf[2] = 's';
            wasm_buf[3] = 'm';
            /* Version 1 */
            wasm_buf[4] = 0x01;
            wasm_buf[5] = 0x00;
            wasm_buf[6] = 0x00;
            wasm_buf[7] = 0x00;

            /* Sometimes generate structured sections after header */
            if (g_fdp->ConsumeProbability<double>() < 0.6 && wasm_size > 16) {
                uint32_t pos = 8;

                /* Decide how many sections to generate */
                uint32_t num_sections = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 6);
                uint8_t section_ids[] = {0x01, 0x02, 0x03, 0x05, 0x07, 0x0a};

                for (uint32_t s = 0; s < num_sections && pos + 2 < wasm_size; s++) {
                    uint8_t sid = section_ids[s % 6];
                    /* Occasionally use a fuzzed section id for broader coverage */
                    if (g_fdp->ConsumeProbability<double>() < 0.1)
                        sid = g_fdp->ConsumeIntegralInRange<uint8_t>(0, 0x12);

                    wasm_buf[pos++] = sid;

                    /* Section size as LEB128 (1 byte for sizes < 128) */
                    uint32_t avail = wasm_size - pos - 1;
                    uint8_t section_size = (uint8_t)g_fdp->ConsumeIntegralInRange<uint32_t>(
                        1, avail < 120 ? avail : 120);
                    wasm_buf[pos++] = section_size;

                    /* Fill section content */
                    uint32_t fill = (pos + section_size <= wasm_size)
                                    ? section_size : (wasm_size - pos);
                    if (fill > 0) {
                        /* For type section (0x01), write a count byte first */
                        if (sid == 0x01 && fill >= 2) {
                            wasm_buf[pos] = g_fdp->ConsumeIntegralInRange<uint8_t>(0, 4);
                            pos++; fill--;
                        }
                        if (fill > 0) g_fdp->ConsumeData(wasm_buf + pos, fill);
                        pos += fill;
                    }
                    /* Ensure we wrote exactly section_size bytes */
                    if (pos > wasm_size) break;
                }
            } else if (g_fdp->ConsumeProbability<double>() < 0.3 && wasm_size >= 12) {
                /* Minimal valid WASM: just a type section with one functype */
                uint32_t pos = 8;
                wasm_buf[pos++] = 0x01; /* Type section id */
                wasm_buf[pos++] = 0x04; /* section size = 4 bytes */
                wasm_buf[pos++] = 0x01; /* 1 type entry */
                wasm_buf[pos++] = 0x60; /* func type */
                wasm_buf[pos++] = 0x00; /* 0 params */
                wasm_buf[pos++] = 0x00; /* 0 results */
                /* Fill rest with fuzzed data */
                if (pos < wasm_size) g_fdp->ConsumeData(wasm_buf + pos, wasm_size - pos);
            } else {
                /* Random fuzzed bytes after header */
                if (wasm_size > 8)
                    g_fdp->ConsumeData(wasm_buf + 8, wasm_size - 8);
            }
        }

        char error_buf[256];
        uint64_t args[4];
        args[0] = (uint64_t)(uintptr_t)wasm_buf;
        args[1] = (uint64_t)wasm_size;
        args[2] = (uint64_t)(uintptr_t)error_buf;
        args[3] = (uint64_t)sizeof(error_buf);

        ecall_handle_command(__g_harness_eid, 1 /* CMD_LOAD_MODULE */,
                             (unsigned char *)args, sizeof(args));
        module_handle_id = (uint32_t)args[0];
    }

    if (module_handle_id == 0) goto cleanup;

    /* ---- Phase 3: Try to instantiate (optional) ---- */
    if (g_fdp->ConsumeBool()) {
        char error_buf[256];
        uint32_t stack_size = g_fdp->ConsumeIntegralInRange<uint32_t>(8192, 65536);
        uint32_t heap_size = g_fdp->ConsumeIntegralInRange<uint32_t>(8192, 65536);
        uint64_t args[5];
        args[0] = (uint64_t)module_handle_id;
        args[1] = (uint64_t)stack_size;
        args[2] = (uint64_t)heap_size;
        args[3] = (uint64_t)(uintptr_t)error_buf;
        args[4] = (uint64_t)sizeof(error_buf);

        ecall_handle_command(__g_harness_eid, 2 /* CMD_INSTANTIATE_MODULE */,
                             (unsigned char *)args, sizeof(args));
        uint32_t instance_handle_id = (uint32_t)args[0];

        if (instance_handle_id != 0) {
            /* Optionally set WASI args before execution (12 args required) */
            if (g_fdp->ConsumeBool()) {
                /* Build outside-enclave string arrays for WASI */
                uint32_t dir_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3);
                uint32_t env_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3);
                uint32_t wasi_argc = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3);
                uint32_t addr_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);

                /* Allocate string arrays outside-enclave (using calloc→arena) */
                char **dir_list = (char **)calloc(dir_count > 0 ? dir_count : 1, sizeof(char *));
                char **env_list = (char **)calloc(env_count > 0 ? env_count : 1, sizeof(char *));
                char **wasi_argv_arr = (char **)calloc(wasi_argc > 0 ? wasi_argc : 1, sizeof(char *));
                char **addr_pool = (char **)calloc(addr_count > 0 ? addr_count : 1, sizeof(char *));

                /* Fill dir strings */
                for (uint32_t i = 0; i < dir_count; i++) {
                    dir_list[i] = (char *)calloc(1, 16);
                    g_fdp->ConsumeData(dir_list[i], 15);
                    dir_list[i][15] = '\0';
                }
                /* Fill env strings */
                for (uint32_t i = 0; i < env_count; i++) {
                    env_list[i] = (char *)calloc(1, 16);
                    g_fdp->ConsumeData(env_list[i], 15);
                    env_list[i][15] = '\0';
                }
                /* Fill wasi_argv strings */
                for (uint32_t i = 0; i < wasi_argc; i++) {
                    wasi_argv_arr[i] = (char *)calloc(1, 16);
                    g_fdp->ConsumeData(wasi_argv_arr[i], 15);
                    wasi_argv_arr[i][15] = '\0';
                }
                /* Fill addr_pool strings */
                for (uint32_t i = 0; i < addr_count; i++) {
                    addr_pool[i] = (char *)calloc(1, 16);
                    g_fdp->ConsumeData(addr_pool[i], 15);
                    addr_pool[i][15] = '\0';
                }

                uint64_t wasi_args[12];
                wasi_args[0] = (uint64_t)module_handle_id;
                wasi_args[1] = (uint64_t)(uintptr_t)dir_list;
                wasi_args[2] = (uint64_t)dir_count;
                wasi_args[3] = (uint64_t)(uintptr_t)env_list;
                wasi_args[4] = (uint64_t)env_count;
                wasi_args[5] = (uint64_t)g_fdp->ConsumeIntegral<int>(); /* stdinfd */
                wasi_args[6] = (uint64_t)g_fdp->ConsumeIntegral<int>(); /* stdoutfd */
                wasi_args[7] = (uint64_t)g_fdp->ConsumeIntegral<int>(); /* stderrfd */
                wasi_args[8] = (uint64_t)(uintptr_t)wasi_argv_arr;
                wasi_args[9] = (uint64_t)wasi_argc;
                wasi_args[10] = (uint64_t)(uintptr_t)addr_pool;
                wasi_args[11] = (uint64_t)addr_count;
                ecall_handle_command(__g_harness_eid, 12 /* CMD_SET_WASI_ARGS */,
                                     (unsigned char *)wasi_args, sizeof(wasi_args));
            }

            /* Try exec_app_main with proper argc matching */
            if (g_fdp->ConsumeBool()) {
                uint32_t app_argc = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
                /* Allocate args array: 2 fixed (instance_id, app_argc) + app_argc string ptrs */
                uint32_t total_args = 2 + app_argc;
                uint64_t *exec_args = (uint64_t *)calloc(total_args, sizeof(uint64_t));
                exec_args[0] = (uint64_t)instance_handle_id;
                exec_args[1] = (uint64_t)app_argc;
                for (uint32_t i = 0; i < app_argc; i++) {
                    char *s = (char *)calloc(1, 8);
                    g_fdp->ConsumeData(s, 7);
                    s[7] = '\0';
                    exec_args[2 + i] = (uint64_t)(uintptr_t)s;
                }
                ecall_handle_command(__g_harness_eid, 7 /* CMD_EXEC_APP_MAIN */,
                                     (unsigned char *)exec_args, total_args * sizeof(uint64_t));
            }

            /* Try exec_app_func with varied args */
            if (g_fdp->ConsumeBool()) {
                char func_name[16];
                g_fdp->ConsumeData(func_name, sizeof(func_name) - 1);
                func_name[sizeof(func_name) - 1] = '\0';

                uint32_t func_argc = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 4);
                uint32_t total_func_args = 3 + func_argc;
                uint64_t *exec_args = (uint64_t *)calloc(total_func_args, sizeof(uint64_t));
                exec_args[0] = (uint64_t)instance_handle_id;
                exec_args[1] = (uint64_t)(uintptr_t)func_name;
                exec_args[2] = (uint64_t)func_argc;
                for (uint32_t i = 0; i < func_argc; i++) {
                    char *s = (char *)calloc(1, 8);
                    g_fdp->ConsumeData(s, 7);
                    s[7] = '\0';
                    exec_args[3 + i] = (uint64_t)(uintptr_t)s;
                }
                ecall_handle_command(__g_harness_eid, 6 /* CMD_EXEC_APP_FUNC */,
                                     (unsigned char *)exec_args, total_func_args * sizeof(uint64_t));
            }

            /* Deinstantiate — also test double-deinstantiate for coverage */
            {
                uint64_t args[1];
                args[0] = (uint64_t)instance_handle_id;
                ecall_handle_command(__g_harness_eid, 9 /* CMD_DEINSTANTIATE_MODULE */,
                                     (unsigned char *)args, sizeof(args));
                /* Double deinstantiate to test error path */
                if (g_fdp->ConsumeBool()) {
                    ecall_handle_command(__g_harness_eid, 9 /* CMD_DEINSTANTIATE_MODULE */,
                                         (unsigned char *)args, sizeof(args));
                }
            }
        }
    }

    /* Unload module */
    {
        uint64_t args[1];
        args[0] = (uint64_t)module_handle_id;
        ecall_handle_command(__g_harness_eid, 10 /* CMD_UNLOAD_MODULE */,
                             (unsigned char *)args, sizeof(args));
    }

cleanup:
    /* Destroy runtime */
    ecall_handle_command(__g_harness_eid, 11 /* CMD_DESTROY_RUNTIME */,
                         NULL, 0);
}

HARNESS_REGISTER(harness_load_wasm_magic, 40)
