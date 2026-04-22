#pragma once

/* Harness that generates structurally valid WASM modules.
 *
 * Motivation: Previous harnesses generate random/fuzzed WASM bytes that
 * almost always fail at "magic header not detected" or early section
 * validation. Last fuzz run reached load_type_section, load_import_section,
 * load_code_section etc. as NEW_FUNC, but wasm_instantiate is still at 16%
 * (20/124 edges, only 1 hit).
 *
 * The key insight: a valid WASM binary needs sections in order, with matching
 * counts between function/code sections, valid type indices, and proper LEB128
 * encoding. Random fuzzing almost never produces valid combinations.
 *
 * This harness generates minimal valid WASM modules with:
 * - Correct magic header + version
 * - Type section with 1-4 function types (0x60 flag, valid param/result types)
 * - Function section referencing those types
 * - Export section exporting functions (e.g. "_start", "main")
 * - Code section with matching function bodies
 * - Optional: memory section, table section, global section, data section
 *
 * Targets:
 *   - wasm_instantiate: 16% → 40%+
 *   - execute_post_instantiate_functions: 13% → 30%+
 *   - load_code_section: deeper path coverage
 *   - handle_cmd_exec_app_main: 38% → 60%+
 *   - handle_cmd_set_wasi_args: 12% → 30%+ (via valid module path)
 */

/* Helper: write LEB128 unsigned integer, returns bytes written */
static int write_leb128(uint8_t *buf, uint32_t value) {
    int count = 0;
    do {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value != 0) byte |= 0x80;
        buf[count++] = byte;
    } while (value != 0);
    return count;
}

/* Valid WASM value types */
#define VALTYPE_I32 0x7F
#define VALTYPE_I64 0x7E
#define VALTYPE_F32 0x7D
#define VALTYPE_F64 0x7C

static void harness_valid_wasm(void)
{
    /* ---- Phase 1: Init runtime ---- */
    {
        uint64_t args[1];
        args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 8);
        ecall_handle_command(__g_harness_eid, 0 /* CMD_INIT_RUNTIME */,
                             (unsigned char *)args, sizeof(args));
    }

    /* ---- Phase 2: Build valid WASM module ---- */
    uint32_t module_handle_id = 0;
    {
        /* Buffer for WASM binary - modules are small, don't waste data */
        uint32_t buf_size = g_fdp->ConsumeIntegralInRange<uint32_t>(64, 512);
        uint8_t *buf = (uint8_t *)calloc(1, buf_size);
        if (!buf) goto cleanup;
        uint32_t pos = 0;

        /* -- WASM Header -- */
        buf[pos++] = 0x00; buf[pos++] = 'a';
        buf[pos++] = 's';  buf[pos++] = 'm';
        buf[pos++] = 0x01; buf[pos++] = 0x00;
        buf[pos++] = 0x00; buf[pos++] = 0x00;

        /* -- Choose module complexity -- */
        uint32_t complexity = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 4);

        /* Number of function types (1-4) */
        uint32_t num_types = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
        /* Number of functions (must match code bodies) */
        uint32_t num_funcs = g_fdp->ConsumeIntegralInRange<uint32_t>(1,
                                      num_types > 2 ? 3 : num_types);
        /* Whether to include memory section */
        bool has_memory = g_fdp->ConsumeBool();
        /* Whether to include export section */
        bool has_export = g_fdp->ConsumeBool();
        /* Whether to include data section */
        bool has_data = has_memory && g_fdp->ConsumeBool();

        /* ---- Type Section (id=1) ---- */
        {
            /* Build type section body first, then wrap with section header */
            uint32_t type_body_start = pos;
            /* Reserve space for section header (id + LEB128 size) - we'll fill later */
            pos += 4; /* max 4 bytes for header */

            /* Count of types */
            pos += write_leb128(buf + pos, num_types);

            for (uint32_t t = 0; t < num_types; t++) {
                if (pos + 10 >= buf_size) break;
                /* func type flag */
                buf[pos++] = 0x60;

                /* Parameter count and types */
                uint32_t param_count;
                if (complexity >= 2) {
                    param_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 4);
                } else {
                    param_count = 0;
                }
                pos += write_leb128(buf + pos, param_count);
                for (uint32_t p = 0; p < param_count; p++) {
                    uint8_t vtypes[] = {VALTYPE_I32, VALTYPE_I64, VALTYPE_F32, VALTYPE_F64};
                    buf[pos++] = vtypes[g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3)];
                }

                /* Result count and types */
                uint32_t result_count;
                if (complexity >= 3) {
                    result_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);
                } else {
                    result_count = 0;
                }
                pos += write_leb128(buf + pos, result_count);
                for (uint32_t r = 0; r < result_count; r++) {
                    uint8_t vtypes[] = {VALTYPE_I32, VALTYPE_I64, VALTYPE_F32, VALTYPE_F64};
                    buf[pos++] = vtypes[g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3)];
                }
            }

            /* Write section header */
            uint32_t type_body_size = pos - (type_body_start + 4);
            uint32_t hdr_pos = type_body_start;
            buf[hdr_pos++] = 0x01; /* Type section id */
            hdr_pos += write_leb128(buf + hdr_pos, type_body_size);
            /* Shift body if header was smaller than 4 bytes */
            uint32_t hdr_used = hdr_pos - type_body_start;
            if (hdr_used < 4) {
                memmove(buf + hdr_pos, buf + type_body_start + 4, type_body_size);
                pos = hdr_pos + type_body_size;
            }
        }

        /* ---- Function Section (id=3) ---- */
        {
            uint32_t func_body_start = pos;
            pos += 4; /* reserve for header */

            /* Count of functions */
            pos += write_leb128(buf + pos, num_funcs);
            for (uint32_t f = 0; f < num_funcs; f++) {
                /* Type index (references types defined above) */
                uint32_t type_idx = g_fdp->ConsumeIntegralInRange<uint32_t>(0, num_types - 1);
                pos += write_leb128(buf + pos, type_idx);
            }

            uint32_t func_body_size = pos - (func_body_start + 4);
            uint32_t hdr_pos = func_body_start;
            buf[hdr_pos++] = 0x03; /* Function section id */
            hdr_pos += write_leb128(buf + hdr_pos, func_body_size);
            uint32_t hdr_used = hdr_pos - func_body_start;
            if (hdr_used < 4) {
                memmove(buf + hdr_pos, buf + func_body_start + 4, func_body_size);
                pos = hdr_pos + func_body_size;
            }
        }

        /* ---- Optional: Table Section (id=4) ---- */
        if (complexity >= 3 && g_fdp->ConsumeBool() && pos + 10 < buf_size) {
            uint32_t tbl_body_start = pos;
            pos += 3; /* reserve */
            pos += write_leb128(buf + pos, 1); /* 1 table */
            buf[pos++] = 0x70; /* funcref */
            buf[pos++] = 0x00; /* limits: no max */
            pos += write_leb128(buf + pos, g_fdp->ConsumeIntegralInRange<uint32_t>(1, 10));
            uint32_t tbl_body_size = pos - (tbl_body_start + 3);
            buf[tbl_body_start] = 0x04;
            uint32_t sz_written = write_leb128(buf + tbl_body_start + 1, tbl_body_size);
            if (sz_written < 2) {
                memmove(buf + tbl_body_start + 1 + sz_written,
                        buf + tbl_body_start + 3, tbl_body_size);
                pos = tbl_body_start + 1 + sz_written + tbl_body_size;
            }
        }

        /* ---- Optional: Memory Section (id=5) ---- */
        if (has_memory && pos + 10 < buf_size) {
            uint32_t mem_body_start = pos;
            pos += 3; /* reserve */
            pos += write_leb128(buf + pos, 1); /* 1 memory */
            uint8_t flags = (uint8_t)g_fdp->ConsumeIntegralInRange<uint32_t>(0, 1);
            buf[pos++] = flags; /* 0 = no max, 1 = has max */
            pos += write_leb128(buf + pos, g_fdp->ConsumeIntegralInRange<uint32_t>(1, 256));
            if (flags & 1) {
                pos += write_leb128(buf + pos, g_fdp->ConsumeIntegralInRange<uint32_t>(1, 256));
            }
            uint32_t mem_body_size = pos - (mem_body_start + 3);
            buf[mem_body_start] = 0x05;
            uint32_t sz_written = write_leb128(buf + mem_body_start + 1, mem_body_size);
            if (sz_written < 2) {
                memmove(buf + mem_body_start + 1 + sz_written,
                        buf + mem_body_start + 3, mem_body_size);
                pos = mem_body_start + 1 + sz_written + mem_body_size;
            }
        }

        /* ---- Optional: Global Section (id=6) ---- */
        if (complexity >= 4 && g_fdp->ConsumeBool() && pos + 15 < buf_size) {
            uint32_t glb_body_start = pos;
            pos += 4; /* reserve */
            uint32_t num_globals = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 2);
            pos += write_leb128(buf + pos, num_globals);
            for (uint32_t g = 0; g < num_globals && pos + 6 < buf_size; g++) {
                uint8_t gtypes[] = {VALTYPE_I32, VALTYPE_I64};
                buf[pos++] = gtypes[g_fdp->ConsumeIntegralInRange<uint32_t>(0, 1)];
                buf[pos++] = 0x01; /* mutable */
                buf[pos++] = 0x41; /* i32.const */
                pos += write_leb128(buf + pos,
                    g_fdp->ConsumeIntegralInRange<uint32_t>(0, 100));
                buf[pos++] = 0x0B; /* end */
            }
            uint32_t glb_body_size = pos - (glb_body_start + 4);
            uint32_t hdr_pos = glb_body_start;
            buf[hdr_pos++] = 0x06;
            hdr_pos += write_leb128(buf + hdr_pos, glb_body_size);
            uint32_t hdr_used = hdr_pos - glb_body_start;
            if (hdr_used < 4) {
                memmove(buf + hdr_pos, buf + glb_body_start + 4, glb_body_size);
                pos = hdr_pos + glb_body_size;
            }
        }

        /* ---- Optional: Export Section (id=7) ---- */
        if (has_export && pos + 20 < buf_size) {
            uint32_t exp_body_start = pos;
            pos += 4; /* reserve */

            /* Export "_start" as function (index 0) + maybe others */
            uint32_t num_exports = g_fdp->ConsumeIntegralInRange<uint32_t>(1,
                                          num_funcs > 1 ? 3 : 1);
            pos += write_leb128(buf + pos, num_exports);

            for (uint32_t e = 0; e < num_exports && pos + 10 < buf_size; e++) {
                /* Export name */
                const char *names[] = {"_start", "main", "foo", "run"};
                const char *name = names[e % 4];
                uint32_t name_len = (uint32_t)strlen(name);
                pos += write_leb128(buf + pos, name_len);
                memcpy(buf + pos, name, name_len);
                pos += name_len;

                /* Export kind: 0=func, 1=table, 2=memory, 3=global */
                if (e == 0) {
                    buf[pos++] = 0x00; /* function export */
                    pos += write_leb128(buf + pos,
                        g_fdp->ConsumeIntegralInRange<uint32_t>(0, num_funcs - 1));
                } else {
                    uint8_t kind = (uint8_t)g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3);
                    buf[pos++] = kind;
                    /* Index depends on kind - fuzz it */
                    pos += write_leb128(buf + pos,
                        g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3));
                }
            }

            uint32_t exp_body_size = pos - (exp_body_start + 4);
            uint32_t hdr_pos = exp_body_start;
            buf[hdr_pos++] = 0x07;
            hdr_pos += write_leb128(buf + hdr_pos, exp_body_size);
            uint32_t hdr_used = hdr_pos - exp_body_start;
            if (hdr_used < 4) {
                memmove(buf + hdr_pos, buf + exp_body_start + 4, exp_body_size);
                pos = hdr_pos + exp_body_size;
            }
        }

        /* ---- Optional: Start Section (id=8) ---- */
        if (complexity >= 2 && g_fdp->ConsumeBool() && pos + 6 < buf_size) {
            buf[pos++] = 0x08; /* Start section id */
            buf[pos++] = 0x01; /* section size = 1 */
            buf[pos++] = (uint8_t)g_fdp->ConsumeIntegralInRange<uint32_t>(0, num_funcs - 1);
        }

        /* ---- Optional: Elem Section (id=9) ---- */
        if (complexity >= 3 && g_fdp->ConsumeBool() && pos + 10 < buf_size) {
            uint32_t elem_body_start = pos;
            pos += 3; /* reserve */
            pos += write_leb128(buf + pos, 1); /* 1 element segment */
            buf[pos++] = 0x00; /* active, table 0, offset */
            buf[pos++] = 0x41; /* i32.const */
            pos += write_leb128(buf + pos, 0);
            buf[pos++] = 0x0B; /* end */
            pos += write_leb128(buf + pos, 1); /* 1 function index */
            pos += write_leb128(buf + pos,
                g_fdp->ConsumeIntegralInRange<uint32_t>(0, num_funcs - 1));
            uint32_t elem_body_size = pos - (elem_body_start + 3);
            buf[elem_body_start] = 0x09;
            uint32_t sz_written = write_leb128(buf + elem_body_start + 1, elem_body_size);
            if (sz_written < 2) {
                memmove(buf + elem_body_start + 1 + sz_written,
                        buf + elem_body_start + 3, elem_body_size);
                pos = elem_body_start + 1 + sz_written + elem_body_size;
            }
        }

        /* ---- Code Section (id=10) ---- */
        /* MUST have num_funcs function bodies matching function section */
        {
            uint32_t code_body_start = pos;
            pos += 4; /* reserve */

            pos += write_leb128(buf + pos, num_funcs);

            for (uint32_t f = 0; f < num_funcs && pos + 10 < buf_size; f++) {
                /* Function body: local_set_count + locals + bytecodes + end */
                uint32_t func_body_start = pos;
                pos += 2; /* reserve for body size */

                uint32_t local_set_count = (complexity >= 1)
                    ? g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2) : 0;
                pos += write_leb128(buf + pos, local_set_count);
                for (uint32_t ls = 0; ls < local_set_count; ls++) {
                    pos += write_leb128(buf + pos,
                        g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4));
                    uint8_t ltypes[] = {VALTYPE_I32, VALTYPE_I64, VALTYPE_F32, VALTYPE_F64};
                    buf[pos++] = ltypes[g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3)];
                }

                /* Simple bytecode sequences */
                uint32_t bytecode_start = pos;
                if (complexity == 0) {
                    /* Simplest: just end */
                    buf[pos++] = 0x0B; /* end */
                } else {
                    /* Generate 1-8 instructions + end */
                    uint32_t num_instr = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 8);
                    for (uint32_t ins = 0; ins < num_instr && pos + 5 < buf_size; ins++) {
                        uint8_t opcode = (uint8_t)g_fdp->ConsumeIntegralInRange<uint32_t>(0, 0x50);
                        switch (opcode) {
                            case 0x00: /* unreachable */
                            case 0x01: /* nop */
                                buf[pos++] = opcode;
                                break;
                            case 0x02: /* block */
                                buf[pos++] = opcode;
                                buf[pos++] = 0x40; /* void block type */
                                break;
                            case 0x03: /* loop */
                                buf[pos++] = opcode;
                                buf[pos++] = 0x40;
                                break;
                            case 0x04: /* if */
                                buf[pos++] = opcode;
                                buf[pos++] = 0x40;
                                break;
                            case 0x0C: /* br */
                            case 0x0D: /* br_if */
                                buf[pos++] = opcode;
                                pos += write_leb128(buf + pos, 0);
                                break;
                            case 0x0F: /* return */
                                buf[pos++] = opcode;
                                break;
                            case 0x10: /* call */
                                buf[pos++] = opcode;
                                pos += write_leb128(buf + pos,
                                    g_fdp->ConsumeIntegralInRange<uint32_t>(0, num_funcs - 1));
                                break;
                            case 0x1A: /* drop */
                                buf[pos++] = opcode;
                                break;
                            case 0x1B: /* select */
                                buf[pos++] = opcode;
                                break;
                            case 0x20: /* local.get */
                            case 0x21: /* local.set */
                            case 0x22: /* local.tee */
                                buf[pos++] = opcode;
                                pos += write_leb128(buf + pos,
                                    g_fdp->ConsumeIntegralInRange<uint32_t>(0, 4));
                                break;
                            case 0x41: /* i32.const */
                                buf[pos++] = opcode;
                                /* Signed LEB128 for i32 */
                                {
                                    int32_t val = g_fdp->ConsumeIntegral<int32_t>();
                                    /* Simple unsigned encoding (works for small values) */
                                    pos += write_leb128(buf + pos, (uint32_t)val);
                                }
                                break;
                            case 0x45: /* i32.eqz */
                            case 0x46: /* i32.eq */
                            case 0x47: /* i32.ne */
                            case 0x48: /* i32.lt_s */
                            case 0x49: /* i32.lt_u */
                            case 0x4A: /* i32.gt_s */
                            case 0x4B: /* i32.gt_u */
                            case 0x4C: /* i32.le_s */
                            case 0x4D: /* i32.le_u */
                            case 0x4E: /* i32.ge_s */
                            case 0x4F: /* i32.ge_u */
                            case 0x50: /* i64.eqz */
                                buf[pos++] = opcode;
                                break;
                            default:
                                /* For unknown opcodes, use nop to avoid parse failures */
                                buf[pos++] = 0x01; /* nop */
                                break;
                        }
                    }
                    buf[pos++] = 0x0B; /* end */
                }

                /* Write function body size */
                uint32_t body_size = pos - bytecode_start;
                uint32_t func_body_hdr_pos = func_body_start;
                uint32_t sz_written = write_leb128(buf + func_body_hdr_pos, body_size);
                if (sz_written < 2) {
                    memmove(buf + func_body_hdr_pos + sz_written,
                            buf + func_body_start + 2, body_size);
                    pos = func_body_hdr_pos + sz_written + body_size;
                }
            }

            /* Write code section header */
            uint32_t code_body_size = pos - (code_body_start + 4);
            uint32_t hdr_pos = code_body_start;
            buf[hdr_pos++] = 0x0A; /* Code section id */
            hdr_pos += write_leb128(buf + hdr_pos, code_body_size);
            uint32_t hdr_used = hdr_pos - code_body_start;
            if (hdr_used < 4) {
                memmove(buf + hdr_pos, buf + code_body_start + 4, code_body_size);
                pos = hdr_pos + code_body_size;
            }
        }

        /* ---- Optional: Data Section (id=11) ---- */
        if (has_data && pos + 15 < buf_size) {
            uint32_t data_body_start = pos;
            pos += 3; /* reserve */
            pos += write_leb128(buf + pos, 1); /* 1 data segment */
            buf[pos++] = 0x00; /* active, memory 0, offset expr */
            buf[pos++] = 0x41; /* i32.const */
            pos += write_leb128(buf + pos, 0);
            buf[pos++] = 0x0B; /* end */
            uint32_t data_len = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 16);
            pos += write_leb128(buf + pos, data_len);
            for (uint32_t d = 0; d < data_len && pos < buf_size; d++) {
                buf[pos++] = (uint8_t)g_fdp->ConsumeIntegralInRange<uint32_t>(0, 255);
            }
            uint32_t data_body_size = pos - (data_body_start + 3);
            buf[data_body_start] = 0x0B;
            uint32_t sz_written = write_leb128(buf + data_body_start + 1, data_body_size);
            if (sz_written < 2) {
                memmove(buf + data_body_start + 1 + sz_written,
                        buf + data_body_start + 3, data_body_size);
                pos = data_body_start + 1 + sz_written + data_body_size;
            }
        }

        /* ---- Load the module ---- */
        char error_buf[256];
        uint64_t args[4];
        args[0] = (uint64_t)(uintptr_t)buf;
        args[1] = (uint64_t)buf_size;
        args[2] = (uint64_t)(uintptr_t)error_buf;
        args[3] = (uint64_t)sizeof(error_buf);

        ecall_handle_command(__g_harness_eid, 1 /* CMD_LOAD_MODULE */,
                             (unsigned char *)args, sizeof(args));
        module_handle_id = (uint32_t)args[0];
    }

    if (module_handle_id == 0) goto cleanup;

    /* ---- Phase 3: Set WASI args if module loaded ---- */
    if (g_fdp->ConsumeBool()) {
        /* Build real string arrays for WASI - they must be outside enclave */
        uint32_t dir_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);
        uint32_t env_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);
        uint32_t argv_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);
        uint32_t addr_count = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 1);

        char **dir_list = (char **)calloc(dir_count > 0 ? dir_count : 1, sizeof(char *));
        char **env_list = (char **)calloc(env_count > 0 ? env_count : 1, sizeof(char *));
        char **wasi_argv = (char **)calloc(argv_count > 0 ? argv_count : 1, sizeof(char *));
        char **addr_pool = (char **)calloc(addr_count > 0 ? addr_count : 1, sizeof(char *));

        for (uint32_t i = 0; i < dir_count; i++) {
            dir_list[i] = (char *)calloc(1, 16);
            g_fdp->ConsumeData(dir_list[i], 15);
            dir_list[i][15] = '\0';
        }
        for (uint32_t i = 0; i < env_count; i++) {
            env_list[i] = (char *)calloc(1, 16);
            g_fdp->ConsumeData(env_list[i], 15);
            env_list[i][15] = '\0';
        }
        for (uint32_t i = 0; i < argv_count; i++) {
            wasi_argv[i] = (char *)calloc(1, 16);
            g_fdp->ConsumeData(wasi_argv[i], 15);
            wasi_argv[i][15] = '\0';
        }
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
        wasi_args[5] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(-1, 5);
        wasi_args[6] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(-1, 5);
        wasi_args[7] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(-1, 5);
        wasi_args[8] = (uint64_t)(uintptr_t)wasi_argv;
        wasi_args[9] = (uint64_t)argv_count;
        wasi_args[10] = (uint64_t)(uintptr_t)addr_pool;
        wasi_args[11] = (uint64_t)addr_count;
        ecall_handle_command(__g_harness_eid, 12 /* CMD_SET_WASI_ARGS */,
                             (unsigned char *)wasi_args, sizeof(wasi_args));
    }

    /* ---- Phase 4: Instantiate ---- */
    {
        char error_buf[256];
        uint64_t args[5];
        args[0] = (uint64_t)module_handle_id;
        args[1] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(8192, 65536);
        args[2] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(8192, 65536);
        args[3] = (uint64_t)(uintptr_t)error_buf;
        args[4] = (uint64_t)sizeof(error_buf);

        ecall_handle_command(__g_harness_eid, 2 /* CMD_INSTANTIATE_MODULE */,
                             (unsigned char *)args, sizeof(args));
        uint32_t instance_handle_id = (uint32_t)args[0];

        if (instance_handle_id != 0) {
            /* ---- Phase 5: Execute main/func ---- */
            if (g_fdp->ConsumeBool()) {
                /* exec_app_main */
                uint32_t app_argc = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
                uint32_t total_exec_args = 2 + app_argc;
                uint64_t *exec_args = (uint64_t *)calloc(total_exec_args, sizeof(uint64_t));
                if (exec_args) {
                    exec_args[0] = (uint64_t)instance_handle_id;
                    exec_args[1] = (uint64_t)app_argc;
                    for (uint32_t i = 0; i < app_argc; i++) {
                        char *s = (char *)calloc(1, 8);
                        if (s) {
                            g_fdp->ConsumeData(s, 7);
                            s[7] = '\0';
                            exec_args[2 + i] = (uint64_t)(uintptr_t)s;
                        }
                    }
                    ecall_handle_command(__g_harness_eid, 7 /* CMD_EXEC_APP_MAIN */,
                                         (unsigned char *)exec_args,
                                         total_exec_args * sizeof(uint64_t));
                }
            }

            if (g_fdp->ConsumeBool()) {
                /* exec_app_func */
                char func_name[16];
                g_fdp->ConsumeData(func_name, sizeof(func_name) - 1);
                func_name[sizeof(func_name) - 1] = '\0';
                uint64_t func_args[4];
                func_args[0] = (uint64_t)instance_handle_id;
                func_args[1] = (uint64_t)(uintptr_t)func_name;
                func_args[2] = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 2);
                func_args[3] = 0;
                ecall_handle_command(__g_harness_eid, 6 /* CMD_EXEC_APP_FUNC */,
                                     (unsigned char *)func_args, sizeof(func_args));
            }

            /* Deinstantiate */
            {
                uint64_t dargs[1];
                dargs[0] = (uint64_t)instance_handle_id;
                ecall_handle_command(__g_harness_eid, 9 /* CMD_DEINSTANTIATE_MODULE */,
                                     (unsigned char *)dargs, sizeof(dargs));
            }
        }
    }

    /* ---- Phase 6: Unload module ---- */
    {
        uint64_t args[1];
        args[0] = (uint64_t)module_handle_id;
        ecall_handle_command(__g_harness_eid, 10 /* CMD_UNLOAD_MODULE */,
                             (unsigned char *)args, sizeof(args));
    }

cleanup:
    ecall_handle_command(__g_harness_eid, 11 /* CMD_DESTROY_RUNTIME */,
                         NULL, 0);
}

HARNESS_REGISTER(harness_valid_wasm, 15)
