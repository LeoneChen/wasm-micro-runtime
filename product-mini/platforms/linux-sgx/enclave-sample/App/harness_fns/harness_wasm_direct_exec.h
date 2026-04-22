#pragma once

/* Harness for ecall_iwasm_main with pre-built valid WASM module templates.
 *
 * Motivation: ecall_iwasm_main provides a SEPARATE code path from
 * ecall_handle_command that goes through:
 *   wasm_runtime_full_init → wasm_runtime_load → wasm_runtime_instantiate →
 *   wasm_application_execute_main → wasm_runtime_deinstantiate → wasm_runtime_unload
 *
 * Currently wasm_application_execute_main (0/3 edges), execute_main (0/31),
 * and execute_func (0/74) are completely UNCOVERED. This is because:
 * 1. ecall_iwasm_main only works when runtime_inited == false (checked at top)
 * 2. The current ecall_iwasm_main harness sends random fuzzed bytes that
 *    almost never pass wasm_load validation
 * 3. ecall_handle_command path uses a different init/load/exec flow
 *
 * This harness pre-builds structurally valid WASM binaries, then varies
 * only the code section bytecodes using fuzz data. This maximizes the
 * chance of passing validation and reaching deep execution paths.
 *
 * Targets:
 *   - wasm_application_execute_main: 0% → 60%+
 *   - execute_main: 0% → 30%+
 *   - wasm_runtime_instantiate: 16% → 40%+
 *   - Various wasm_interp_* interpreter functions
 */

/* Pre-built minimal valid WASM module templates.
 * These are valid WASM binaries with varying structures.
 * The code section bytecodes will be replaced with fuzz data. */

/* Template 0: Minimal - 1 func type () -> (), export "_start", body = end
 * 36 bytes */
static const uint8_t s_wasm_template_minimal[] = {
    0x00, 0x61, 0x73, 0x6d,  /* magic */
    0x01, 0x00, 0x00, 0x00,  /* version */
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Export section: "_start" = func 0 */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,  /* "_start" */
    0x00, 0x00,
    /* Code section: 1 body, size=2, 0 locals, end */
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
};

/* Template 1: With memory section + data section
 * 1 func type () -> (), memory 1 page, export "_start" and "memory", data segment
 * 62 bytes */
static const uint8_t s_wasm_template_memory[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Memory section: 1 memory, min=1 */
    0x05, 0x03, 0x01, 0x00, 0x01,
    /* Export section: "_start" = func 0, "memory" = memory 0 */
    0x07, 0x11, 0x02,
    0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
    /* Code section: 1 body, size=2, 0 locals, end */
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
};

/* Template 2: With globals and table
 * 1 func type, global i32 mutable, table funcref, export "_start"
 * ~54 bytes */
static const uint8_t s_wasm_template_globals[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Table section: 1 table, funcref, min=1 */
    0x04, 0x04, 0x01, 0x70, 0x00, 0x01,
    /* Global section: 1 global, i32 mutable, init = i32.const 0 */
    0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b,
    /* Export section: "_start" = func 0 */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x00,
    /* Code section: 1 body, size=2, 0 locals, end */
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
};

/* Template 3: With WASI-style imports (correct signatures)
 * 3 func types, 2 imports (wasi_snapshot_preview1), 1 local func, export "_start"
 * args_get = (i32,i32)->i32, fd_write = (i32,i32,i32,i32)->i32
 * ~94 bytes */
static const uint8_t s_wasm_template_wasi[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 3 types
     * type 0: () -> ()
     * type 1: (i32, i32) -> (i32)
     * type 2: (i32, i32, i32, i32) -> (i32) */
    0x01, 0x12, 0x03,
    0x60, 0x00, 0x00,              /* type 0: () -> () */
    0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,  /* type 1: (i32,i32) -> (i32) */
    0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,  /* type 2: (i32,i32,i32,i32) -> (i32) */
    /* Import section: 2 imports from "wasi_snapshot_preview1"
     * import 0: "args_get" func type 1
     * import 1: "fd_write" func type 2 */
    0x02, 0x43, 0x02,
    /* import 0: module name length=21 "wasi_snapshot_preview1" */
    0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
    0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
    0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
    0x08, 0x61, 0x72, 0x67, 0x73, 0x5f, 0x67, 0x65, 0x74,  /* "args_get" */
    0x00, 0x01,  /* func import, type index 1 */
    /* import 1: module name */
    0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
    0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
    0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
    0x08, 0x66, 0x64, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65,  /* "fd_write" */
    0x00, 0x02,  /* func import, type index 2 */
    /* Function section: 1 local func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Export section: "_start" = func 2 (after 2 imports) */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x02,  /* func kind, index 2 (imports are 0,1) */
    /* Code section: 1 body — calls args_get(0,0) and fd_write(1,0,0,0) */
    0x0a, 0x16, 0x01,
    0x14, 0x00,                    /* body size=20, 0 locals */
    0x41, 0x00,                    /* i32.const 0 */
    0x41, 0x00,                    /* i32.const 0 */
    0x10, 0x00,                    /* call 0 (args_get) */
    0x1a,                          /* drop */
    0x41, 0x01,                    /* i32.const 1 */
    0x41, 0x00,                    /* i32.const 0 */
    0x41, 0x00,                    /* i32.const 0 */
    0x41, 0x00,                    /* i32.const 0 */
    0x10, 0x01,                    /* call 1 (fd_write) */
    0x1a,                          /* drop */
    0x0b,                          /* end */
};

/* Template 4: With locals and arithmetic
 * 1 func type (i32) -> (i32), local i32, exports "main"
 * ~46 bytes — exercises local.get/set, arithmetic ops */
static const uint8_t s_wasm_template_arith[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, (i32) -> (i32) */
    0x01, 0x05, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Export section: "main" = func 0 */
    0x07, 0x08, 0x01, 0x04,
    0x6d, 0x61, 0x69, 0x6e,  /* "main" */
    0x00, 0x00,
    /* Code section: 1 body, locals=1 i32, body=end */
    0x0a, 0x06, 0x01, 0x04,  /* code section: 1 body, body_size=4 */
    0x01, 0x01, 0x7f,        /* 1 local set: 1 x i32 */
    0x0b,                     /* end */
};

/* Template 5: 2 funcs with call — exercises inter-function calls
 * Type: () -> (), func 0 calls func 1 via call instruction
 * ~50 bytes */
static const uint8_t s_wasm_template_calls[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 2 funcs, both type 0 */
    0x03, 0x03, 0x02, 0x00, 0x00,
    /* Export section: "_start" = func 0 */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x00,
    /* Code section: 2 bodies
     * func 0: call 1 + end
     * func 1: end */
    0x0a, 0x08, 0x02,
    0x03, 0x00, 0x10, 0x01, 0x0b,  /* body 0: size=3, 0 locals, call 1, end */
    0x02, 0x00, 0x0b,              /* body 1: size=2, 0 locals, end */
};

/* Template 6: With memory + i32.load/i32.store bytecodes
 * () -> (), memory 1 page, export "_start" and "memory"
 * Code body has memory ops — exercises wasm_interp_load/store
 * ~50 bytes */
static const uint8_t s_wasm_template_memops[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Memory section: 1 memory, min=1 */
    0x05, 0x03, 0x01, 0x00, 0x01,
    /* Export section: "_start" = func 0, "memory" = memory 0 */
    0x07, 0x11, 0x02,
    0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
    /* Code section: 1 body, i32.const 0 + i32.const 42 + i32.store + end */
    0x0a, 0x0a, 0x01,
    0x08, 0x00,                /* body size=8, 0 locals */
    0x41, 0x00,                /* i32.const 0  (address) */
    0x41, 0x2a,                /* i32.const 42 (value) */
    0x36, 0x02, 0x00,          /* i32.store align=0 offset=0 */
    0x0b,                      /* end */
};

/* Template 7: With data section — exercises load_data_segment_section
 * () -> (), memory 1 page, data segment with 4 bytes, export "_start"
 * ~58 bytes */
static const uint8_t s_wasm_template_data_section[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Memory section: 1 memory, min=1 */
    0x05, 0x03, 0x01, 0x00, 0x01,
    /* Export section: "_start" = func 0, "memory" = memory 0 */
    0x07, 0x11, 0x02,
    0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
    /* Data section: 1 segment, active (memory 0, offset i32.const 0), 4 bytes */
    0x0b, 0x09, 0x01,
    0x07,             /* segment size */
    0x00,             /* flags: active, memory 0 */
    0x41, 0x00, 0x0b, /* i32.const 0, end */
    0x04,             /* data byte count = 4 */
    0x01, 0x02, 0x03, 0x04,
    /* Code section: 1 body, size=2, 0 locals, end */
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
};

/* Template 8: With elem section (table init segment) — exercises load_table_segment_section
 * 1 func type () -> (), table funcref min=1, 1 local func, export "_start",
 * elem section: active segment [table 0, offset 0] = [func 0]
 * ~56 bytes */
static const uint8_t s_wasm_template_elem[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Table section: 1 table, funcref, min=1 */
    0x04, 0x04, 0x01, 0x70, 0x00, 0x01,
    /* Export section: "_start" = func 0 */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x00,
    /* Elem section: 1 segment, mode=0 (active, table 0, offset i32.const 0, vec(funcidx)) */
    0x09, 0x07, 0x01,
    0x00,             /* mode 0: active, table 0 */
    0x41, 0x00, 0x0b, /* i32.const 0, end (init expr for offset) */
    0x01, 0x00,       /* 1 element, func index 0 */
    /* Code section: 1 body, size=2, 0 locals, end */
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
};

/* Template 9: With start section — exercises load_start_section
 * 2 func types, 2 local funcs, export "_start", start=func 1 (different from export)
 * ~58 bytes */
static const uint8_t s_wasm_template_start[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, () -> () */
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
    /* Function section: 2 funcs, both type 0 */
    0x03, 0x03, 0x02, 0x00, 0x00,
    /* Export section: "_start" = func 0 */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x00,
    /* Start section: start function = func 1 (type () -> ()) */
    0x08, 0x01, 0x01,
    /* Code section: 2 bodies
     * func 0: end
     * func 1: end (start function body) */
    0x0a, 0x08, 0x02,
    0x02, 0x00, 0x0b,  /* body 0: size=2, 0 locals, end */
    0x02, 0x00, 0x0b,  /* body 1: size=2, 0 locals, end */
};

/* Template 10: WASI with actual import calls (correct signatures)
 * 3 types, 3 WASI imports (args_get, fd_write, proc_exit), 1 local func
 * The _start body calls all 3 WASI imports to trigger OCall paths.
 * Import 0: args_get (type 1: (i32,i32) -> i32)
 * Import 1: fd_write (type 2: (i32,i32,i32,i32) -> i32)
 * Import 2: proc_exit (type 0: (i32) -> ())
 * Local 3: _start (type 0: () -> ())
 * ~116 bytes */
static const uint8_t s_wasm_template_wasi_calls[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 3 types
     * type 0: (i32) -> ()
     * type 1: (i32, i32) -> (i32)
     * type 2: (i32, i32, i32, i32) -> (i32) */
    0x01, 0x11, 0x03,
    0x60, 0x01, 0x7f, 0x00,        /* type 0: (i32) -> () */
    0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,  /* type 1: (i32,i32) -> (i32) */
    0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,  /* type 2: (i32,i32,i32,i32) -> (i32) */
    /* Import section: 3 imports from "wasi_snapshot_preview1" */
    0x02, 0x5a, 0x03,
    /* import 0: args_get */
    0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
    0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
    0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
    0x08, 0x61, 0x72, 0x67, 0x73, 0x5f, 0x67, 0x65, 0x74,
    0x00, 0x01,  /* func import, type index 1 */
    /* import 1: fd_write */
    0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
    0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
    0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
    0x08, 0x66, 0x64, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65,
    0x00, 0x02,  /* func import, type index 2 */
    /* import 2: proc_exit */
    0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
    0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
    0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
    0x09, 0x70, 0x72, 0x6f, 0x63, 0x5f, 0x65, 0x78, 0x69, 0x74,
    0x00, 0x00,  /* func import, type index 0 */
    /* Function section: 1 local func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Export section: "_start" = func 3 (after 3 imports) */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x03,  /* func kind, index 3 */
    /* Code section: 1 body — calls args_get, fd_write, proc_exit */
    0x0a, 0x1a, 0x01,
    0x18, 0x00,                    /* body size=24, 0 locals */
    0x41, 0x00,                    /* i32.const 0 */
    0x41, 0x00,                    /* i32.const 0 */
    0x10, 0x00,                    /* call 0 (args_get) */
    0x1a,                          /* drop */
    0x41, 0x01,                    /* i32.const 1 */
    0x41, 0x00,                    /* i32.const 0 */
    0x41, 0x00,                    /* i32.const 0 */
    0x41, 0x00,                    /* i32.const 0 */
    0x10, 0x01,                    /* call 1 (fd_write) */
    0x1a,                          /* drop (discard i32 result) */
    0x41, 0x00,                    /* i32.const 0 */
    0x10, 0x02,                    /* call 2 (proc_exit) */
    0x0b,                          /* end */
};

/* Template 11: WASI with memory + fd_write using memory buffer (correct signature)
 * 2 types, 1 WASI import (fd_write), memory 1 page, 1 local func
 * The _start body writes to memory then calls fd_write with 4 args.
 * Import 0: fd_write (type 0: (i32,i32,i32,i32) -> i32)
 * Local 1: _start (type 1: () -> ())
 * ~80 bytes */
static const uint8_t s_wasm_template_wasi_mem[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 2 types
     * type 0: (i32, i32, i32, i32) -> (i32)
     * type 1: () -> () */
    0x01, 0x0c, 0x02,
    0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,  /* type 0: (i32,i32,i32,i32) -> i32 */
    0x60, 0x00, 0x00,              /* type 1: () -> () */
    /* Import section: 1 import from "wasi_snapshot_preview1" */
    0x02, 0x1a, 0x01,
    0x15, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e,
    0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70,
    0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31,
    0x08, 0x66, 0x64, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65,
    0x00, 0x00,  /* func import, type index 0 */
    /* Function section: 1 local func, type 1 */
    0x03, 0x02, 0x01, 0x01,
    /* Memory section: 1 memory, min=1 */
    0x05, 0x03, 0x01, 0x00, 0x01,
    /* Export section: "_start" = func 1, "memory" = memory 0 */
    0x07, 0x11, 0x02,
    0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01,
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
    /* Code section: 1 body — stores to memory, calls fd_write with 4 args */
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

/* Template 12: Float arithmetic — exercises f32/f64 interpreter paths
 * 1 func type (f64, f64) -> (f64), locals: 1xf32
 * Export "_start"
 * ~48 bytes */
static const uint8_t s_wasm_template_float[] = {
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    /* Type section: 1 type, (f64, f64) -> (f64) */
    0x01, 0x09, 0x01, 0x60, 0x02, 0x7c, 0x7c, 0x01, 0x7c,
    /* Function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* Export section: "_start" = func 0 */
    0x07, 0x09, 0x01, 0x06,
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x00,
    /* Code section: 1 body, 1 local f32, body=end */
    0x0a, 0x06, 0x01, 0x04,
    0x01, 0x7d,       /* 1 local: 1 x f32 */
    0x0b,             /* end */
};

/* Extended opcode set for fuzzed bytecodes — covers i32/i64 arithmetic,
 * comparison, memory ops, control flow, and conversions.
 * Range: 0x00-0xBF covering the core WASM instruction set. */
static uint8_t gen_fuzzed_bytecode(FuzzedDataProvider *fdp, uint8_t *buf, uint32_t max_len,
                                    uint32_t num_funcs, uint32_t num_locals) {
    uint32_t pos = 0;
    uint32_t num_instr = fdp->ConsumeIntegralInRange<uint32_t>(0, 8);

    for (uint32_t i = 0; i < num_instr && pos + 8 < max_len; i++) {
        uint8_t opcode = (uint8_t)fdp->ConsumeIntegralInRange<uint32_t>(0, 0xBF);

        switch (opcode) {
            /* ---- Control flow ---- */
            case 0x00: /* unreachable */ buf[pos++] = opcode; break;
            case 0x01: /* nop */ buf[pos++] = opcode; break;
            case 0x02: /* block */
                buf[pos++] = opcode;
                buf[pos++] = 0x40; /* void */
                break;
            case 0x03: /* loop */
                buf[pos++] = opcode;
                buf[pos++] = 0x40;
                break;
            case 0x04: /* if */
                buf[pos++] = opcode;
                buf[pos++] = 0x40;
                break;
            case 0x05: /* else */ buf[pos++] = opcode; break;
            case 0x0C: /* br depth=0 */
            case 0x0D: /* br_if depth=0 */
                buf[pos++] = opcode;
                buf[pos++] = 0x00;
                break;
            case 0x0E: /* br_table */
                buf[pos++] = opcode;
                buf[pos++] = 0x01; /* 1 target */
                buf[pos++] = 0x00;
                buf[pos++] = 0x00;
                break;
            case 0x0F: /* return */ buf[pos++] = opcode; break;

            /* ---- Call ---- */
            case 0x10: /* call */
                buf[pos++] = opcode;
                buf[pos++] = (uint8_t)fdp->ConsumeIntegralInRange<uint32_t>(0,
                    num_funcs > 0 ? num_funcs - 1 : 0);
                break;
            case 0x11: /* call_indirect — requires table, use type=0, table=0 */
                buf[pos++] = opcode;
                buf[pos++] = 0x00;
                buf[pos++] = 0x00;
                break;

            /* ---- Parametric ---- */
            case 0x1A: /* drop */ buf[pos++] = opcode; break;
            case 0x1B: /* select */ buf[pos++] = opcode; break;

            /* ---- Local ops ---- */
            case 0x20: /* local.get */
            case 0x21: /* local.set */
            case 0x22: /* local.tee */
                buf[pos++] = opcode;
                buf[pos++] = (uint8_t)fdp->ConsumeIntegralInRange<uint32_t>(0,
                    num_locals > 0 ? num_locals : 0);
                break;

            /* ---- Global ops ---- */
            case 0x23: /* global.get */
            case 0x24: /* global.set */
                buf[pos++] = opcode;
                buf[pos++] = 0x00;
                break;

            /* ---- Memory ops (require memory section in template) ---- */
            case 0x28: /* i32.load */
            case 0x29: /* i64.load */
            case 0x36: /* i32.store */
            case 0x37: /* i64.store */
                buf[pos++] = opcode;
                buf[pos++] = 0x02; /* align */
                buf[pos++] = 0x00; /* offset */
                break;
            case 0x2C: /* i32.load8_s */
            case 0x2D: /* i32.load8_u */
            case 0x3A: /* i32.store8 */
                buf[pos++] = opcode;
                buf[pos++] = 0x00; /* align */
                buf[pos++] = 0x00; /* offset */
                break;
            case 0x3F: /* memory.size */
                buf[pos++] = opcode;
                buf[pos++] = 0x00; /* reserved byte */
                break;
            case 0x40: /* memory.grow */
                buf[pos++] = opcode;
                buf[pos++] = 0x00; /* reserved byte */
                break;

            /* ---- Constants ---- */
            case 0x41: /* i32.const */
                buf[pos++] = opcode;
                buf[pos++] = (uint8_t)fdp->ConsumeIntegralInRange<uint32_t>(0, 127);
                break;
            case 0x42: /* i64.const */
                buf[pos++] = opcode;
                buf[pos++] = (uint8_t)fdp->ConsumeIntegralInRange<uint32_t>(0, 127);
                break;
            case 0x43: /* f32.const */
                buf[pos++] = opcode;
                buf[pos++] = 0x00; buf[pos++] = 0x00;
                buf[pos++] = 0x80; buf[pos++] = 0x3f; /* 1.0f */
                break;
            case 0x44: /* f64.const */
                buf[pos++] = opcode;
                buf[pos++] = 0x00; buf[pos++] = 0x00;
                buf[pos++] = 0x00; buf[pos++] = 0x00;
                buf[pos++] = 0x00; buf[pos++] = 0x00;
                buf[pos++] = 0xf0; buf[pos++] = 0x3f; /* 1.0 */
                break;

            /* ---- i32 comparison ---- */
            case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A:
            case 0x4B: case 0x4C: case 0x4D:
            case 0x4E: case 0x4F:
                buf[pos++] = opcode;
                break;

            /* ---- i64 comparison ---- */
            case 0x50: case 0x51: case 0x52:
            case 0x53: case 0x54: case 0x55:
            case 0x56: case 0x57: case 0x58:
            case 0x59: case 0x5A:
                buf[pos++] = opcode;
                break;

            /* ---- i32 arithmetic (0x67-0x78) ---- */
            case 0x67: /* i32.clz */
            case 0x68: /* i32.ctz */
            case 0x69: /* i32.popcnt */
            case 0x6A: /* i32.add */
            case 0x6B: /* i32.sub */
            case 0x6C: /* i32.mul */
            case 0x71: /* i32.and */
            case 0x72: /* i32.or */
            case 0x73: /* i32.xor */
                buf[pos++] = opcode;
                break;
            case 0x6D: /* i32.div_s */
            case 0x6E: /* i32.div_u */
            case 0x6F: /* i32.rem_s */
            case 0x70: /* i32.rem_u */
            case 0x74: /* i32.shl */
            case 0x75: /* i32.shr_s */
            case 0x76: /* i32.shr_u */
            case 0x77: /* i32.rotl */
            case 0x78: /* i32.rotr */
                buf[pos++] = opcode;
                break;

            /* ---- i64 arithmetic (0x79-0x8A) ---- */
            case 0x79: /* i64.clz */
            case 0x7A: /* i64.ctz */
            case 0x7B: /* i64.popcnt */
            case 0x7C: /* i64.add */
            case 0x7D: /* i64.sub */
            case 0x7E: /* i64.mul */
            case 0x83: /* i64.and */
            case 0x84: /* i64.or */
            case 0x85: /* i64.xor */
            case 0x86: /* i64.shl */
            case 0x87: /* i64.shr_s */
            case 0x88: /* i64.shr_u */
            case 0x89: /* i64.rotl */
            case 0x8A: /* i64.rotr */
                buf[pos++] = opcode;
                break;

            /* ---- f32 arithmetic (0x92-0x98) ---- */
            case 0x92: /* f32.abs */
            case 0x93: /* f32.neg */
            case 0x94: /* f32.ceil */
            case 0x95: /* f32.floor */
            case 0x96: /* f32.trunc */
            case 0x97: /* f32.nearest */
            case 0x98: /* f32.sqrt */
                buf[pos++] = opcode;
                break;
            case 0x99: /* f32.add */
            case 0x9A: /* f32.sub */
            case 0x9B: /* f32.mul */
            case 0x9C: /* f32.div */
            case 0x9D: /* f32.min */
            case 0x9E: /* f32.max */
            case 0x9F: /* f32.copysign */
                buf[pos++] = opcode;
                break;

            /* ---- f64 arithmetic (0xA0-0xA6) ---- */
            case 0xA0: /* f64.abs */
            case 0xA1: /* f64.neg */
            case 0xA2: /* f64.ceil */
            case 0xA3: /* f64.floor */
            case 0xA4: /* f64.trunc */
            case 0xA5: /* f64.nearest */
            case 0xA6: /* f64.sqrt */
                buf[pos++] = opcode;
                break;
            case 0xA7: /* i32.wrap_i64 */
            case 0xA8: /* f32.trunc_i32_f32 — kept as single-byte */ 
                buf[pos++] = opcode;
                break;
            case 0xAC: /* i64.extend_i32_s */
            case 0xAD: /* i64.extend_i32_u */
                buf[pos++] = opcode;
                break;

            default:
                buf[pos++] = 0x01; /* nop */
                break;
        }
    }
    buf[pos++] = 0x0b; /* end */
    return (uint8_t)pos;
}

static void harness_wasm_direct_exec(void)
{
    /* Select a template */
    uint32_t template_idx = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 12);

    const uint8_t *template_data;
    uint32_t template_size;
    uint32_t num_funcs = 1;
    uint32_t num_locals = 0;

    switch (template_idx) {
        case 0:
            template_data = s_wasm_template_minimal;
            template_size = sizeof(s_wasm_template_minimal);
            break;
        case 1:
            template_data = s_wasm_template_memory;
            template_size = sizeof(s_wasm_template_memory);
            break;
        case 2:
            template_data = s_wasm_template_globals;
            template_size = sizeof(s_wasm_template_globals);
            break;
        case 3:
            template_data = s_wasm_template_wasi;
            template_size = sizeof(s_wasm_template_wasi);
            break;
        case 4:
            template_data = s_wasm_template_arith;
            template_size = sizeof(s_wasm_template_arith);
            num_locals = 1;
            break;
        case 5:
            template_data = s_wasm_template_calls;
            template_size = sizeof(s_wasm_template_calls);
            num_funcs = 2;
            break;
        case 6:
            template_data = s_wasm_template_memops;
            template_size = sizeof(s_wasm_template_memops);
            break;
        case 7:
            template_data = s_wasm_template_data_section;
            template_size = sizeof(s_wasm_template_data_section);
            break;
        case 8:
            template_data = s_wasm_template_elem;
            template_size = sizeof(s_wasm_template_elem);
            break;
        case 9:
            template_data = s_wasm_template_start;
            template_size = sizeof(s_wasm_template_start);
            num_funcs = 2;
            break;
        case 10:
            template_data = s_wasm_template_wasi_calls;
            template_size = sizeof(s_wasm_template_wasi_calls);
            num_funcs = 4; /* 3 imports + 1 local */
            break;
        case 11:
            template_data = s_wasm_template_wasi_mem;
            template_size = sizeof(s_wasm_template_wasi_mem);
            break;
        case 12:
        default:
            template_data = s_wasm_template_float;
            template_size = sizeof(s_wasm_template_float);
            num_locals = 2; /* params f64,f64 + local f32 */
            break;
    }

    /* Copy template into mutable buffer with room for code modifications */
    uint32_t buf_size = template_size + g_fdp->ConsumeIntegralInRange<uint32_t>(0, 48);
    uint8_t *wasm_buf = (uint8_t *)calloc(1, buf_size);
    if (!wasm_buf) return;

    memcpy(wasm_buf, template_data, template_size);
    uint32_t actual_size = template_size;

    /* Fuzz mode: vary the code section bytecodes
     * The code section is the last section in all templates.
     * The bytecode is at offset (template_size - 1) = the 0x0b (end) byte.
     * Replace the end byte and add fuzzed instructions before it. */
    uint32_t fuzz_mode = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 3);

    if (fuzz_mode == 0) {
        /* Mode 0: Keep template as-is (valid WASM, tests the happy path) */
        /* Do nothing extra */
    } else if (fuzz_mode == 1 && buf_size >= actual_size + 24) {
        /* Mode 1: Replace the code section with fuzzed bytecodes
         * We know the code section starts at the last 0x0a byte.
         * For simplicity, rebuild the code section with fuzzed bytecodes. */

        /* Find the code section (0x0a byte) */
        int code_section_offset = -1;
        for (int i = (int)actual_size - 1; i >= 0; i--) {
            if (wasm_buf[i] == 0x0a && i + 4 < (int)actual_size) {
                code_section_offset = i;
                break;
            }
        }

        if (code_section_offset >= 0) {
            /* Generate fuzzed bytecodes */
            uint8_t bytecodes[40];
            uint8_t bc_len = gen_fuzzed_bytecode(g_fdp, bytecodes, sizeof(bytecodes),
                                                  num_funcs, num_locals);

            /* Rebuild code section at code_section_offset */
            /* For single-func templates: code section format: 0x0a sec_size count body_size locals_count bytecodes */
            uint32_t body_size = 1 + bc_len; /* 1 for locals_count=0 */
            uint32_t sec_size = 1 + 1 + body_size; /* count + body_size_leb + body */

            if (code_section_offset + 2 + sec_size <= buf_size) {
                wasm_buf[code_section_offset] = 0x0a;
                wasm_buf[code_section_offset + 1] = (uint8_t)sec_size;
                wasm_buf[code_section_offset + 2] = 0x01; /* 1 body */
                wasm_buf[code_section_offset + 3] = (uint8_t)body_size;
                wasm_buf[code_section_offset + 4] = 0x00; /* 0 locals */
                memcpy(wasm_buf + code_section_offset + 5, bytecodes, bc_len);
                actual_size = code_section_offset + 5 + bc_len;
            }
        }
    } else if (fuzz_mode == 2) {
        /* Mode 2: Append extra bytes after the template (test parser robustness) */
        uint32_t extra = g_fdp->ConsumeIntegralInRange<uint32_t>(1,
            buf_size > actual_size ? buf_size - actual_size : 1);
        if (actual_size + extra <= buf_size) {
            g_fdp->ConsumeData(wasm_buf + actual_size, extra);
            actual_size += extra;
        }
    } else {
        /* Mode 3: Random mutations at fuzz-chosen offsets */
        uint32_t num_mutations = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
        for (uint32_t m = 0; m < num_mutations; m++) {
            uint32_t offset = g_fdp->ConsumeIntegralInRange<uint32_t>(8, actual_size - 1);
            wasm_buf[offset] = (uint8_t)g_fdp->ConsumeIntegral<uint8_t>();
        }
    }

    /* Call ecall_iwasm_main with the WASM buffer */
    ecall_iwasm_main(__g_harness_eid, wasm_buf, actual_size);
}

HARNESS_REGISTER(harness_wasm_direct_exec, 30)
