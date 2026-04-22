#pragma once

/* Harness for ecall_iwasm_main
 * EDL: public void ecall_iwasm_main([user_check]uint8_t *wasm_file_buf,
 *                                   uint32_t wasm_file_size);
 *
 * [user_check] means the SDK does NOT perform automatic bounds checking
 * on this pointer — HIGH fuzzing value. The enclave code must validate
 * wasm_file_buf and wasm_file_size itself.
 *
 * Already found a null-pointer bug. Downweighted to explore other paths.
 * Still exercises the WASM parser with various buffer conditions.
 */

static void harness_ecall_iwasm_main(void)
{
    uint32_t wasm_file_size = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 65536);
    uint8_t *wasm_file_buf = NULL;

    if (wasm_file_size > 0) {
        wasm_file_buf = (uint8_t *)calloc(1, wasm_file_size);
        if (wasm_file_buf) {
            g_fdp->ConsumeData(wasm_file_buf, wasm_file_size);
        }
    }

    /* Also test with NULL buffer + non-zero size (common missing-check bug) */
    if (g_fdp->ConsumeProbability<double>() < 0.1) {
        wasm_file_buf = NULL;
    }

    ecall_iwasm_main(__g_harness_eid, wasm_file_buf, wasm_file_size);
}

HARNESS_REGISTER(harness_ecall_iwasm_main, 5)
