#pragma once

/* Harness for ecall_handle_command
 * EDL: public void ecall_handle_command(unsigned cmd,
 *                                       [in, out, size=cmd_buf_size]uint8_t *cmd_buf,
 *                                       unsigned cmd_buf_size);
 *
 * CMD enum:
 *   CMD_INIT_RUNTIME = 0,
 *   CMD_LOAD_MODULE,
 *   CMD_INSTANTIATE_MODULE,
 *   CMD_LOOKUP_FUNCTION,
 *   CMD_CREATE_EXEC_ENV,
 *   CMD_CALL_WASM,
 *   CMD_EXEC_APP_FUNC,
 *   CMD_EXEC_APP_MAIN,
 *   CMD_GET_EXCEPTION,
 *   CMD_DEINSTANTIATE_MODULE,
 *   CMD_UNLOAD_MODULE,
 *   CMD_DESTROY_RUNTIME,
 *   CMD_SET_WASI_ARGS,
 *   CMD_SET_LOG_LEVEL,
 *   CMD_GET_VERSION,
 *   CMD_GET_PGO_PROF_BUF_SIZE,
 *   CMD_DUMP_PGO_PROF_BUF_DATA
 *
 * IMPORTANT: The enclave validates cmd_buf alignment (must be multiple of 8)
 * and rejects mismatched buf/size pairs. This harness always generates
 * 8-byte-aligned buffers to pass these checks.
 */

static void harness_ecall_handle_command(void)
{
    /* Generate a random cmd value. We fuzz both valid commands (0-16)
     * and invalid values to test error handling paths. */
    unsigned int cmd = g_fdp->ConsumeIntegralInRange<unsigned int>(0, 32);

    /* cmd_buf is [in, out, size=cmd_buf_size]. The enclave requires
     * cmd_buf_size to be a multiple of 8 (uint64 alignment).
     * We generate sizes that are always 8-byte aligned.
     * Typical handler needs 1-12 uint64 args, so 0-96 bytes.
     * We also sometimes generate larger sizes to test edge cases. */
    unsigned int num_args = g_fdp->ConsumeIntegralInRange<unsigned int>(0, 16);
    unsigned int cmd_buf_size = num_args * sizeof(uint64_t);

    uint8_t *cmd_buf = NULL;

    if (cmd_buf_size > 0) {
        cmd_buf = (uint8_t *)calloc(1, cmd_buf_size);
        if (cmd_buf) {
            g_fdp->ConsumeData(cmd_buf, cmd_buf_size);
        }
    }

    ecall_handle_command(__g_harness_eid, cmd, cmd_buf, cmd_buf_size);
}

HARNESS_REGISTER(harness_ecall_handle_command, 15)
