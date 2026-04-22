#pragma once

/* Harness focused on AoT/XIP file detection paths.
 *
 * Motivation: is_xip_file has only 25% coverage (4/16 edges). It requires
 * an AoT magic header (\0aot) with valid section structures. The current
 * harness_load_wasm_magic creates AoT headers but doesn't craft the sections
 * correctly for is_xip_file to return true.
 *
 * is_xip_file logic:
 *   1. get_package_type must return Wasm_Module_AoT → needs \0aot header
 *   2. Iterates sections, looking for AOT_SECTION_TYPE_TARGET_INFO
 *   3. Within that section, reads e_type and checks E_TYPE_XIP
 *
 * This harness crafts AoT-style bytes with proper section headers to
 * exercise these paths, plus tests invalid section structures.
 */

/* Helper: write a uint32 little-endian into buffer at position, advance pos */
static void write_u32_le(uint8_t *buf, uint32_t *pos, uint32_t val) {
    buf[*pos]     = (uint8_t)(val);
    buf[*pos + 1] = (uint8_t)(val >> 8);
    buf[*pos + 2] = (uint8_t)(val >> 16);
    buf[*pos + 3] = (uint8_t)(val >> 24);
    *pos += 4;
}

/* Helper: write a uint16 little-endian into buffer at position, advance pos */
static void write_u16_le(uint8_t *buf, uint32_t *pos, uint16_t val) {
    buf[*pos]     = (uint8_t)(val);
    buf[*pos + 1] = (uint8_t)(val >> 8);
    *pos += 2;
}

static void harness_aot_xip(void)
{
    /* ---- Phase 1: Init runtime ---- */
    {
        uint64_t args[1];
        args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
        ecall_handle_command(__g_harness_eid, 0 /* CMD_INIT_RUNTIME */,
                             (unsigned char *)args, sizeof(args));
    }

    /* ---- Phase 2: Craft AoT bytes with structured sections ---- */
    uint32_t module_handle_id = 0;
    {
        /* Choose what kind of AoT input to generate */
        uint32_t mode = g_fdp->ConsumeIntegralInRange<uint32_t>(0, 4);
        uint32_t buf_size = g_fdp->ConsumeIntegralInRange<uint32_t>(16, 2048);
        uint8_t *buf = (uint8_t *)calloc(1, buf_size);
        if (!buf) goto cleanup;
        uint32_t pos = 0;

        /* All modes start with AoT magic header */
        buf[pos++] = 0x00; buf[pos++] = 'a';
        buf[pos++] = 'o';  buf[pos++] = 't';
        buf[pos++] = 0x01; buf[pos++] = 0x00;
        buf[pos++] = 0x00; buf[pos++] = 0x00;

        if (mode == 0) {
            /* Mode 0: AoT with TARGET_INFO section containing E_TYPE_XIP
             * This should make is_xip_file return true */
            /* Section: type=TARGET_INFO (2), size=8 */
            if (pos + 12 <= buf_size) {
                write_u32_le(buf, &pos, 2); /* section_type = AOT_SECTION_TYPE_TARGET_INFO */
                write_u32_le(buf, &pos, 8); /* section_size */
                /* TARGET_INFO content: 4 bytes padding + 2 bytes e_type + 2 bytes padding */
                pos += 4; /* skip some fields */
                write_u16_le(buf, &pos, 0xFE19); /* E_TYPE_XIP value */
                pos += 2;
            }
            /* Fill remaining with fuzzed data */
            if (pos < buf_size) g_fdp->ConsumeData(buf + pos, buf_size - pos);
        } else if (mode == 1) {
            /* Mode 1: AoT with TARGET_INFO but non-XIP e_type */
            if (pos + 12 <= buf_size) {
                write_u32_le(buf, &pos, 2); /* section_type */
                write_u32_le(buf, &pos, 8); /* section_size */
                pos += 4;
                write_u16_le(buf, &pos, (uint16_t)g_fdp->ConsumeIntegral<uint16_t>());
                pos += 2;
            }
            if (pos < buf_size) g_fdp->ConsumeData(buf + pos, buf_size - pos);
        } else if (mode == 2) {
            /* Mode 2: AoT with sections before TARGET_INFO */
            /* First: a non-target-info section (type < SIGNATURE threshold) */
            if (pos + 12 <= buf_size) {
                write_u32_le(buf, &pos, 0); /* section_type = something else */
                write_u32_le(buf, &pos, 4); /* section_size */
                g_fdp->ConsumeData(buf + pos, 4);
                pos += 4;
            }
            /* Then: TARGET_INFO section */
            if (pos + 12 <= buf_size) {
                write_u32_le(buf, &pos, 2);
                write_u32_le(buf, &pos, 8);
                pos += 4;
                write_u16_le(buf, &pos, (uint16_t)g_fdp->ConsumeIntegral<uint16_t>());
                pos += 2;
            }
            if (pos < buf_size) g_fdp->ConsumeData(buf + pos, buf_size - pos);
        } else if (mode == 3) {
            /* Mode 3: AoT with SIGNATURE section first (section_type >= AOT_SECTION_TYPE_SIGNATURE)
             * This exercises the early return in is_xip_file */
            if (pos + 12 <= buf_size) {
                write_u32_le(buf, &pos, 100); /* section_type >= SIGNATURE threshold */
                write_u32_le(buf, &pos, 4);
                g_fdp->ConsumeData(buf + pos, 4);
                pos += 4;
            }
            if (pos < buf_size) g_fdp->ConsumeData(buf + pos, buf_size - pos);
        } else {
            /* Mode 4: AoT with truncated/invalid section data */
            /* Write section header but truncate section body */
            if (pos + 4 <= buf_size) {
                write_u32_le(buf, &pos, 2); /* TARGET_INFO type */
                write_u32_le(buf, &pos, 200); /* section_size larger than remaining buffer */
            }
            if (pos < buf_size) g_fdp->ConsumeData(buf + pos, buf_size - pos);
        }

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

    if (module_handle_id != 0) {
        /* If module loaded, try to instantiate and exercise more paths */
        if (g_fdp->ConsumeBool()) {
            char error_buf[256];
            uint64_t args[5];
            args[0] = (uint64_t)module_handle_id;
            args[1] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(4096, 65536);
            args[2] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(4096, 65536);
            args[3] = (uint64_t)(uintptr_t)error_buf;
            args[4] = (uint64_t)sizeof(error_buf);

            ecall_handle_command(__g_harness_eid, 2 /* CMD_INSTANTIATE_MODULE */,
                                 (unsigned char *)args, sizeof(args));
            uint32_t instance_id = (uint32_t)args[0];

            if (instance_id != 0) {
                /* Deinstantiate */
                uint64_t dargs[1];
                dargs[0] = (uint64_t)instance_id;
                ecall_handle_command(__g_harness_eid, 9 /* CMD_DEINSTANTIATE_MODULE */,
                                     (unsigned char *)dargs, sizeof(dargs));
            }
        }

        /* Unload module */
        uint64_t uargs[1];
        uargs[0] = (uint64_t)module_handle_id;
        ecall_handle_command(__g_harness_eid, 10 /* CMD_UNLOAD_MODULE */,
                             (unsigned char *)uargs, sizeof(uargs));
    }

cleanup:
    ecall_handle_command(__g_harness_eid, 11 /* CMD_DESTROY_RUNTIME */,
                         NULL, 0);
}

HARNESS_REGISTER(harness_aot_xip, 30)
