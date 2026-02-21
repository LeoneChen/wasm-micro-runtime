/*
 * EnclaveFuzz - SGX Enclave Fuzzing Test Harness (Auto-Generated)
 *
 * Generated from EDL: Enclave.edl
 *
 * ============================================================================
 * Fuzzing Framework Architecture
 * ============================================================================
 *
 * Initialization (once):
 *     LibFuzzer → LLVMFuzzerInitialize()
 *                  ↓
 *                 customized_init()  ← Register harnesses, calculate weights
 *
 * Fuzzing loop (per input):
 *     LibFuzzer → LLVMFuzzerTestOneInput(data, size)
 *                  ↓ Reinitialize g_fdp with new input
 *                  ↓ Recreate enclave (__g_harness_eid)
 *                  ↓
 *                 customized_harness()  ← Weighted selection
 *                  ↓
 *                 _harness_xxx()   ← Auto-generated test functions
 *                  ↓
 *                 ECall → Enclave Code
 *
 * ============================================================================
 * EDL Attribute Reference
 * ============================================================================
 *
 * | Attribute    | Meaning             | Fuzzing Strategy (ECall)         |
 * |--------------|---------------------|----------------------------------|
 * | [in]         | Input to callee     | Generate fuzzy data (Host→Encl)  |
 * | [out]        | Output from callee  | Allocate buffer (Encl→Host)      |
 * | [in,out]     | Bidirectional       | Generate input + allocate        |
 * | [size=N]     | Buffer size (bytes) | Use N for allocation             |
 * | [count=N]    | Array element count | Use N * sizeof(element)          |
 * | [string]     | Null-terminated str | Ensure null terminator           |
 * | [user_check] | No auto checking    | High fuzz value                  |
 *
 * CRITICAL: Direction Semantics ([in]/[out] relative to callee)
 * - For ECalls (Enclave is callee):
 *   [in] = Host→Enclave → FUZZ THIS in harness
 *   [out] = Enclave→Host → Allocate buffer only
 * - For OCalls (Host is callee):
 *   [in] = Enclave→Host → No fuzzing needed
 *   [out] = Host→Enclave → FUZZ THIS in OCall wrapper
 *
 * ============================================================================
 * Memory Management (Two Approaches)
 * ============================================================================
 * Approach 1 (Auto-Managed by g_alloc_mgr) - CURRENT DEFAULT:
 * - Use calloc() + g_alloc_mgr.push_back() to track allocations
 * - Framework in LLVMFuzzerTestOneInput (at test.cpp) automatically frees all
 * tracked memory after each iteration
 * - No explicit free() needed in harness functions
 * - Pros: Simple, no memory leaks, centralized cleanup
 * - Cons: Memory accumulates until end of iteration
 *
 * Approach 2 (Explicit free()):
 * - Use calloc() without g_alloc_mgr tracking
 * - Manually write free() calls at appropriate locations in harness code
 * - Pros: Immediate memory release, lower memory footprint
 * - Cons: Must ensure all allocations are freed, risk of memory leaks
 *
 * Usage: Choose approach based on your needs:
 * - Default: g_alloc_mgr for safety and simplicity
 * - Manual: Direct free() for memory-sensitive scenarios
 *
 * ============================================================================
 * Weighted Selection System
 * ============================================================================
 * Each harness has a weight (default: 10). Adjust weights in customized_init():
 * - High weight (e.g., 50-100) for critical/bottleneck paths
 * - Low weight (e.g., 1-5) for well-covered paths
 * - Modify test_harness_registry[i].weight before calculating total_weight
 *
 * ============================================================================
 */

#include "Enclave_u.h"
#include <errno.h>
#include <sgx_urts.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "FuzzedDataProvider.h"
#include <vector>

// ============================================================================
// Global Variables
// ============================================================================

extern FuzzedDataProvider *g_fdp;
extern std::vector<uint8_t *> g_alloc_mgr;
extern sgx_enclave_id_t __g_harness_eid;

// Fuzzing configuration parameters
static size_t g_max_strlen = 128; // Max string length for [string] attributes
static size_t g_max_cnt = 32;     // Max count for unbounded arrays
static size_t g_max_size = 512;   // Max size for unbounded buffers

// ============================================================================
// Test Harness Registration System
// ============================================================================

typedef void (*TestHarness)(void);

struct TestHarnessEntry {
    TestHarness function;
    int weight; // Selection weight (default: 10)
};

static TestHarnessEntry test_harness_registry[10240];
static unsigned int test_harness_count = 0;
static int total_weight = 0;

// ============================================================================
// OCall Wrappers
// ============================================================================
// These wrappers intercept OCalls and fuzz [out] parameters
// to test Enclave's resilience to untrusted data
// ============================================================================

extern "C" int
_harness_ocall_print(const char *str)
{
    int _fuzz_ret = ocall_print(str);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" void
_harness_sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
    sgx_oc_cpuidex(cpuinfo, leaf, subleaf);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
            g_fdp->ConsumeData(&cpuinfo[i_0_0], sizeof(int));
        }
    }
}

extern "C" int
_harness_sgx_thread_wait_untrusted_event_ocall(const void *self)
{
    int _fuzz_ret = sgx_thread_wait_untrusted_event_ocall(self);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_self = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)self, count_0_self * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_untrusted_event_ocall(const void *waiter)
{
    int _fuzz_ret = sgx_thread_set_untrusted_event_ocall(waiter);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_waiter = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_setwait_untrusted_events_ocall(const void *waiter,
                                                   const void *self)
{
    int _fuzz_ret = sgx_thread_setwait_untrusted_events_ocall(waiter, self);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_waiter = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_self = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)self, count_0_self * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_multiple_untrusted_events_ocall(const void **waiters,
                                                        size_t total)
{
    int _fuzz_ret =
        sgx_thread_set_multiple_untrusted_events_ocall(waiters, total);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_pthread_wait_timeout_ocall(unsigned long long waiter,
                                    unsigned long long timeout)
{
    int _fuzz_ret = pthread_wait_timeout_ocall(waiter, timeout);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_pthread_create_ocall(unsigned long long self)
{
    int _fuzz_ret = pthread_create_ocall(self);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_pthread_wakeup_ocall(unsigned long long waiter)
{
    int _fuzz_ret = pthread_wakeup_ocall(waiter);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_open(const char *pathname, int flags, bool has_mode,
                    unsigned int mode)
{
    int _fuzz_ret = ocall_open(pathname, flags, has_mode, mode);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_openat(int dirfd, const char *pathname, int flags, bool has_mode,
                      unsigned int mode)
{
    int _fuzz_ret = ocall_openat(dirfd, pathname, flags, has_mode, mode);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_close(int fd)
{
    int _fuzz_ret = ocall_close(fd);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_read(int fd, void *buf, size_t read_size)
{
    ssize_t _fuzz_ret = ocall_read(fd, buf, read_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (read_size)) / 1;
        g_fdp->ConsumeData((void *)buf, count_0_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" off_t
_harness_ocall_lseek(int fd, off_t offset, int whence)
{
    off_t _fuzz_ret = ocall_lseek(fd, offset, whence);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_ftruncate(int fd, off_t length)
{
    int _fuzz_ret = ocall_ftruncate(fd, length);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_fsync(int fd)
{
    int _fuzz_ret = ocall_fsync(fd);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_fdatasync(int fd)
{
    int _fuzz_ret = ocall_fdatasync(fd);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_isatty(int fd)
{
    int _fuzz_ret = ocall_isatty(fd);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" void
_harness_ocall_fdopendir(int fd, void **p_dirp)
{
    ocall_fdopendir(fd, p_dirp);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_p_dirp = ((1) * (sizeof(void *))) / sizeof(void *);
        for (size_t i_0_p_dirp = 0; i_0_p_dirp < count_0_p_dirp; i_0_p_dirp++) {
            void *p_dirp_0_deref = NULL;
            p_dirp_0_deref = p_dirp[i_0_p_dirp];
            size_t count_1_p_dirp_0_deref =
                g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1,
                                                      g_max_cnt);
            g_fdp->ConsumeData((void *)p_dirp_0_deref,
                               count_1_p_dirp_0_deref * 1);
        }
    }
}

extern "C" void *
_harness_ocall_readdir(void *dirp)
{
    void *_fuzz_ret = ocall_readdir(dirp);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_dirp = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)dirp, count_0_dirp * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0__fuzz_ret = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)_fuzz_ret, count_0__fuzz_ret * 1);
    }
    return _fuzz_ret;
}

extern "C" void
_harness_ocall_rewinddir(void *dirp)
{
    ocall_rewinddir(dirp);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_dirp = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)dirp, count_0_dirp * 1);
    }
}

extern "C" void
_harness_ocall_seekdir(void *dirp, long int loc)
{
    ocall_seekdir(dirp, loc);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_dirp = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)dirp, count_0_dirp * 1);
    }
}

extern "C" long int
_harness_ocall_telldir(void *dirp)
{
    long int _fuzz_ret = ocall_telldir(dirp);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_dirp = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)dirp, count_0_dirp * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(long int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_closedir(void *dirp)
{
    int _fuzz_ret = ocall_closedir(dirp);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_dirp = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)dirp, count_0_dirp * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_stat(const char *pathname, void *buf, unsigned int buf_len)
{
    int _fuzz_ret = ocall_stat(pathname, buf, buf_len);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (buf_len)) / 1;
        g_fdp->ConsumeData((void *)buf, count_0_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_fstat(int fd, void *buf, unsigned int buf_len)
{
    int _fuzz_ret = ocall_fstat(fd, buf, buf_len);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (buf_len)) / 1;
        g_fdp->ConsumeData((void *)buf, count_0_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_fstatat(int dirfd, const char *pathname, void *buf,
                       unsigned int buf_len, int flags)
{
    int _fuzz_ret = ocall_fstatat(dirfd, pathname, buf, buf_len, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (buf_len)) / 1;
        g_fdp->ConsumeData((void *)buf, count_0_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_mkdirat(int dirfd, const char *pathname, unsigned int mode)
{
    int _fuzz_ret = ocall_mkdirat(dirfd, pathname, mode);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_link(const char *oldpath, const char *newpath)
{
    int _fuzz_ret = ocall_link(oldpath, newpath);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_linkat(int olddirfd, const char *oldpath, int newdirfd,
                      const char *newpath, int flags)
{
    int _fuzz_ret = ocall_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_unlinkat(int dirfd, const char *pathname, int flags)
{
    int _fuzz_ret = ocall_unlinkat(dirfd, pathname, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    ssize_t _fuzz_ret = ocall_readlink(pathname, buf, bufsiz);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (bufsiz)) / sizeof(char);
        g_fdp->ConsumeData((void *)buf, count_0_buf * sizeof(char));
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_readlinkat(int dirfd, const char *pathname, char *buf,
                          size_t bufsiz)
{
    ssize_t _fuzz_ret = ocall_readlinkat(dirfd, pathname, buf, bufsiz);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (bufsiz)) / sizeof(char);
        g_fdp->ConsumeData((void *)buf, count_0_buf * sizeof(char));
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_renameat(int olddirfd, const char *oldpath, int newdirfd,
                        const char *newpath)
{
    int _fuzz_ret = ocall_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    int _fuzz_ret = ocall_symlinkat(target, newdirfd, linkpath);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_ioctl(int fd, unsigned long int request, void *arg,
                     unsigned int arg_len)
{
    int _fuzz_ret = ocall_ioctl(fd, request, arg, arg_len);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_arg = ((1) * (arg_len)) / 1;
        g_fdp->ConsumeData((void *)arg, count_0_arg * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_fcntl(int fd, int cmd)
{
    int _fuzz_ret = ocall_fcntl(fd, cmd);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_fcntl_long(int fd, int cmd, long int arg)
{
    int _fuzz_ret = ocall_fcntl_long(fd, cmd, arg);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_realpath(const char *path, char *buf, unsigned int buf_len)
{
    int _fuzz_ret = ocall_realpath(path, buf, buf_len);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (buf_len)) / sizeof(char);
        g_fdp->ConsumeData((void *)buf, count_0_buf * sizeof(char));
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_posix_fallocate(int fd, off_t offset, off_t len)
{
    int _fuzz_ret = ocall_posix_fallocate(fd, offset, len);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_poll(void *fds, unsigned int nfds, int timeout,
                    unsigned int fds_len)
{
    int _fuzz_ret = ocall_poll(fds, nfds, timeout, fds_len);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_fds = ((1) * (fds_len)) / 1;
        g_fdp->ConsumeData((void *)fds, count_0_fds * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_getopt(int argc, char *argv_buf, unsigned int argv_buf_len,
                      const char *optstring)
{
    int _fuzz_ret = ocall_getopt(argc, argv_buf, argv_buf_len, optstring);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_readv(int fd, char *iov_buf, unsigned int buf_size, int iovcnt,
                     bool has_offset, off_t offset)
{
    ssize_t _fuzz_ret =
        ocall_readv(fd, iov_buf, buf_size, iovcnt, has_offset, offset);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_iov_buf = ((1) * (buf_size)) / sizeof(char);
        g_fdp->ConsumeData((void *)iov_buf, count_0_iov_buf * sizeof(char));
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_writev(int fd, char *iov_buf, unsigned int buf_size, int iovcnt,
                      bool has_offset, off_t offset)
{
    ssize_t _fuzz_ret =
        ocall_writev(fd, iov_buf, buf_size, iovcnt, has_offset, offset);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_clock_gettime(unsigned int clock_id, void *tp_buf,
                             unsigned int tp_buf_size)
{
    int _fuzz_ret = ocall_clock_gettime(clock_id, tp_buf, tp_buf_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_tp_buf = ((1) * (tp_buf_size)) / 1;
        g_fdp->ConsumeData((void *)tp_buf, count_0_tp_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_clock_getres(int clock_id, void *res_buf,
                            unsigned int res_buf_size)
{
    int _fuzz_ret = ocall_clock_getres(clock_id, res_buf, res_buf_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_res_buf = ((1) * (res_buf_size)) / 1;
        g_fdp->ConsumeData((void *)res_buf, count_0_res_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_utimensat(int dirfd, const char *pathname, const void *times_buf,
                         unsigned int times_buf_size, int flags)
{
    int _fuzz_ret =
        ocall_utimensat(dirfd, pathname, times_buf, times_buf_size, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_futimens(int fd, const void *times_buf,
                        unsigned int times_buf_size)
{
    int _fuzz_ret = ocall_futimens(fd, times_buf, times_buf_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_clock_nanosleep(unsigned int clock_id, int flags,
                               const void *req_buf, unsigned int req_buf_size,
                               void *rem_buf, unsigned int rem_buf_size)
{
    int _fuzz_ret = ocall_clock_nanosleep(clock_id, flags, req_buf,
                                          req_buf_size, rem_buf, rem_buf_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_rem_buf = ((1) * (rem_buf_size)) / 1;
        g_fdp->ConsumeData((void *)rem_buf, count_0_rem_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_raise(int sig)
{
    int _fuzz_ret = ocall_raise(sig);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_sched_yield(void)
{
    int _fuzz_ret = ocall_sched_yield();
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_pthread_rwlock_init(void **rwlock, void *attr)
{
    int _fuzz_ret = ocall_pthread_rwlock_init(rwlock, attr);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_rwlock = ((1) * (sizeof(void *))) / sizeof(void *);
        for (size_t i_0_rwlock = 0; i_0_rwlock < count_0_rwlock; i_0_rwlock++) {
            void *rwlock_0_deref = NULL;
            rwlock_0_deref = rwlock[i_0_rwlock];
            size_t count_1_rwlock_0_deref =
                g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1,
                                                      g_max_cnt);
            g_fdp->ConsumeData((void *)rwlock_0_deref,
                               count_1_rwlock_0_deref * 1);
        }
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_attr = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)attr, count_0_attr * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_pthread_rwlock_destroy(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_destroy(rwlock);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_rwlock = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)rwlock, count_0_rwlock * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_pthread_rwlock_rdlock(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_rdlock(rwlock);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_rwlock = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)rwlock, count_0_rwlock * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_pthread_rwlock_wrlock(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_wrlock(rwlock);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_rwlock = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)rwlock, count_0_rwlock * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_pthread_rwlock_unlock(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_unlock(rwlock);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_rwlock = g_fdp->ConsumeIntegralInRange<size_t>(
            1 < 8 ? (20 / 1) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)rwlock, count_0_rwlock * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_get_errno(void)
{
    int _fuzz_ret = ocall_get_errno();
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_accept(int sockfd, void *addr, uint32_t *addrlen,
                      uint32_t addr_size)
{
    int _fuzz_ret = ocall_accept(sockfd, addr, addrlen, addr_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_bind(int sockfd, const void *addr, uint32_t addrlen)
{
    int _fuzz_ret = ocall_bind(sockfd, addr, addrlen);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_connect(int sockfd, void *addr, uint32_t addrlen)
{
    int _fuzz_ret = ocall_connect(sockfd, addr, addrlen);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_getsockname(int sockfd, void *addr, uint32_t *addrlen,
                           uint32_t addr_size)
{
    int _fuzz_ret = ocall_getsockname(sockfd, addr, addrlen, addr_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_addr = ((1) * (addr_size)) / 1;
        g_fdp->ConsumeData((void *)addr, count_0_addr * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_addrlen = ((1) * (4)) / sizeof(uint32_t);
        g_fdp->ConsumeData((void *)addrlen, count_0_addrlen * sizeof(uint32_t));
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_getpeername(int sockfd, void *addr, uint32_t *addrlen,
                           uint32_t addr_size)
{
    int _fuzz_ret = ocall_getpeername(sockfd, addr, addrlen, addr_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_addr = ((1) * (addr_size)) / 1;
        g_fdp->ConsumeData((void *)addr, count_0_addr * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_addrlen = ((1) * (4)) / sizeof(uint32_t);
        g_fdp->ConsumeData((void *)addrlen, count_0_addrlen * sizeof(uint32_t));
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_getsockopt(int sockfd, int level, int optname, void *val_buf,
                          unsigned int val_buf_size, void *len_buf)
{
    int _fuzz_ret = ocall_getsockopt(sockfd, level, optname, val_buf,
                                     val_buf_size, len_buf);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_val_buf = ((1) * (val_buf_size)) / 1;
        g_fdp->ConsumeData((void *)val_buf, count_0_val_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_len_buf = ((1) * (4)) / 1;
        g_fdp->ConsumeData((void *)len_buf, count_0_len_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_listen(int sockfd, int backlog)
{
    int _fuzz_ret = ocall_listen(sockfd, backlog);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    int _fuzz_ret = ocall_recv(sockfd, buf, len, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (len)) / 1;
        g_fdp->ConsumeData((void *)buf, count_0_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        void *src_addr, uint32_t *addrlen, uint32_t addr_size)
{
    ssize_t _fuzz_ret =
        ocall_recvfrom(sockfd, buf, len, flags, src_addr, addrlen, addr_size);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_buf = ((1) * (len)) / 1;
        g_fdp->ConsumeData((void *)buf, count_0_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_src_addr = ((1) * (addr_size)) / 1;
        g_fdp->ConsumeData((void *)src_addr, count_0_src_addr * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_addrlen = ((1) * (4)) / sizeof(uint32_t);
        g_fdp->ConsumeData((void *)addrlen, count_0_addrlen * sizeof(uint32_t));
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_recvmsg(int sockfd, void *msg_buf, unsigned int msg_buf_size,
                       int flags)
{
    ssize_t _fuzz_ret = ocall_recvmsg(sockfd, msg_buf, msg_buf_size, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        size_t count_0_msg_buf = ((1) * (msg_buf_size)) / 1;
        g_fdp->ConsumeData((void *)msg_buf, count_0_msg_buf * 1);
    }
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    int _fuzz_ret = ocall_send(sockfd, buf, len, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_sendto(int sockfd, const void *buf, size_t len, int flags,
                      void *dest_addr, uint32_t addrlen)
{
    ssize_t _fuzz_ret =
        ocall_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" ssize_t
_harness_ocall_sendmsg(int sockfd, void *msg_buf, unsigned int msg_buf_size,
                       int flags)
{
    ssize_t _fuzz_ret = ocall_sendmsg(sockfd, msg_buf, msg_buf_size, flags);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, 1);
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_setsockopt(int sockfd, int level, int optname, void *optval,
                          unsigned int optlen)
{
    int _fuzz_ret = ocall_setsockopt(sockfd, level, optname, optval, optlen);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_shutdown(int sockfd, int how)
{
    int _fuzz_ret = ocall_shutdown(sockfd, how);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

extern "C" int
_harness_ocall_socket(int domain, int type, int protocol)
{
    int _fuzz_ret = ocall_socket(domain, type, protocol);
    if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
        g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
    }
    return _fuzz_ret;
}

// ============================================================================
// ECall Test Harnesses
// ============================================================================
// Auto-generated harness functions for each ECall
// Each function prepares fuzz inputs and invokes the corresponding ECall
// ============================================================================

static void
_harness_ecall_handle_command(void)
{
    unsigned int cmd;
    g_fdp->ConsumeData(&cmd, sizeof(unsigned int));
    uint8_t *cmd_buf = NULL;
    unsigned int cmd_buf_size;
    cmd_buf_size = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);
    cmd_buf = NULL;
    if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
        size_t count_0_cmd_buf =
            ((1) * (cmd_buf_size) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
        cmd_buf = (uint8_t *)calloc(count_0_cmd_buf, sizeof(uint8_t));
        g_alloc_mgr.push_back((uint8_t *)cmd_buf);
        g_fdp->ConsumeData((void *)cmd_buf, count_0_cmd_buf * sizeof(uint8_t));
    }
    ecall_handle_command(__g_harness_eid, cmd, cmd_buf, cmd_buf_size);
}
static void
_harness_ecall_iwasm_main(void)
{
    uint8_t *wasm_file_buf = NULL;
    wasm_file_buf = NULL;
    if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
        size_t count_0_wasm_file_buf = g_fdp->ConsumeIntegralInRange<size_t>(
            sizeof(uint8_t) < 8 ? (20 / sizeof(uint8_t)) : 1, g_max_cnt);
        wasm_file_buf =
            (uint8_t *)calloc(count_0_wasm_file_buf, sizeof(uint8_t));
        g_alloc_mgr.push_back((uint8_t *)wasm_file_buf);
        g_fdp->ConsumeData((void *)wasm_file_buf,
                           count_0_wasm_file_buf * sizeof(uint8_t));
    }
    uint32_t wasm_file_size;
    g_fdp->ConsumeData(&wasm_file_size, sizeof(uint32_t));
    ecall_iwasm_main(__g_harness_eid, wasm_file_buf, wasm_file_size);
}

// ============================================================================
// Targeted Bottleneck Harnesses
// ============================================================================
// These harnesses target specific coverage bottlenecks identified by analysis.
// They provide properly structured inputs to reach deep code paths.
// ============================================================================

// Command IDs matching EcallCmd enum in Enclave.cpp
#define HARNESS_CMD_INIT_RUNTIME         0
#define HARNESS_CMD_LOAD_MODULE          1
#define HARNESS_CMD_INSTANTIATE_MODULE   2
#define HARNESS_CMD_EXEC_APP_FUNC        6
#define HARNESS_CMD_EXEC_APP_MAIN        7
#define HARNESS_CMD_GET_EXCEPTION        8
#define HARNESS_CMD_DEINSTANTIATE_MODULE 9
#define HARNESS_CMD_UNLOAD_MODULE        10
#define HARNESS_CMD_DESTROY_RUNTIME      11
#define HARNESS_CMD_SET_WASI_ARGS        12
#define HARNESS_CMD_SET_LOG_LEVEL        13
#define HARNESS_CMD_GET_VERSION          14

// WASM binary magic: \0asm + version 1
static const uint8_t wasm_magic_hdr[8] = {
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00
};
// AOT binary magic: \0aot
static const uint8_t aot_magic_hdr[4] = {
    0x00, 0x61, 0x6F, 0x74
};

// Helper: write unsigned LEB128 encoding, returns number of bytes written
static size_t
write_u32_leb128(uint8_t *buf, uint32_t value)
{
    size_t n = 0;
    do {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value != 0)
            byte |= 0x80;
        buf[n++] = byte;
    } while (value != 0);
    return n;
}

// Helper: write a WASM section (section_id + LEB128 size + body)
static size_t
write_wasm_section(uint8_t *buf, uint8_t section_id,
                   const uint8_t *body, size_t body_size)
{
    size_t off = 0;
    buf[off++] = section_id;
    off += write_u32_leb128(buf + off, (uint32_t)body_size);
    memcpy(buf + off, body, body_size);
    return off + body_size;
}

/*
 * Workflow harness: exercises the full command pipeline.
 * init_runtime -> load_module -> set_wasi_args -> instantiate -> exec -> cleanup
 *
 * Targets bottlenecks in:
 *   handle_cmd_load_module (50%), handle_cmd_set_wasi_args (16%),
 *   handle_cmd_instantiate_module (55%), handle_cmd_exec_app_main (38%),
 *   handle_cmd_exec_app_func (41%), handle_cmd_get_exception (42%),
 *   handle_cmd_unload_module (33%), handle_cmd_deinstantiate_module (83%)
 */
static void
harness_cmd_workflow(void)
{
    if (g_fdp->remaining_bytes() < 32)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Step 1: Initialize runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 8);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        return;

    /* Step 2: Set log level */
    {
        uint64_t log_args[1];
        log_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(0, 5);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_SET_LOG_LEVEL,
                             (uint8_t *)log_args, sizeof(log_args));
    }

    /* Step 3: Load module with WASM/AOT magic header */
    size_t wasm_size = g_fdp->ConsumeIntegralInRange<size_t>(16, 4096);
    uint8_t *wasm_file = (uint8_t *)calloc(1, wasm_size);
    g_alloc_mgr.push_back(wasm_file);
    if (!wasm_file)
        goto cleanup;

    /* Choose format: 70% WASM, 30% AOT */
    if (g_fdp->ConsumeProbability<double>() < 0.7) {
        memcpy(wasm_file, wasm_magic_hdr, sizeof(wasm_magic_hdr));
    }
    else {
        memcpy(wasm_file, aot_magic_hdr, sizeof(aot_magic_hdr));
        uint32_t aot_ver = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 3);
        memcpy(wasm_file + 4, &aot_ver, sizeof(aot_ver));
    }

    /* Fill rest of wasm data with fuzz input */
    if (wasm_size > 8) {
        size_t fill = wasm_size - 8;
        if (g_fdp->remaining_bytes() >= fill)
            g_fdp->ConsumeData(wasm_file + 8, fill);
        else if (g_fdp->remaining_bytes() > 0)
            g_fdp->ConsumeData(wasm_file + 8, g_fdp->remaining_bytes());
    }

    {
        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)wasm_file;
        load_args[1] = (uint64_t)wasm_size;
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Step 4: Set WASI args (50% chance) */
        if (g_fdp->remaining_bytes() > 16
            && g_fdp->ConsumeProbability<double>() < 0.5) {
            char *dir_str = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir_str);
            char *argv_str = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv_str);
            char **dir_list_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)dir_list_arr);
            char **argv_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)argv_arr);

            if (dir_str && argv_str && dir_list_arr && argv_arr) {
                memcpy(dir_str, ".", 2);
                memcpy(argv_str, "test", 5);
                dir_list_arr[0] = dir_str;
                argv_arr[0] = argv_str;

                uint64_t wasi_args[12];
                wasi_args[0] = (uint64_t)(uintptr_t)enclave_module;
                wasi_args[1] = (uint64_t)(uintptr_t)dir_list_arr;
                wasi_args[2] = 1;  /* dir_list_size */
                wasi_args[3] = 0;  /* env_list (NULL) */
                wasi_args[4] = 0;  /* env_list_size */
                wasi_args[5] = 0;  /* stdinfd */
                wasi_args[6] = 1;  /* stdoutfd */
                wasi_args[7] = 2;  /* stderrfd */
                wasi_args[8] = (uint64_t)(uintptr_t)argv_arr;
                wasi_args[9] = 1;  /* wasi_argc */
                wasi_args[10] = 0; /* addr_pool_list (NULL) */
                wasi_args[11] = 0; /* addr_pool_list_size */
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_SET_WASI_ARGS,
                                     (uint8_t *)wasi_args,
                                     sizeof(wasi_args));
            }
        }

        /* Step 5: Instantiate module */
        memset(error_buf, 0, sizeof(error_buf));
        {
            uint64_t inst_args[5];
            inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
            inst_args[1] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(
                8 * 1024, 64 * 1024);
            inst_args[2] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(
                8 * 1024, 64 * 1024);
            inst_args[3] = (uint64_t)(uintptr_t)error_buf;
            inst_args[4] = (uint64_t)sizeof(error_buf);
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_INSTANTIATE_MODULE,
                                 (uint8_t *)inst_args, sizeof(inst_args));

            void *module_inst = (void *)(uintptr_t)inst_args[0];

            if (module_inst) {
                /* Step 6a: Execute main or func */
                if (g_fdp->remaining_bytes() > 8) {
                    if (g_fdp->ConsumeProbability<double>() < 0.5) {
                        /* CMD_EXEC_APP_MAIN */
                        char *main_arg = (char *)calloc(1, 16);
                        g_alloc_mgr.push_back((uint8_t *)main_arg);
                        if (main_arg) {
                            memcpy(main_arg, "main", 5);
                            uint64_t exec_args[3];
                            exec_args[0] =
                                (uint64_t)(uintptr_t)module_inst;
                            exec_args[1] = 1; /* app_argc */
                            exec_args[2] =
                                (uint64_t)(uintptr_t)main_arg;
                            ecall_handle_command(
                                __g_harness_eid,
                                HARNESS_CMD_EXEC_APP_MAIN,
                                (uint8_t *)exec_args,
                                sizeof(exec_args));
                        }
                    }
                    else {
                        /* CMD_EXEC_APP_FUNC */
                        char *func_name = (char *)calloc(1, 32);
                        g_alloc_mgr.push_back((uint8_t *)func_name);
                        if (func_name) {
                            const char *names[] = {
                                "main", "_start", "run", "test", "init"};
                            int idx =
                                g_fdp->ConsumeIntegralInRange<int>(0, 4);
                            memcpy(func_name, names[idx],
                                   strlen(names[idx]) + 1);

                            uint64_t exec_args[3];
                            exec_args[0] =
                                (uint64_t)(uintptr_t)module_inst;
                            exec_args[1] =
                                (uint64_t)(uintptr_t)func_name;
                            exec_args[2] = 0; /* app_argc */
                            ecall_handle_command(
                                __g_harness_eid,
                                HARNESS_CMD_EXEC_APP_FUNC,
                                (uint8_t *)exec_args,
                                sizeof(exec_args));
                        }
                    }
                }

                /* Step 6b: Get exception */
                {
                    char exc_buf[256];
                    memset(exc_buf, 0, sizeof(exc_buf));
                    uint64_t exc_args[3];
                    exc_args[0] = (uint64_t)(uintptr_t)module_inst;
                    exc_args[1] = (uint64_t)(uintptr_t)exc_buf;
                    exc_args[2] = (uint64_t)sizeof(exc_buf);
                    ecall_handle_command(__g_harness_eid,
                                         HARNESS_CMD_GET_EXCEPTION,
                                         (uint8_t *)exc_args,
                                         sizeof(exc_args));
                }

                /* Step 7: Deinstantiate module */
                {
                    uint64_t deinst_args[1];
                    deinst_args[0] = (uint64_t)(uintptr_t)module_inst;
                    ecall_handle_command(
                        __g_harness_eid,
                        HARNESS_CMD_DEINSTANTIATE_MODULE,
                        (uint8_t *)deinst_args, sizeof(deinst_args));
                }
            }

            /* Step 8: Unload module */
            {
                uint64_t unload_args[1];
                unload_args[0] = (uint64_t)(uintptr_t)enclave_module;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_UNLOAD_MODULE,
                                     (uint8_t *)unload_args,
                                     sizeof(unload_args));
            }
        }
    }

cleanup:
    /* Step 9: Destroy runtime */
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * Improved ecall_iwasm_main with structured WASM/AOT data.
 * Fixes: wasm_file_size matches actual buffer, includes proper magic header.
 *
 * Targets bottlenecks in:
 *   ecall_iwasm_main (60%), wasm_runtime_load_ex (46%),
 *   get_package_type (76%), aot_load_from_aot_file (50%),
 *   create_sections (18%), resolve_execute_mode (31%)
 */
static void
harness_iwasm_main_structured(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    size_t wasm_size = g_fdp->ConsumeIntegralInRange<size_t>(8, 2048);
    uint8_t *wasm_file = (uint8_t *)calloc(1, wasm_size);
    g_alloc_mgr.push_back(wasm_file);
    if (!wasm_file)
        return;

    /* Choose format: 60% WASM, 40% AOT */
    if (g_fdp->ConsumeProbability<double>() < 0.6) {
        memcpy(wasm_file, wasm_magic_hdr, sizeof(wasm_magic_hdr));
    }
    else {
        memcpy(wasm_file, aot_magic_hdr, sizeof(aot_magic_hdr));
        uint32_t aot_ver = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 3);
        memcpy(wasm_file + 4, &aot_ver, sizeof(aot_ver));
    }

    /* Fill rest with fuzz data */
    if (wasm_size > 8) {
        size_t fill = wasm_size - 8;
        if (g_fdp->remaining_bytes() >= fill)
            g_fdp->ConsumeData(wasm_file + 8, fill);
        else if (g_fdp->remaining_bytes() > 0)
            g_fdp->ConsumeData(wasm_file + 8, g_fdp->remaining_bytes());
    }

    /* Key fix: wasm_file_size matches actual buffer size */
    ecall_iwasm_main(__g_harness_eid, wasm_file, (uint32_t)wasm_size);
}

/*
 * Targeted individual command harness with proper argc.
 * Ensures cmd_buf is properly sized for each command type.
 */
static void
harness_cmd_targeted(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    unsigned cmd = g_fdp->ConsumeIntegralInRange<unsigned>(0, 14);

    switch (cmd) {
        case HARNESS_CMD_INIT_RUNTIME: {
            uint64_t args[1];
            args[0] = (uint64_t)g_fdp->ConsumeIntegral<uint32_t>();
            ecall_handle_command(__g_harness_eid, cmd,
                                 (uint8_t *)args, sizeof(args));
            break;
        }
        case HARNESS_CMD_SET_LOG_LEVEL: {
            uint64_t args[1];
            args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(0, 5);
            ecall_handle_command(__g_harness_eid, cmd,
                                 (uint8_t *)args, sizeof(args));
            break;
        }
        case HARNESS_CMD_GET_VERSION: {
            uint64_t args[3] = {0, 0, 0};
            ecall_handle_command(__g_harness_eid, cmd,
                                 (uint8_t *)args, sizeof(args));
            break;
        }
        case HARNESS_CMD_DESTROY_RUNTIME: {
            ecall_handle_command(__g_harness_eid, cmd, NULL, 0);
            break;
        }
        default: {
            /* For stateful commands, create properly-sized fuzzed buffer */
            size_t argc_needed;
            switch (cmd) {
                case HARNESS_CMD_LOAD_MODULE:
                    argc_needed = 4;
                    break;
                case HARNESS_CMD_SET_WASI_ARGS:
                    argc_needed = 12;
                    break;
                case HARNESS_CMD_INSTANTIATE_MODULE:
                    argc_needed = 5;
                    break;
                case HARNESS_CMD_EXEC_APP_FUNC:
                case HARNESS_CMD_EXEC_APP_MAIN:
                case HARNESS_CMD_GET_EXCEPTION:
                    argc_needed = 3;
                    break;
                case HARNESS_CMD_DEINSTANTIATE_MODULE:
                case HARNESS_CMD_UNLOAD_MODULE:
                    argc_needed = 1;
                    break;
                default:
                    argc_needed = 1;
                    break;
            }
            size_t buf_size = argc_needed * sizeof(uint64_t);
            uint8_t *buf = (uint8_t *)calloc(1, buf_size);
            g_alloc_mgr.push_back(buf);
            if (buf) {
                if (g_fdp->remaining_bytes() >= buf_size)
                    g_fdp->ConsumeData(buf, buf_size);
                ecall_handle_command(__g_harness_eid, cmd,
                                     buf, (unsigned)buf_size);
            }
            break;
        }
    }
}

/*
 * Null buffer edge case harness.
 * Targets: ecall_handle_command line 837 (NULL buffer with non-zero size)
 */
static void
harness_cmd_null_buf(void)
{
    unsigned cmd = g_fdp->ConsumeIntegralInRange<unsigned>(0, 14);
    unsigned size = g_fdp->ConsumeIntegralInRange<unsigned>(1, 256);
    ecall_handle_command(__g_harness_eid, cmd, NULL, size);
}

/*
 * Minimal valid WASM through ecall_iwasm_main.
 * Constructs a module with proper sections: type, function, memory, export,
 * code. The function body is trivial (just 'end') to ensure successful load,
 * instantiation, and execution through the full pipeline.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (0%), execute_main (6%),
 *   wasm_runtime_init_wasi (2%), execute_post_instantiate_functions (13%),
 *   wasm_instantiate (16%), load_from_sections (18%),
 *   load_type_section (16%), load_function_section (5%),
 *   load_export_section (13%), load_memory_section (20%)
 */
static void
harness_valid_wasm_minimal(void)
{
    /* Minimal valid WASM module:
     * - 1 type: () -> ()
     * - 1 function: type_idx=0
     * - 1 memory: min=1 page
     * - 2 exports: "memory" (memory 0), "_start" (func 0)
     * - 1 code entry: 0 locals, end */
    static const uint8_t module[] = {
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, /* magic+version */
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00,             /* type section */
        0x03, 0x02, 0x01, 0x00,                           /* func section */
        0x05, 0x03, 0x01, 0x00, 0x01,                     /* memory section */
        0x07, 0x13, 0x02,                                 /* export hdr */
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00, /* "memory" */
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00, /* "_start" */
        0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B,             /* code section */
    };
    uint8_t *buf = (uint8_t *)calloc(1, sizeof(module));
    g_alloc_mgr.push_back(buf);
    if (!buf)
        return;
    memcpy(buf, module, sizeof(module));
    ecall_iwasm_main(__g_harness_eid, buf, (uint32_t)sizeof(module));
}

/*
 * Valid WASM with fuzzed function body through ecall_iwasm_main.
 * Builds a structurally valid module but fills the code section body
 * with fuzzer-generated bytecode (always ending with 'end' opcode 0x0B).
 * This exercises the bytecode validator and, when valid, the interpreter.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (0%), wasm_loader_prepare_bytecode,
 *   load_code_section (57%), load_from_sections (18%)
 */
static void
harness_valid_wasm_fuzz_body(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    size_t body_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 256);

    uint8_t *module_buf = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(module_buf);
    if (!module_buf)
        return;

    size_t off = 0;

    /* Magic + version */
    memcpy(module_buf, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 1 type () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(module_buf + off, 0x01,
                              type_body, sizeof(type_body));

    /* Function section: 1 function, type_idx=0 */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(module_buf + off, 0x03,
                              func_body, sizeof(func_body));

    /* Memory section: 1 memory, min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(module_buf + off, 0x05,
                              mem_body, sizeof(mem_body));

    /* Export section: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(module_buf + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: 1 code entry with fuzzed bytecode */
    uint8_t code_buf[300];
    size_t cb_off = 0;
    code_buf[cb_off++] = 0x01; /* 1 code entry */

    /* Function body: 0 local groups + fuzzed bytecode ending with 0x0B */
    uint8_t func_bytecode[258];
    size_t fb_off = 0;
    func_bytecode[fb_off++] = 0x00; /* 0 local groups */

    size_t actual = body_len;
    if (g_fdp->remaining_bytes() < actual)
        actual = g_fdp->remaining_bytes();
    if (actual > 0)
        g_fdp->ConsumeData(func_bytecode + fb_off, actual);
    fb_off += actual;
    func_bytecode[fb_off - 1] = 0x0B; /* ensure end opcode */

    cb_off += write_u32_leb128(code_buf + cb_off, (uint32_t)fb_off);
    memcpy(code_buf + cb_off, func_bytecode, fb_off);
    cb_off += fb_off;

    off += write_wasm_section(module_buf + off, 0x0A, code_buf, cb_off);

    ecall_iwasm_main(__g_harness_eid, module_buf, (uint32_t)off);
}

/*
 * Valid WASM with multiple section types through ecall_iwasm_main.
 * Includes: type, function, table, memory, global, export, start, code.
 *
 * Targets bottlenecks in:
 *   load_table_section (45%), load_global_section (23%),
 *   load_start_section (22%), execute_post_instantiate_functions (13%),
 *   all instantiation/execution paths
 */
static void
harness_valid_wasm_rich(void)
{
    uint8_t *module_buf = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(module_buf);
    if (!module_buf)
        return;

    size_t off = 0;

    /* Magic + version */
    memcpy(module_buf, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 2 types: () -> () and (i32) -> (i32) */
    static const uint8_t type_body[] = {
        0x02,
        0x60, 0x00, 0x00,                   /* () -> () */
        0x60, 0x01, 0x7F, 0x01, 0x7F,       /* (i32) -> (i32) */
    };
    off += write_wasm_section(module_buf + off, 0x01,
                              type_body, sizeof(type_body));

    /* Function section: 2 functions */
    static const uint8_t func_body[] = { 0x02, 0x00, 0x01 };
    off += write_wasm_section(module_buf + off, 0x03,
                              func_body, sizeof(func_body));

    /* Table section: 1 table, funcref, min=1 */
    static const uint8_t table_body[] = { 0x01, 0x70, 0x00, 0x01 };
    off += write_wasm_section(module_buf + off, 0x04,
                              table_body, sizeof(table_body));

    /* Memory section: 1 memory, min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(module_buf + off, 0x05,
                              mem_body, sizeof(mem_body));

    /* Global section: 1 global, i32, mutable, init=0 */
    static const uint8_t global_body[] = {
        0x01,
        0x7F, 0x01,             /* i32, mutable */
        0x41, 0x00, 0x0B,       /* i32.const 0, end */
    };
    off += write_wasm_section(module_buf + off, 0x06,
                              global_body, sizeof(global_body));

    /* Export section: memory + _start + global */
    static const uint8_t export_body[] = {
        0x03,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
        0x02, 0x67, 0x30, 0x03, 0x00,
    };
    off += write_wasm_section(module_buf + off, 0x07,
                              export_body, sizeof(export_body));

    /* Start section: start function = 0 (the () -> () one) */
    static const uint8_t start_body[] = { 0x00 };
    off += write_wasm_section(module_buf + off, 0x08,
                              start_body, sizeof(start_body));

    /* Code section: 2 code entries
     * Func 0: () -> () : just end
     * Func 1: (i32) -> (i32) : local.get 0, end */
    static const uint8_t code_body[] = {
        0x02,                           /* 2 code entries */
        0x02, 0x00, 0x0B,              /* entry 0: size=2, 0 locals, end */
        0x04, 0x00, 0x20, 0x00, 0x0B, /* entry 1: size=4, 0 locals,
                                          local.get 0, end */
    };
    off += write_wasm_section(module_buf + off, 0x0A,
                              code_body, sizeof(code_body));

    ecall_iwasm_main(__g_harness_eid, module_buf, (uint32_t)off);
}

/*
 * Command workflow using a structurally valid WASM module.
 * Unlike harness_cmd_workflow which uses random data, this uses a valid
 * WASM module to reliably reach instantiation, WASI init, and execution
 * through the ecall_handle_command pipeline.
 *
 * Targets bottlenecks in:
 *   handle_cmd_set_wasi_args (12%), handle_cmd_instantiate_module (44%),
 *   handle_cmd_exec_app_main (23%), handle_cmd_exec_app_func (25%),
 *   wasm_runtime_init_wasi (2%), wasm_instantiate (16%)
 */
static void
harness_cmd_workflow_valid_wasm(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Step 1: Initialize runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 8);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        goto cleanup;

    /* Step 2: Set log level */
    {
        uint64_t log_args[1];
        log_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<int>(0, 5);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_SET_LOG_LEVEL,
                             (uint8_t *)log_args, sizeof(log_args));
    }

    /* Step 3: Load a structurally valid WASM module */
    {
        static const uint8_t valid_wasm[] = {
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00,
            0x05, 0x03, 0x01, 0x00, 0x01,
            0x07, 0x13, 0x02,
            0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
            0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B,
        };
        uint8_t *wasm_file = (uint8_t *)calloc(1, sizeof(valid_wasm));
        g_alloc_mgr.push_back(wasm_file);
        if (!wasm_file)
            goto cleanup;
        memcpy(wasm_file, valid_wasm, sizeof(valid_wasm));

        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)wasm_file;
        load_args[1] = (uint64_t)sizeof(valid_wasm);
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Step 4: Set WASI args (always, to target wasm_runtime_init_wasi) */
        {
            char *dir_str = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir_str);
            char *argv_str = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv_str);
            char **dir_list_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)dir_list_arr);
            char **argv_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)argv_arr);

            if (dir_str && argv_str && dir_list_arr && argv_arr) {
                memcpy(dir_str, ".", 2);
                memcpy(argv_str, "test", 5);
                dir_list_arr[0] = dir_str;
                argv_arr[0] = argv_str;

                uint64_t wasi_args[12];
                wasi_args[0] = (uint64_t)(uintptr_t)enclave_module;
                wasi_args[1] = (uint64_t)(uintptr_t)dir_list_arr;
                wasi_args[2] = 1;  /* dir_list_size */
                wasi_args[3] = 0;  /* env_list (NULL) */
                wasi_args[4] = 0;  /* env_list_size */
                wasi_args[5] = 0;  /* stdinfd */
                wasi_args[6] = 1;  /* stdoutfd */
                wasi_args[7] = 2;  /* stderrfd */
                wasi_args[8] = (uint64_t)(uintptr_t)argv_arr;
                wasi_args[9] = 1;  /* wasi_argc */
                wasi_args[10] = 0; /* addr_pool_list (NULL) */
                wasi_args[11] = 0; /* addr_pool_list_size */
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_SET_WASI_ARGS,
                                     (uint8_t *)wasi_args,
                                     sizeof(wasi_args));
            }
        }

        /* Step 5: Instantiate module */
        memset(error_buf, 0, sizeof(error_buf));
        {
            uint64_t inst_args[5];
            inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
            inst_args[1] = (uint64_t)(32 * 1024);
            inst_args[2] = (uint64_t)(32 * 1024);
            inst_args[3] = (uint64_t)(uintptr_t)error_buf;
            inst_args[4] = (uint64_t)sizeof(error_buf);
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_INSTANTIATE_MODULE,
                                 (uint8_t *)inst_args, sizeof(inst_args));

            void *module_inst = (void *)(uintptr_t)inst_args[0];
            if (module_inst) {
                /* Step 6: Execute main */
                {
                    char *main_arg = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)main_arg);
                    if (main_arg) {
                        memcpy(main_arg, "test", 5);
                        uint64_t exec_args[3];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = 1; /* app_argc */
                        exec_args[2] = (uint64_t)(uintptr_t)main_arg;
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_MAIN,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                }

                /* Step 7: Execute func "_start" */
                if (g_fdp->remaining_bytes() > 4) {
                    char *func_name = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)func_name);
                    if (func_name) {
                        memcpy(func_name, "_start", 7);
                        uint64_t exec_args[3];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = (uint64_t)(uintptr_t)func_name;
                        exec_args[2] = 0; /* app_argc */
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_FUNC,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                }

                /* Step 8: Get exception */
                {
                    char exc_buf[256];
                    memset(exc_buf, 0, sizeof(exc_buf));
                    uint64_t exc_args[3];
                    exc_args[0] = (uint64_t)(uintptr_t)module_inst;
                    exc_args[1] = (uint64_t)(uintptr_t)exc_buf;
                    exc_args[2] = (uint64_t)sizeof(exc_buf);
                    ecall_handle_command(__g_harness_eid,
                                         HARNESS_CMD_GET_EXCEPTION,
                                         (uint8_t *)exc_args,
                                         sizeof(exc_args));
                }

                /* Step 9: Deinstantiate */
                {
                    uint64_t deinst_args[1];
                    deinst_args[0] = (uint64_t)(uintptr_t)module_inst;
                    ecall_handle_command(__g_harness_eid,
                                         HARNESS_CMD_DEINSTANTIATE_MODULE,
                                         (uint8_t *)deinst_args,
                                         sizeof(deinst_args));
                }
            }

            /* Step 10: Unload module */
            {
                uint64_t unload_args[1];
                unload_args[0] = (uint64_t)(uintptr_t)enclave_module;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_UNLOAD_MODULE,
                                     (uint8_t *)unload_args,
                                     sizeof(unload_args));
            }
        }
    }

cleanup:
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * WASM module with data section + datacount section.
 * Exercises load_data_segment_section and load_datacount_section.
 * BULK_MEMORY is enabled, so both active and passive data segments are tested.
 *
 * Targets bottlenecks in:
 *   load_data_segment_section, load_datacount_section,
 *   data segment initialization during instantiation
 */
static void
harness_wasm_data_section(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: 1 memory, min=1 max=2 */
    static const uint8_t mem_body[] = { 0x01, 0x01, 0x01, 0x02 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export section: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: 1 code entry, just 'end' */
    static const uint8_t code_body[] = {
        0x01, 0x02, 0x00, 0x0B
    };
    off += write_wasm_section(mod + off, 0x0A, code_body, sizeof(code_body));

    /* Choose data segment configuration */
    int mode = g_fdp->ConsumeIntegralInRange<int>(0, 3);
    uint8_t data_buf[256];
    size_t db_off = 0;

    /* Datacount section (0x0C) - required before data section with bulk_memory */
    uint8_t dc_body[5];
    size_t dc_len = 0;

    switch (mode) {
        case 0: {
            /* Single active data segment: mode=0, i32.const offset, data */
            dc_len = write_u32_leb128(dc_body, 1);
            off += write_wasm_section(mod + off, 0x0C, dc_body, dc_len);

            size_t data_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
            data_buf[db_off++] = 0x01; /* 1 segment */
            data_buf[db_off++] = 0x00; /* active, implicit memidx 0 */
            data_buf[db_off++] = 0x41; /* i32.const */
            uint32_t seg_offset =
                g_fdp->ConsumeIntegralInRange<uint32_t>(0, 128);
            db_off += write_u32_leb128(data_buf + db_off, seg_offset);
            data_buf[db_off++] = 0x0B; /* end init_expr */
            db_off += write_u32_leb128(data_buf + db_off, (uint32_t)data_len);
            if (g_fdp->remaining_bytes() >= data_len)
                g_fdp->ConsumeData(data_buf + db_off, data_len);
            db_off += data_len;
            break;
        }
        case 1: {
            /* Single passive data segment: mode=1, data only */
            dc_len = write_u32_leb128(dc_body, 1);
            off += write_wasm_section(mod + off, 0x0C, dc_body, dc_len);

            size_t data_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
            data_buf[db_off++] = 0x01; /* 1 segment */
            data_buf[db_off++] = 0x01; /* passive */
            db_off += write_u32_leb128(data_buf + db_off, (uint32_t)data_len);
            if (g_fdp->remaining_bytes() >= data_len)
                g_fdp->ConsumeData(data_buf + db_off, data_len);
            db_off += data_len;
            break;
        }
        case 2: {
            /* Active with explicit memory index: mode=2, memidx, init_expr, data */
            dc_len = write_u32_leb128(dc_body, 1);
            off += write_wasm_section(mod + off, 0x0C, dc_body, dc_len);

            size_t data_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
            data_buf[db_off++] = 0x01; /* 1 segment */
            data_buf[db_off++] = 0x02; /* active with memidx */
            data_buf[db_off++] = 0x00; /* memory index 0 */
            data_buf[db_off++] = 0x41; /* i32.const */
            db_off += write_u32_leb128(data_buf + db_off, 0);
            data_buf[db_off++] = 0x0B; /* end init_expr */
            db_off += write_u32_leb128(data_buf + db_off, (uint32_t)data_len);
            if (g_fdp->remaining_bytes() >= data_len)
                g_fdp->ConsumeData(data_buf + db_off, data_len);
            db_off += data_len;
            break;
        }
        case 3: {
            /* Two segments: one active + one passive */
            dc_len = write_u32_leb128(dc_body, 2);
            off += write_wasm_section(mod + off, 0x0C, dc_body, dc_len);

            data_buf[db_off++] = 0x02; /* 2 segments */
            /* Segment 0: active */
            data_buf[db_off++] = 0x00;
            data_buf[db_off++] = 0x41;
            data_buf[db_off++] = 0x00;
            data_buf[db_off++] = 0x0B;
            data_buf[db_off++] = 0x04; /* 4 bytes */
            data_buf[db_off++] = 0xDE;
            data_buf[db_off++] = 0xAD;
            data_buf[db_off++] = 0xBE;
            data_buf[db_off++] = 0xEF;
            /* Segment 1: passive */
            data_buf[db_off++] = 0x01;
            data_buf[db_off++] = 0x02; /* 2 bytes */
            data_buf[db_off++] = 0xCA;
            data_buf[db_off++] = 0xFE;
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0B, data_buf, db_off);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with element section (table initialization).
 * Exercises load_table_segment_section with various element modes.
 * REF_TYPES is enabled, allowing modes 0-7.
 *
 * Targets bottlenecks in:
 *   load_table_segment_section, table initialization during instantiation
 */
static void
harness_wasm_elem_section(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 2 functions */
    static const uint8_t func_body[] = { 0x02, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Table section: 1 funcref table, min=4 */
    static const uint8_t table_body[] = { 0x01, 0x70, 0x00, 0x04 };
    off += write_wasm_section(mod + off, 0x04,
                              table_body, sizeof(table_body));

    /* Memory section: 1 memory, min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start(func 0) */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Element section with fuzzed mode */
    int elem_mode = g_fdp->ConsumeIntegralInRange<int>(0, 5);
    uint8_t elem_buf[128];
    size_t eb_off = 0;

    elem_buf[eb_off++] = 0x01; /* 1 element segment */
    switch (elem_mode) {
        case 0:
            /* Mode 0: active, implicit table 0, funcidx vector */
            elem_buf[eb_off++] = 0x00;
            elem_buf[eb_off++] = 0x41; /* i32.const */
            elem_buf[eb_off++] = 0x00; /* offset 0 */
            elem_buf[eb_off++] = 0x0B; /* end */
            elem_buf[eb_off++] = 0x02; /* 2 function indices */
            elem_buf[eb_off++] = 0x00; /* func 0 */
            elem_buf[eb_off++] = 0x01; /* func 1 */
            break;
        case 1:
            /* Mode 1: passive, elemkind=funcref, funcidx vector */
            elem_buf[eb_off++] = 0x01;
            elem_buf[eb_off++] = 0x00; /* elemkind = funcref */
            elem_buf[eb_off++] = 0x02; /* 2 indices */
            elem_buf[eb_off++] = 0x00;
            elem_buf[eb_off++] = 0x01;
            break;
        case 2:
            /* Mode 2: active with explicit table_idx, funcidx vector */
            elem_buf[eb_off++] = 0x02;
            elem_buf[eb_off++] = 0x00; /* table index 0 */
            elem_buf[eb_off++] = 0x41; /* i32.const */
            elem_buf[eb_off++] = 0x01; /* offset 1 */
            elem_buf[eb_off++] = 0x0B; /* end */
            elem_buf[eb_off++] = 0x00; /* elemkind = funcref */
            elem_buf[eb_off++] = 0x01; /* 1 index */
            elem_buf[eb_off++] = 0x00; /* func 0 */
            break;
        case 3:
            /* Mode 3: declarative, elemkind=funcref, funcidx vector */
            elem_buf[eb_off++] = 0x03;
            elem_buf[eb_off++] = 0x00; /* elemkind = funcref */
            elem_buf[eb_off++] = 0x01; /* 1 index */
            elem_buf[eb_off++] = 0x00; /* func 0 */
            break;
        case 4:
            /* Mode 4: active, expr vector (ref.func + end per entry) */
            elem_buf[eb_off++] = 0x04;
            elem_buf[eb_off++] = 0x41; /* i32.const */
            elem_buf[eb_off++] = 0x00; /* offset 0 */
            elem_buf[eb_off++] = 0x0B; /* end */
            elem_buf[eb_off++] = 0x01; /* 1 expression */
            elem_buf[eb_off++] = 0xD2; /* ref.func */
            elem_buf[eb_off++] = 0x00; /* func 0 */
            elem_buf[eb_off++] = 0x0B; /* end */
            break;
        case 5:
            /* Mode 5: passive, reftype=funcref, expr vector */
            elem_buf[eb_off++] = 0x05;
            elem_buf[eb_off++] = 0x70; /* reftype = funcref */
            elem_buf[eb_off++] = 0x01; /* 1 expression */
            elem_buf[eb_off++] = 0xD2; /* ref.func */
            elem_buf[eb_off++] = 0x00; /* func 0 */
            elem_buf[eb_off++] = 0x0B; /* end */
            break;
    }

    off += write_wasm_section(mod + off, 0x09, elem_buf, eb_off);

    /* Code section: 2 entries, both just 'end' */
    static const uint8_t code_body[] = {
        0x02,
        0x02, 0x00, 0x0B,
        0x02, 0x00, 0x0B,
    };
    off += write_wasm_section(mod + off, 0x0A, code_body, sizeof(code_body));

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with import section.
 * Exercises load_import_section for function, table, memory, global imports.
 * Even though resolution may fail (no multi-module), the parsing paths are tested.
 *
 * Targets bottlenecks in:
 *   load_import_section (function/table/memory/global import parsing),
 *   UTF-8 name validation
 */
static void
harness_wasm_import_section(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 2 types: () -> () and (i32) -> (i32) */
    static const uint8_t type_body[] = {
        0x02,
        0x60, 0x00, 0x00,
        0x60, 0x01, 0x7F, 0x01, 0x7F,
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Import section with fuzzed import kinds */
    int import_kind = g_fdp->ConsumeIntegralInRange<int>(0, 3);
    uint8_t imp_buf[128];
    size_t ib_off = 0;

    imp_buf[ib_off++] = 0x01; /* 1 import */
    /* module name: "env" */
    imp_buf[ib_off++] = 0x03;
    imp_buf[ib_off++] = 'e';
    imp_buf[ib_off++] = 'n';
    imp_buf[ib_off++] = 'v';

    switch (import_kind) {
        case 0:
            /* Import function: "fn" -> type 0 */
            imp_buf[ib_off++] = 0x02; /* field name len */
            imp_buf[ib_off++] = 'f';
            imp_buf[ib_off++] = 'n';
            imp_buf[ib_off++] = 0x00; /* kind = func */
            imp_buf[ib_off++] = 0x00; /* type index 0 */
            break;
        case 1:
            /* Import table: "tb" -> funcref, min=1 */
            imp_buf[ib_off++] = 0x02;
            imp_buf[ib_off++] = 't';
            imp_buf[ib_off++] = 'b';
            imp_buf[ib_off++] = 0x01; /* kind = table */
            imp_buf[ib_off++] = 0x70; /* funcref */
            imp_buf[ib_off++] = 0x00; /* limits: no max */
            imp_buf[ib_off++] = 0x01; /* min = 1 */
            break;
        case 2:
            /* Import memory: "mem" -> min=1, max=10 */
            imp_buf[ib_off++] = 0x03;
            imp_buf[ib_off++] = 'm';
            imp_buf[ib_off++] = 'e';
            imp_buf[ib_off++] = 'm';
            imp_buf[ib_off++] = 0x02; /* kind = memory */
            imp_buf[ib_off++] = 0x01; /* limits: has max */
            imp_buf[ib_off++] = 0x01; /* min = 1 */
            imp_buf[ib_off++] = 0x0A; /* max = 10 */
            break;
        case 3:
            /* Import global: "g0" -> i32, immutable */
            imp_buf[ib_off++] = 0x02;
            imp_buf[ib_off++] = 'g';
            imp_buf[ib_off++] = '0';
            imp_buf[ib_off++] = 0x03; /* kind = global */
            imp_buf[ib_off++] = 0x7F; /* i32 */
            imp_buf[ib_off++] = 0x00; /* immutable */
            break;
    }
    off += write_wasm_section(mod + off, 0x02, imp_buf, ib_off);

    /* Function section: 1 function */
    static const uint8_t func_sec[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_sec, sizeof(func_sec));

    /* Memory section (only if we didn't import memory) */
    if (import_kind != 2) {
        static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
        off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));
    }

    /* Export section: _start */
    uint8_t export_buf[32];
    size_t ex_off = 0;
    export_buf[ex_off++] = 0x01; /* 1 export */
    export_buf[ex_off++] = 0x06; /* name len */
    memcpy(export_buf + ex_off, "_start", 6);
    ex_off += 6;
    export_buf[ex_off++] = 0x00; /* kind = func */
    /* func index: import_kind==0 means func 0 is imported, our func is 1 */
    export_buf[ex_off++] = (import_kind == 0) ? 0x01 : 0x00;
    off += write_wasm_section(mod + off, 0x07, export_buf, ex_off);

    /* Code section: 1 entry, just 'end' */
    static const uint8_t code_body[] = { 0x01, 0x02, 0x00, 0x0B };
    off += write_wasm_section(mod + off, 0x0A, code_body, sizeof(code_body));

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with custom/name section.
 * Exercises load_user_section and name section parsing.
 *
 * Targets bottlenecks in:
 *   load_user_section, UTF-8 validation,
 *   name section subsection handling
 */
static void
harness_wasm_custom_section(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Custom section BEFORE type section: "name" section or generic custom */
    int custom_type = g_fdp->ConsumeIntegralInRange<int>(0, 2);
    uint8_t custom_buf[256];
    size_t cb_off = 0;

    if (custom_type == 0) {
        /* "name" section with module name subsection */
        cb_off = 0;
        custom_buf[cb_off++] = 0x04; /* name len */
        custom_buf[cb_off++] = 'n';
        custom_buf[cb_off++] = 'a';
        custom_buf[cb_off++] = 'm';
        custom_buf[cb_off++] = 'e';
        /* Subsection 0: module name */
        custom_buf[cb_off++] = 0x00; /* subsection id */
        custom_buf[cb_off++] = 0x06; /* subsection size */
        custom_buf[cb_off++] = 0x05; /* name len */
        custom_buf[cb_off++] = 't';
        custom_buf[cb_off++] = 'e';
        custom_buf[cb_off++] = 's';
        custom_buf[cb_off++] = 't';
        custom_buf[cb_off++] = 'm';
    }
    else if (custom_type == 1) {
        /* "name" section with function name subsection */
        cb_off = 0;
        custom_buf[cb_off++] = 0x04; /* name len */
        custom_buf[cb_off++] = 'n';
        custom_buf[cb_off++] = 'a';
        custom_buf[cb_off++] = 'm';
        custom_buf[cb_off++] = 'e';
        /* Subsection 1: function names */
        custom_buf[cb_off++] = 0x01; /* subsection id */
        custom_buf[cb_off++] = 0x06; /* subsection size */
        custom_buf[cb_off++] = 0x01; /* name map count */
        custom_buf[cb_off++] = 0x00; /* func index */
        custom_buf[cb_off++] = 0x03; /* name len */
        custom_buf[cb_off++] = 'f';
        custom_buf[cb_off++] = 'o';
        custom_buf[cb_off++] = 'o';
    }
    else {
        /* Generic custom section with fuzzed name */
        size_t name_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
        cb_off = 0;
        cb_off += write_u32_leb128(custom_buf + cb_off, (uint32_t)name_len);
        if (g_fdp->remaining_bytes() >= name_len)
            g_fdp->ConsumeData(custom_buf + cb_off, name_len);
        cb_off += name_len;
        /* Some custom data */
        size_t data_len = g_fdp->ConsumeIntegralInRange<size_t>(0, 32);
        if (g_fdp->remaining_bytes() >= data_len)
            g_fdp->ConsumeData(custom_buf + cb_off, data_len);
        cb_off += data_len;
    }

    /* Type section */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export section */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section */
    static const uint8_t code_body[] = { 0x01, 0x02, 0x00, 0x0B };
    off += write_wasm_section(mod + off, 0x0A, code_body, sizeof(code_body));

    /* Custom section AFTER code section (allowed position) */
    off += write_wasm_section(mod + off, 0x00, custom_buf, cb_off);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with multiple function types, locals, and diverse opcodes.
 * Generates structurally valid function bodies with various instruction types
 * to exercise the bytecode validator and interpreter more thoroughly.
 *
 * Targets bottlenecks in:
 *   wasm_loader_prepare_bytecode, wasm_interp_call_func_bytecode,
 *   load_function_section, load_code_section, local variable handling
 */
static void
harness_wasm_multi_func(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 8192);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 4 types */
    static const uint8_t type_body[] = {
        0x04,
        0x60, 0x00, 0x00,                         /* type 0: () -> () */
        0x60, 0x01, 0x7F, 0x01, 0x7F,             /* type 1: (i32) -> (i32) */
        0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,       /* type 2: (i32,i32) -> (i32) */
        0x60, 0x00, 0x01, 0x7E,                    /* type 3: () -> (i64) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 4 functions */
    static const uint8_t func_body[] = { 0x04, 0x00, 0x01, 0x02, 0x03 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Global section: 2 globals (i32 mutable, i64 mutable) */
    static const uint8_t global_body[] = {
        0x02,
        0x7F, 0x01, 0x41, 0x2A, 0x0B, /* i32, mut, i32.const 42, end */
        0x7E, 0x01, 0x42, 0x00, 0x0B, /* i64, mut, i64.const 0, end */
    };
    off += write_wasm_section(mod + off, 0x06,
                              global_body, sizeof(global_body));

    /* Export section: memory + _start(func 0) + add(func 2) */
    static const uint8_t export_body[] = {
        0x03,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
        0x03, 0x61, 0x64, 0x64, 0x00, 0x02,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: 4 function bodies */
    uint8_t code_buf[512];
    size_t cc_off = 0;
    code_buf[cc_off++] = 0x04; /* 4 code entries */

    /* Func 0: () -> () - calls func 1, stores to global */
    {
        static const uint8_t body[] = {
            0x00,       /* 0 local groups */
            0x41, 0x07, /* i32.const 7 */
            0x10, 0x01, /* call func 1 */
            0x24, 0x00, /* global.set 0 */
            0x0B,       /* end */
        };
        cc_off += write_u32_leb128(code_buf + cc_off, (uint32_t)sizeof(body));
        memcpy(code_buf + cc_off, body, sizeof(body));
        cc_off += sizeof(body);
    }

    /* Func 1: (i32) -> (i32) - has locals, arithmetic, control flow */
    {
        static const uint8_t body[] = {
            0x01, 0x01, 0x7F, /* 1 local group: 1 x i32 */
            0x20, 0x00,       /* local.get 0 */
            0x21, 0x01,       /* local.set 1 */
            0x20, 0x01,       /* local.get 1 */
            0x41, 0x01,       /* i32.const 1 */
            0x6A,             /* i32.add */
            0x41, 0x0A,       /* i32.const 10 */
            0x48,             /* i32.lt_s */
            0x04, 0x7F,       /* if (result i32) */
            0x20, 0x01,       /* local.get 1 */
            0x41, 0x02,       /* i32.const 2 */
            0x6C,             /* i32.mul */
            0x05,             /* else */
            0x20, 0x01,       /* local.get 1 */
            0x0B,             /* end if */
            0x0B,             /* end */
        };
        cc_off += write_u32_leb128(code_buf + cc_off, (uint32_t)sizeof(body));
        memcpy(code_buf + cc_off, body, sizeof(body));
        cc_off += sizeof(body);
    }

    /* Func 2: (i32, i32) -> (i32) - simple add */
    {
        static const uint8_t body[] = {
            0x00,
            0x20, 0x00,
            0x20, 0x01,
            0x6A,
            0x0B,
        };
        cc_off += write_u32_leb128(code_buf + cc_off, (uint32_t)sizeof(body));
        memcpy(code_buf + cc_off, body, sizeof(body));
        cc_off += sizeof(body);
    }

    /* Func 3: () -> (i64) - memory load, global get */
    {
        static const uint8_t body[] = {
            0x01, 0x01, 0x7E, /* 1 local group: 1 x i64 */
            0x23, 0x01,       /* global.get 1 */
            0x42, 0x01,       /* i64.const 1 */
            0x7C,             /* i64.add */
            0x22, 0x00,       /* local.tee 0 */
            0x24, 0x01,       /* global.set 1 (but we need i64 on stack) */
            0x20, 0x00,       /* local.get 0 */
            0x0B,             /* end */
        };
        cc_off += write_u32_leb128(code_buf + cc_off, (uint32_t)sizeof(body));
        memcpy(code_buf + cc_off, body, sizeof(body));
        cc_off += sizeof(body);
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc_off);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Command workflow with full WASI args (env_list, addr_pool_list).
 * Exercises deeper WASI initialization paths including environment variables,
 * address pool setup, and multiple directory pre-opens.
 *
 * Targets bottlenecks in:
 *   wasm_runtime_init_wasi, wasm_runtime_set_wasi_args_ex,
 *   directory pre-opening, environment setup, address pool init
 */
static void
harness_cmd_workflow_wasi_full(void)
{
    if (g_fdp->remaining_bytes() < 32)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Step 1: Init runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        goto cleanup;

    /* Step 2: Load valid WASM module */
    {
        static const uint8_t valid_wasm[] = {
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00,
            0x05, 0x03, 0x01, 0x00, 0x01,
            0x07, 0x13, 0x02,
            0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
            0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B,
        };
        uint8_t *wasm_file = (uint8_t *)calloc(1, sizeof(valid_wasm));
        g_alloc_mgr.push_back(wasm_file);
        if (!wasm_file)
            goto cleanup;
        memcpy(wasm_file, valid_wasm, sizeof(valid_wasm));

        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)wasm_file;
        load_args[1] = (uint64_t)sizeof(valid_wasm);
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Step 3: Set WASI args with env and addr pool */
        {
            /* Directories */
            char *dir1 = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir1);
            char *dir2 = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir2);
            char **dir_arr = (char **)calloc(2, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)dir_arr);

            /* Argv */
            char *argv0 = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv0);
            char *argv1 = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv1);
            char **argv_arr = (char **)calloc(2, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)argv_arr);

            /* Environment variables */
            char *env0 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)env0);
            char *env1 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)env1);
            char **env_arr = (char **)calloc(2, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)env_arr);

            /* Address pool */
            char *addr0 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)addr0);
            char **addr_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)addr_arr);

            if (dir1 && dir2 && dir_arr && argv0 && argv1 && argv_arr
                && env0 && env1 && env_arr && addr0 && addr_arr) {
                memcpy(dir1, ".", 2);
                memcpy(dir2, "/tmp", 5);
                dir_arr[0] = dir1;
                dir_arr[1] = dir2;

                memcpy(argv0, "test", 5);
                memcpy(argv1, "--help", 7);
                argv_arr[0] = argv0;
                argv_arr[1] = argv1;

                memcpy(env0, "HOME=/tmp", 10);
                memcpy(env1, "PATH=/bin", 10);
                env_arr[0] = env0;
                env_arr[1] = env1;

                memcpy(addr0, "127.0.0.1", 10);
                addr_arr[0] = addr0;

                uint64_t wasi_args[12];
                wasi_args[0] = (uint64_t)(uintptr_t)enclave_module;
                wasi_args[1] = (uint64_t)(uintptr_t)dir_arr;
                wasi_args[2] = 2;  /* dir_list_size */
                wasi_args[3] = (uint64_t)(uintptr_t)env_arr;
                wasi_args[4] = 2;  /* env_list_size */
                wasi_args[5] = g_fdp->ConsumeIntegralInRange<int>(0, 2);
                wasi_args[6] = 1;
                wasi_args[7] = 2;
                wasi_args[8] = (uint64_t)(uintptr_t)argv_arr;
                wasi_args[9] = 2;  /* wasi_argc */
                wasi_args[10] = (uint64_t)(uintptr_t)addr_arr;
                wasi_args[11] = 1; /* addr_pool_list_size */
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_SET_WASI_ARGS,
                                     (uint8_t *)wasi_args,
                                     sizeof(wasi_args));
            }
        }

        /* Step 4: Instantiate */
        memset(error_buf, 0, sizeof(error_buf));
        {
            uint64_t inst_args[5];
            inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
            inst_args[1] = (uint64_t)(32 * 1024);
            inst_args[2] = (uint64_t)(32 * 1024);
            inst_args[3] = (uint64_t)(uintptr_t)error_buf;
            inst_args[4] = (uint64_t)sizeof(error_buf);
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_INSTANTIATE_MODULE,
                                 (uint8_t *)inst_args, sizeof(inst_args));

            void *module_inst = (void *)(uintptr_t)inst_args[0];
            if (module_inst) {
                /* Execute main */
                char *main_arg = (char *)calloc(1, 16);
                g_alloc_mgr.push_back((uint8_t *)main_arg);
                if (main_arg) {
                    memcpy(main_arg, "test", 5);
                    uint64_t exec_args[3];
                    exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                    exec_args[1] = 1;
                    exec_args[2] = (uint64_t)(uintptr_t)main_arg;
                    ecall_handle_command(__g_harness_eid,
                                         HARNESS_CMD_EXEC_APP_MAIN,
                                         (uint8_t *)exec_args,
                                         sizeof(exec_args));
                }

                /* Deinstantiate */
                uint64_t deinst_args[1];
                deinst_args[0] = (uint64_t)(uintptr_t)module_inst;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_DEINSTANTIATE_MODULE,
                                     (uint8_t *)deinst_args,
                                     sizeof(deinst_args));
            }

            /* Unload */
            uint64_t unload_args[1];
            unload_args[0] = (uint64_t)(uintptr_t)enclave_module;
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_UNLOAD_MODULE,
                                 (uint8_t *)unload_args,
                                 sizeof(unload_args));
        }
    }

cleanup:
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * WASM module with comprehensive sections through the command pipeline.
 * Uses ecall_handle_command to load a module with data+elem+import sections,
 * allowing these sections to be tested through the command-based path as well.
 */
static void
harness_cmd_comprehensive_wasm(void)
{
    if (g_fdp->remaining_bytes() < 32)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Init runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        goto cleanup;

    /* Build a comprehensive WASM module */
    {
        uint8_t *mod = (uint8_t *)calloc(1, 8192);
        g_alloc_mgr.push_back(mod);
        if (!mod)
            goto cleanup;

        size_t moff = 0;
        memcpy(mod, wasm_magic_hdr, 8);
        moff = 8;

        /* Type section: 2 types */
        static const uint8_t type_body[] = {
            0x02,
            0x60, 0x00, 0x00,
            0x60, 0x01, 0x7F, 0x01, 0x7F,
        };
        moff += write_wasm_section(mod + moff, 0x01,
                                   type_body, sizeof(type_body));

        /* Function section: 2 functions */
        static const uint8_t func_body[] = { 0x02, 0x00, 0x01 };
        moff += write_wasm_section(mod + moff, 0x03,
                                   func_body, sizeof(func_body));

        /* Table section: funcref, min=2 */
        static const uint8_t table_body[] = { 0x01, 0x70, 0x00, 0x02 };
        moff += write_wasm_section(mod + moff, 0x04,
                                   table_body, sizeof(table_body));

        /* Memory section: min=1 max=4 */
        static const uint8_t mem_body[] = { 0x01, 0x01, 0x01, 0x04 };
        moff += write_wasm_section(mod + moff, 0x05,
                                   mem_body, sizeof(mem_body));

        /* Global section: 1 mutable i32 */
        static const uint8_t global_body[] = {
            0x01, 0x7F, 0x01, 0x41, 0x00, 0x0B
        };
        moff += write_wasm_section(mod + moff, 0x06,
                                   global_body, sizeof(global_body));

        /* Export section: memory + _start */
        static const uint8_t export_body[] = {
            0x02,
            0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
            0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
        };
        moff += write_wasm_section(mod + moff, 0x07,
                                   export_body, sizeof(export_body));

        /* Element section: 1 active segment, func 0 at offset 0 */
        static const uint8_t elem_body[] = {
            0x01,
            0x00,       /* active, table 0 */
            0x41, 0x00, /* i32.const 0 */
            0x0B,       /* end */
            0x01,       /* 1 func index */
            0x00,       /* func 0 */
        };
        moff += write_wasm_section(mod + moff, 0x09,
                                   elem_body, sizeof(elem_body));

        /* Code section: 2 entries */
        static const uint8_t code_body[] = {
            0x02,
            0x02, 0x00, 0x0B,              /* func 0: end */
            0x04, 0x00, 0x20, 0x00, 0x0B,  /* func 1: local.get 0, end */
        };
        moff += write_wasm_section(mod + moff, 0x0A,
                                   code_body, sizeof(code_body));

        /* Datacount section: 1 */
        static const uint8_t dc_body[] = { 0x01 };
        moff += write_wasm_section(mod + moff, 0x0C,
                                   dc_body, sizeof(dc_body));

        /* Data section: 1 active segment */
        static const uint8_t data_body[] = {
            0x01,
            0x00,                   /* active, memidx 0 */
            0x41, 0x00, 0x0B,       /* i32.const 0, end */
            0x04,                   /* 4 bytes */
            0x48, 0x65, 0x6C, 0x6C, /* "Hell" */
        };
        moff += write_wasm_section(mod + moff, 0x0B,
                                   data_body, sizeof(data_body));

        /* Load via command pipeline */
        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)mod;
        load_args[1] = (uint64_t)moff;
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Instantiate */
        memset(error_buf, 0, sizeof(error_buf));
        uint64_t inst_args[5];
        inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
        inst_args[1] = (uint64_t)(32 * 1024);
        inst_args[2] = (uint64_t)(32 * 1024);
        inst_args[3] = (uint64_t)(uintptr_t)error_buf;
        inst_args[4] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid,
                             HARNESS_CMD_INSTANTIATE_MODULE,
                             (uint8_t *)inst_args, sizeof(inst_args));

        void *module_inst = (void *)(uintptr_t)inst_args[0];
        if (module_inst) {
            /* Execute */
            char *main_arg = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)main_arg);
            if (main_arg) {
                memcpy(main_arg, "test", 5);
                uint64_t exec_args[3];
                exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                exec_args[1] = 1;
                exec_args[2] = (uint64_t)(uintptr_t)main_arg;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_EXEC_APP_MAIN,
                                     (uint8_t *)exec_args,
                                     sizeof(exec_args));
            }

            uint64_t deinst_args[1];
            deinst_args[0] = (uint64_t)(uintptr_t)module_inst;
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_DEINSTANTIATE_MODULE,
                                 (uint8_t *)deinst_args,
                                 sizeof(deinst_args));
        }

        uint64_t unload_args[1];
        unload_args[0] = (uint64_t)(uintptr_t)enclave_module;
        ecall_handle_command(__g_harness_eid,
                             HARNESS_CMD_UNLOAD_MODULE,
                             (uint8_t *)unload_args,
                             sizeof(unload_args));
    }

cleanup:
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * WASM module with diverse opcodes targeting the interpreter dispatch loop.
 * Generates a valid module with control flow (block/loop/br_if), memory
 * load/store, numeric operations (add/sub/mul/and/or/xor/shl/shr/rotl/rotr),
 * comparisons, and conversions.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (2% coverage! - the main interpreter loop),
 *   wasm_loader_prepare_bytecode, check_block_stack
 */
static void
harness_wasm_diverse_opcodes(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: 1 memory, min=1 max=2 */
    static const uint8_t mem_body[] = { 0x01, 0x01, 0x01, 0x02 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: 1 function with diverse opcodes */
    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 5);
    uint8_t func_code[256];
    size_t fc_off = 0;

    switch (variant) {
        case 0: {
            /* Block + br_if + memory store/load */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,       /* 1 local: i32 */
                0x41, 0x00,             /* i32.const 0 */
                0x41, 0x2A,             /* i32.const 42 */
                0x36, 0x02, 0x00,       /* i32.store align=2 offset=0 */
                0x41, 0x00,             /* i32.const 0 */
                0x28, 0x02, 0x00,       /* i32.load align=2 offset=0 */
                0x21, 0x00,             /* local.set 0 */
                0x02, 0x40,             /* block (void) */
                0x20, 0x00,             /* local.get 0 */
                0x41, 0x2A,             /* i32.const 42 */
                0x46,                   /* i32.eq */
                0x0D, 0x00,             /* br_if 0 (exit block) */
                0x00,                   /* unreachable */
                0x0B,                   /* end block */
                0x0B,                   /* end func */
            };
            memcpy(func_code, body, sizeof(body));
            fc_off = sizeof(body);
            break;
        }
        case 1: {
            /* Loop + counter + br_if */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,       /* 1 local: i32 */
                0x41, 0x0A,             /* i32.const 10 */
                0x21, 0x00,             /* local.set 0 (counter=10) */
                0x03, 0x40,             /* loop (void) */
                0x20, 0x00,             /* local.get 0 */
                0x41, 0x01,             /* i32.const 1 */
                0x6B,                   /* i32.sub */
                0x22, 0x00,             /* local.tee 0 */
                0x0D, 0x00,             /* br_if 0 (continue loop if != 0) */
                0x0B,                   /* end loop */
                0x0B,                   /* end func */
            };
            memcpy(func_code, body, sizeof(body));
            fc_off = sizeof(body);
            break;
        }
        case 2: {
            /* Arithmetic: add, sub, mul, and, or, xor, shl, shr_u, rotl */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,       /* 1 local: i32 */
                0x41, 0x07,             /* i32.const 7 */
                0x41, 0x03,             /* i32.const 3 */
                0x6A,                   /* i32.add */
                0x41, 0x02,             /* i32.const 2 */
                0x6C,                   /* i32.mul */
                0x41, 0x05,             /* i32.const 5 */
                0x6B,                   /* i32.sub */
                0x41, 0xFF, 0x00,       /* i32.const 127 */
                0x71,                   /* i32.and */
                0x41, 0x0F,             /* i32.const 15 */
                0x72,                   /* i32.or */
                0x41, 0x03,             /* i32.const 3 */
                0x73,                   /* i32.xor */
                0x41, 0x02,             /* i32.const 2 */
                0x74,                   /* i32.shl */
                0x41, 0x01,             /* i32.const 1 */
                0x76,                   /* i32.shr_u */
                0x41, 0x04,             /* i32.const 4 */
                0x77,                   /* i32.rotl */
                0x1A,                   /* drop */
                0x0B,                   /* end func */
            };
            memcpy(func_code, body, sizeof(body));
            fc_off = sizeof(body);
            break;
        }
        case 3: {
            /* If/else with nested blocks */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,       /* 1 local: i32 */
                0x41, 0x01,             /* i32.const 1 */
                0x04, 0x40,             /* if (void) */
                0x41, 0x04,             /* i32.const 4 */
                0x41, 0x08,             /* i32.const 8 */
                0x36, 0x02, 0x00,       /* i32.store offset=0 */
                0x05,                   /* else */
                0x41, 0x04,             /* i32.const 4 */
                0x41, 0x00,             /* i32.const 0 */
                0x36, 0x02, 0x00,       /* i32.store offset=0 */
                0x0B,                   /* end if */
                0x41, 0x00,             /* i32.const 0 */
                0x04, 0x40,             /* if (void) - false branch */
                0x00,                   /* unreachable (never reached) */
                0x05,                   /* else */
                0x01,                   /* nop */
                0x0B,                   /* end if */
                0x0B,                   /* end func */
            };
            memcpy(func_code, body, sizeof(body));
            fc_off = sizeof(body);
            break;
        }
        case 4: {
            /* Memory size + grow + load various widths */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,       /* 1 local: i32 */
                0x3F, 0x00,             /* memory.size */
                0x1A,                   /* drop */
                0x41, 0x01,             /* i32.const 1 */
                0x40, 0x00,             /* memory.grow */
                0x1A,                   /* drop */
                0x41, 0x00,             /* i32.const 0 */
                0x41, 0xAA, 0x01,       /* i32.const 170 */
                0x3A, 0x00, 0x00,       /* i32.store8 offset=0 */
                0x41, 0x00,             /* i32.const 0 */
                0x2D, 0x00, 0x00,       /* i32.load8_u offset=0 */
                0x1A,                   /* drop */
                0x41, 0x00,             /* i32.const 0 */
                0x2C, 0x00, 0x00,       /* i32.load8_s offset=0 */
                0x1A,                   /* drop */
                0x41, 0x00,             /* i32.const 0 */
                0x2F, 0x01, 0x00,       /* i32.load16_u offset=0 */
                0x1A,                   /* drop */
                0x0B,                   /* end func */
            };
            memcpy(func_code, body, sizeof(body));
            fc_off = sizeof(body);
            break;
        }
        case 5: {
            /* i64 operations + conversions */
            static const uint8_t body[] = {
                0x02, 0x01, 0x7F, 0x01, 0x7E, /* 2 locals: 1xi32, 1xi64 */
                0x42, 0x80, 0x80, 0x04, /* i64.const 65536 */
                0x42, 0x02,             /* i64.const 2 */
                0x7E,                   /* i64.mul */
                0x42, 0x01,             /* i64.const 1 */
                0x7C,                   /* i64.add */
                0x22, 0x01,             /* local.tee 1 */
                0xA7,                   /* i32.wrap_i64 */
                0x21, 0x00,             /* local.set 0 */
                0x20, 0x00,             /* local.get 0 */
                0xAC,                   /* i64.extend_i32_s */
                0x20, 0x01,             /* local.get 1 */
                0x51,                   /* i64.eq */
                0x1A,                   /* drop */
                0x0B,                   /* end func */
            };
            memcpy(func_code, body, sizeof(body));
            fc_off = sizeof(body);
            break;
        }
    }

    /* Wrap in code section */
    uint8_t code_sec[300];
    size_t cs_off = 0;
    code_sec[cs_off++] = 0x01; /* 1 code entry */
    cs_off += write_u32_leb128(code_sec + cs_off, (uint32_t)fc_off);
    memcpy(code_sec + cs_off, func_code, fc_off);
    cs_off += fc_off;

    off += write_wasm_section(mod + off, 0x0A, code_sec, cs_off);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with call_indirect to exercise table-based dispatch.
 * Creates a table with function references and uses call_indirect to invoke
 * them, exercising the indirect call paths in the interpreter.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (call_indirect handler),
 *   tables_instantiate, load_table_segment_section
 */
static void
harness_wasm_call_indirect(void)
{
    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 2 types: () -> () and (i32) -> (i32) */
    static const uint8_t type_body[] = {
        0x02,
        0x60, 0x00, 0x00,                  /* type 0: () -> () */
        0x60, 0x01, 0x7F, 0x01, 0x7F,      /* type 1: (i32) -> (i32) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 4 functions */
    static const uint8_t func_body[] = { 0x04, 0x00, 0x01, 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Table section: 1 funcref table, min=4 max=4 */
    static const uint8_t table_body[] = { 0x01, 0x70, 0x01, 0x04, 0x04 };
    off += write_wasm_section(mod + off, 0x04, table_body, sizeof(table_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start(func 0) */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Element section: initialize table with funcs 1, 2, 1, 3 */
    static const uint8_t elem_body[] = {
        0x01,                       /* 1 segment */
        0x00,                       /* active, table 0 */
        0x41, 0x00,                 /* i32.const 0 */
        0x0B,                       /* end */
        0x04,                       /* 4 indices */
        0x01, 0x02, 0x01, 0x03,    /* func 1, 2, 1, 3 */
    };
    off += write_wasm_section(mod + off, 0x09,
                              elem_body, sizeof(elem_body));

    /* Code section: 4 entries */
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x04; /* 4 entries */

    /* Func 0: _start - calls funcs via call_indirect */
    {
        static const uint8_t body[] = {
            0x01, 0x01, 0x7F,       /* 1 local: i32 */
            0x41, 0x05,             /* i32.const 5 (arg) */
            0x41, 0x00,             /* i32.const 0 (table idx -> func 1) */
            0x11, 0x01, 0x00,       /* call_indirect type=1 table=0 */
            0x21, 0x00,             /* local.set 0 */
            0x20, 0x00,             /* local.get 0 */
            0x41, 0x01,             /* i32.const 1 (table idx -> func 2) */
            0x11, 0x01, 0x00,       /* call_indirect type=1 table=0 */
            0x1A,                   /* drop */
            0x0B,                   /* end */
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    /* Func 1: (i32) -> (i32) - doubles input */
    {
        static const uint8_t body[] = {
            0x00,
            0x20, 0x00,             /* local.get 0 */
            0x41, 0x02,             /* i32.const 2 */
            0x6C,                   /* i32.mul */
            0x0B,
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    /* Func 2: (i32) -> (i32) - increments */
    {
        static const uint8_t body[] = {
            0x00,
            0x20, 0x00,
            0x41, 0x01,
            0x6A,                   /* i32.add */
            0x0B,
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    /* Func 3: () -> () - nop */
    {
        static const uint8_t body[] = { 0x00, 0x0B };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with br_table instruction for multi-way branching.
 * Exercises the br_table opcode handler in the interpreter and the
 * wasm_loader_check_br / wasm_loader_emit_br_info validation paths.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (br_table handler),
 *   wasm_loader_check_br (40%), wasm_loader_emit_br_info (40%)
 */
static void
harness_wasm_br_table(void)
{
    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_sec[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_sec, sizeof(func_sec));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: br_table with 3 targets + default */
    /* The function stores different values to memory[0] based on
     * which br_table target is taken. */
    static const uint8_t code_body[] = {
        0x01,                           /* 1 code entry */
        0x2D,                           /* body size = 45 */
        0x01, 0x01, 0x7F,              /* 1 local: i32 */
        0x41, 0x02,                     /* i32.const 2 (selector) */
        0x21, 0x00,                     /* local.set 0 */
        0x02, 0x40,                     /* block $B0 (void) */
        0x02, 0x40,                     /* block $B1 (void) */
        0x02, 0x40,                     /* block $B2 (void) */
        0x02, 0x40,                     /* block $B3 (void) */
        0x20, 0x00,                     /* local.get 0 */
        0x0E, 0x03,                     /* br_table: 3 targets */
        0x00, 0x01, 0x02,              /* targets: B3, B2, B1 */
        0x03,                           /* default: B0 */
        0x0B,                           /* end B3 */
        0x41, 0x00, 0x41, 0x01,
        0x36, 0x02, 0x00,              /* store 1 at mem[0] */
        0x0C, 0x02,                     /* br B0 */
        0x0B,                           /* end B2 */
        0x41, 0x00, 0x41, 0x02,
        0x36, 0x02, 0x00,              /* store 2 at mem[0] */
        0x0C, 0x01,                     /* br B0 */
        0x0B,                           /* end B1 */
        0x41, 0x00, 0x41, 0x03,
        0x36, 0x02, 0x00,              /* store 3 at mem[0] */
        0x0B,                           /* end B0 */
        0x0B,                           /* end func */
    };
    off += write_wasm_section(mod + off, 0x0A,
                              code_body, sizeof(code_body));

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Command workflow using a WASM module with diverse opcodes.
 * Same diverse opcode module but via ecall_handle_command pipeline,
 * ensuring the interpreter is exercised through both entry paths.
 * Also exercises execute_func with the correct export name "add".
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (2%), execute_func (6%),
 *   handle_cmd_exec_app_func (33%), wasm_application_execute_func (66%)
 */
static void
harness_cmd_workflow_diverse_exec(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Init runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        goto cleanup;

    /* Load a module with exported "add" function: (i32,i32)->(i32) */
    {
        static const uint8_t wasm_mod[] = {
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            /* Type: 2 types */
            0x01, 0x09, 0x02,
            0x60, 0x00, 0x00,                           /* () -> () */
            0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,         /* (i32,i32) -> (i32) */
            /* Function: 2 funcs */
            0x03, 0x03, 0x02, 0x00, 0x01,
            /* Memory: min=1 */
            0x05, 0x03, 0x01, 0x00, 0x01,
            /* Export: memory, _start(func0), add(func1) */
            0x07, 0x17, 0x03,
            0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
            0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            0x03, 0x61, 0x64, 0x64, 0x00, 0x01,
            /* Code: 2 entries */
            0x0A, 0x0E, 0x02,
            0x02, 0x00, 0x0B,                          /* func0: end */
            0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
                                                       /* func1: get0+get1+add+end */
        };
        uint8_t *wf = (uint8_t *)calloc(1, sizeof(wasm_mod));
        g_alloc_mgr.push_back(wf);
        if (!wf)
            goto cleanup;
        memcpy(wf, wasm_mod, sizeof(wasm_mod));

        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)wf;
        load_args[1] = (uint64_t)sizeof(wasm_mod);
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Set WASI args */
        {
            char *dir_str = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir_str);
            char *argv_str = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv_str);
            char **dir_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)dir_arr);
            char **argv_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)argv_arr);
            if (dir_str && argv_str && dir_arr && argv_arr) {
                memcpy(dir_str, ".", 2);
                memcpy(argv_str, "test", 5);
                dir_arr[0] = dir_str;
                argv_arr[0] = argv_str;
                uint64_t wasi_args[12];
                wasi_args[0] = (uint64_t)(uintptr_t)enclave_module;
                wasi_args[1] = (uint64_t)(uintptr_t)dir_arr;
                wasi_args[2] = 1;
                wasi_args[3] = 0;
                wasi_args[4] = 0;
                wasi_args[5] = 0;
                wasi_args[6] = 1;
                wasi_args[7] = 2;
                wasi_args[8] = (uint64_t)(uintptr_t)argv_arr;
                wasi_args[9] = 1;
                wasi_args[10] = 0;
                wasi_args[11] = 0;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_SET_WASI_ARGS,
                                     (uint8_t *)wasi_args,
                                     sizeof(wasi_args));
            }
        }

        /* Instantiate */
        memset(error_buf, 0, sizeof(error_buf));
        {
            uint64_t inst_args[5];
            inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
            inst_args[1] = (uint64_t)(32 * 1024);
            inst_args[2] = (uint64_t)(32 * 1024);
            inst_args[3] = (uint64_t)(uintptr_t)error_buf;
            inst_args[4] = (uint64_t)sizeof(error_buf);
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_INSTANTIATE_MODULE,
                                 (uint8_t *)inst_args, sizeof(inst_args));

            void *module_inst = (void *)(uintptr_t)inst_args[0];
            if (module_inst) {
                /* Execute main first */
                {
                    char *arg = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)arg);
                    if (arg) {
                        memcpy(arg, "test", 5);
                        uint64_t exec_args[3];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = 1;
                        exec_args[2] = (uint64_t)(uintptr_t)arg;
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_MAIN,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                }

                /* Execute "add" function with args "3" and "4" */
                {
                    char *fn = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)fn);
                    char *a1 = (char *)calloc(1, 8);
                    g_alloc_mgr.push_back((uint8_t *)a1);
                    char *a2 = (char *)calloc(1, 8);
                    g_alloc_mgr.push_back((uint8_t *)a2);
                    if (fn && a1 && a2) {
                        memcpy(fn, "add", 4);
                        memcpy(a1, "3", 2);
                        memcpy(a2, "4", 2);
                        uint64_t exec_args[5];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = (uint64_t)(uintptr_t)fn;
                        exec_args[2] = 2; /* argc */
                        exec_args[3] = (uint64_t)(uintptr_t)a1;
                        exec_args[4] = (uint64_t)(uintptr_t)a2;
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_FUNC,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                }

                /* Deinstantiate */
                uint64_t deinst[1];
                deinst[0] = (uint64_t)(uintptr_t)module_inst;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_DEINSTANTIATE_MODULE,
                                     (uint8_t *)deinst, sizeof(deinst));
            }

            /* Unload */
            uint64_t unload[1];
            unload[0] = (uint64_t)(uintptr_t)enclave_module;
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_UNLOAD_MODULE,
                                 (uint8_t *)unload, sizeof(unload));
        }
    }

cleanup:
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * WASM module with f32 and f64 floating-point operations.
 * Exercises the floating-point dispatch paths in the interpreter which are
 * completely separate from the integer paths already tested.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (f32/f64 opcode handlers),
 *   wasm_loader_prepare_bytecode (float validation)
 */
static void
harness_wasm_float_ops(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 3 types */
    static const uint8_t type_body[] = {
        0x03,
        0x60, 0x00, 0x00,                         /* type 0: () -> () */
        0x60, 0x02, 0x7D, 0x7D, 0x01, 0x7D,       /* type 1: (f32,f32) -> (f32) */
        0x60, 0x02, 0x7C, 0x7C, 0x01, 0x7C,       /* type 2: (f64,f64) -> (f64) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 3 functions */
    static const uint8_t func_body[] = { 0x03, 0x00, 0x01, 0x02 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 2);

    uint8_t code_buf[512];
    size_t cc = 0;
    code_buf[cc++] = 0x03; /* 3 code entries */

    switch (variant) {
        case 0: {
            /* Func 0: _start - f32 arithmetic via memory store/load */
            static const uint8_t body0[] = {
                0x01, 0x01, 0x7D,       /* 1 local: f32 */
                0x43, 0x00, 0x00, 0x20, 0x41, /* f32.const 10.0 */
                0x43, 0x00, 0x00, 0xA0, 0x40, /* f32.const 5.0 */
                0x92,                   /* f32.add */
                0x21, 0x00,             /* local.set 0 */
                0x41, 0x00,             /* i32.const 0 (addr) */
                0x20, 0x00,             /* local.get 0 */
                0x38, 0x02, 0x00,       /* f32.store align=2 offset=0 */
                0x41, 0x00,             /* i32.const 0 */
                0x2A, 0x02, 0x00,       /* f32.load align=2 offset=0 */
                0x43, 0x00, 0x00, 0x80, 0x3F, /* f32.const 1.0 */
                0x93,                   /* f32.sub */
                0x43, 0x00, 0x00, 0x40, 0x40, /* f32.const 3.0 */
                0x94,                   /* f32.mul */
                0x43, 0x00, 0x00, 0x00, 0x40, /* f32.const 2.0 */
                0x95,                   /* f32.div */
                0x1A,                   /* drop */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body0));
            memcpy(code_buf + cc, body0, sizeof(body0));
            cc += sizeof(body0);

            /* Func 1: (f32,f32) -> (f32) - min/max/neg/abs/sqrt */
            static const uint8_t body1[] = {
                0x00,
                0x20, 0x00,     /* local.get 0 */
                0x20, 0x01,     /* local.get 1 */
                0x96,           /* f32.min */
                0x20, 0x00,     /* local.get 0 */
                0x20, 0x01,     /* local.get 1 */
                0x97,           /* f32.max */
                0x92,           /* f32.add */
                0x8C,           /* f32.abs */
                0x8D,           /* f32.neg */
                0x8E,           /* f32.ceil */
                0x8F,           /* f32.floor */
                0x90,           /* f32.trunc */
                0x91,           /* f32.nearest */
                0x0B,           /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body1));
            memcpy(code_buf + cc, body1, sizeof(body1));
            cc += sizeof(body1);

            /* Func 2: (f64,f64) -> (f64) - basic f64 ops */
            static const uint8_t body2[] = {
                0x00,
                0x20, 0x00,     /* local.get 0 */
                0x20, 0x01,     /* local.get 1 */
                0xA0,           /* f64.add */
                0x20, 0x00,     /* local.get 0 */
                0xA2,           /* f64.mul */
                0x0B,           /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body2));
            memcpy(code_buf + cc, body2, sizeof(body2));
            cc += sizeof(body2);
            break;
        }
        case 1: {
            /* Func 0: _start - f64 arithmetic + comparisons */
            static const uint8_t body0[] = {
                0x02, 0x01, 0x7C, 0x01, 0x7F, /* 2 locals: 1xf64, 1xi32 */
                0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x40, /* f64.const 100.0 */
                0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x40, /* f64.const 50.0 */
                0xA0,                   /* f64.add */
                0x21, 0x00,             /* local.set 0 */
                0x20, 0x00,             /* local.get 0 */
                0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x62, 0x40, /* f64.const 150.0 */
                0x61,                   /* f64.eq */
                0x21, 0x01,             /* local.set 1 */
                0x20, 0x00,             /* local.get 0 */
                0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* f64.const 0.0 */
                0x63,                   /* f64.gt */
                0x1A,                   /* drop */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body0));
            memcpy(code_buf + cc, body0, sizeof(body0));
            cc += sizeof(body0);

            /* Func 1: (f32,f32) -> (f32) - comparisons */
            static const uint8_t body1[] = {
                0x00,
                0x20, 0x00, 0x20, 0x01, 0x5B, /* f32.eq */
                0x04, 0x7D,             /* if (result f32) */
                0x20, 0x00,             /* local.get 0 */
                0x05,                   /* else */
                0x20, 0x01,             /* local.get 1 */
                0x0B,                   /* end if */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body1));
            memcpy(code_buf + cc, body1, sizeof(body1));
            cc += sizeof(body1);

            /* Func 2: (f64,f64) -> (f64) - sqrt, copysign */
            static const uint8_t body2[] = {
                0x00,
                0x20, 0x00,     /* local.get 0 */
                0x9F,           /* f64.sqrt */
                0x20, 0x01,     /* local.get 1 */
                0xA6,           /* f64.copysign */
                0x0B,           /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body2));
            memcpy(code_buf + cc, body2, sizeof(body2));
            cc += sizeof(body2);
            break;
        }
        case 2: {
            /* Func 0: _start - conversions between types */
            static const uint8_t body0[] = {
                0x02, 0x01, 0x7D, 0x01, 0x7C, /* 2 locals: f32, f64 */
                0x41, 0x2A,             /* i32.const 42 */
                0xB2,                   /* f32.convert_i32_s */
                0x21, 0x00,             /* local.set 0 (f32 local) */
                0x20, 0x00,             /* local.get 0 */
                0xBB,                   /* f64.promote_f32 */
                0x21, 0x01,             /* local.set 1 (f64 local) */
                0x20, 0x01,             /* local.get 1 */
                0xAA,                   /* i32.trunc_f64_s */
                0x1A,                   /* drop */
                0x20, 0x00,             /* local.get 0 */
                0xBC,                   /* i32.reinterpret_f32 */
                0x1A,                   /* drop */
                0x42, 0x80, 0x80, 0x04, /* i64.const 65536 */
                0xB9,                   /* f64.convert_i64_s */
                0xB6,                   /* f32.demote_f64 */
                0x1A,                   /* drop */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body0));
            memcpy(code_buf + cc, body0, sizeof(body0));
            cc += sizeof(body0);

            /* Func 1: (f32,f32) -> (f32) - select */
            static const uint8_t body1[] = {
                0x00,
                0x20, 0x00,     /* local.get 0 */
                0x20, 0x01,     /* local.get 1 */
                0x20, 0x00,     /* local.get 0 */
                0x20, 0x01,     /* local.get 1 */
                0x5D,           /* f32.gt */
                0x1B,           /* select */
                0x0B,           /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body1));
            memcpy(code_buf + cc, body1, sizeof(body1));
            cc += sizeof(body1);

            /* Func 2: (f64,f64) -> (f64) - f64 store/load */
            static const uint8_t body2[] = {
                0x00,
                0x41, 0x00,                     /* i32.const 0 */
                0x20, 0x00,                     /* local.get 0 */
                0x20, 0x01,                     /* local.get 1 */
                0xA0,                           /* f64.add */
                0x39, 0x03, 0x00,               /* f64.store align=3 offset=0 */
                0x41, 0x00,                     /* i32.const 0 */
                0x2B, 0x03, 0x00,               /* f64.load align=3 offset=0 */
                0x0B,                           /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body2));
            memcpy(code_buf + cc, body2, sizeof(body2));
            cc += sizeof(body2);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with bulk memory operations: memory.fill, memory.copy.
 * These use the 0xFC prefix byte and exercise the extended opcode
 * dispatcher in the interpreter.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (0xFC prefix handler),
 *   wasm_loader_prepare_bytecode (bulk memory validation),
 *   memory bounds checking
 */
static void
harness_wasm_bulk_memory(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=2 max=4 */
    static const uint8_t mem_body[] = { 0x01, 0x01, 0x02, 0x04 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Datacount section: 1 */
    static const uint8_t dc_body[] = { 0x01 };
    off += write_wasm_section(mod + off, 0x0C, dc_body, sizeof(dc_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 2);
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /* memory.fill + memory.copy */
            static const uint8_t body[] = {
                0x00,                   /* 0 locals */
                0x41, 0x00,             /* i32.const 0 (dest) */
                0x41, 0xFF, 0x00,       /* i32.const 0xFF (value) */
                0x41, 0x40,             /* i32.const 64 (count) */
                0xFC, 0x0B, 0x00,       /* memory.fill mem=0 */
                0x41, 0x80, 0x01,       /* i32.const 128 (dest) */
                0x41, 0x00,             /* i32.const 0 (src) */
                0x41, 0x40,             /* i32.const 64 (count) */
                0xFC, 0x0A, 0x00, 0x00, /* memory.copy dst=0 src=0 */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* memory.init + data.drop */
            static const uint8_t body[] = {
                0x00,                   /* 0 locals */
                0x41, 0x00,             /* i32.const 0 (dest) */
                0x41, 0x00,             /* i32.const 0 (src offset) */
                0x41, 0x04,             /* i32.const 4 (count) */
                0xFC, 0x08, 0x00, 0x00, /* memory.init seg=0 mem=0 */
                0xFC, 0x09, 0x00,       /* data.drop seg=0 */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 2: {
            /* memory.grow + fill at grown region */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,       /* 1 local: i32 */
                0x41, 0x01,             /* i32.const 1 (grow 1 page) */
                0x40, 0x00,             /* memory.grow */
                0x21, 0x00,             /* local.set 0 (previous size) */
                0x20, 0x00,             /* local.get 0 */
                0x41, 0x00,             /* i32.const 0 */
                0x48,                   /* i32.lt_s (check grow succeeded) */
                0x04, 0x40,             /* if (void) */
                0x0C, 0x00,             /* br 0 (exit if grow failed) */
                0x0B,                   /* end if */
                0x20, 0x00,             /* local.get 0 (previous page count) */
                0x41, 0x80, 0x80, 0x04, /* i32.const 65536 */
                0x6C,                   /* i32.mul (convert to byte offset) */
                0x41, 0xAA, 0x01,       /* i32.const 0xAA (fill value) */
                0x41, 0x10,             /* i32.const 16 (count) */
                0xFC, 0x0B, 0x00,       /* memory.fill mem=0 */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);

    /* Data section: 1 passive segment for memory.init */
    static const uint8_t data_body[] = {
        0x01,               /* 1 segment */
        0x01,               /* passive */
        0x04,               /* 4 bytes */
        0xDE, 0xAD, 0xBE, 0xEF,
    };
    off += write_wasm_section(mod + off, 0x0B, data_body, sizeof(data_body));

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with table operations: table.grow, table.size, table.fill,
 * table.copy, elem.drop. These use the 0xFC prefix and exercise the
 * reference-types/table manipulation paths.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (table operation handlers),
 *   wasm_loader_prepare_bytecode (ref_types validation),
 *   table bounds checking, element segment handling
 */
static void
harness_wasm_table_ops(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = {
        0x02,
        0x60, 0x00, 0x00,                  /* type 0: () -> () */
        0x60, 0x01, 0x7F, 0x01, 0x7F,      /* type 1: (i32) -> (i32) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 2 functions */
    static const uint8_t func_body[] = { 0x02, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Table section: 1 funcref table, min=2 max=8 */
    static const uint8_t table_body[] = { 0x01, 0x70, 0x01, 0x02, 0x08 };
    off += write_wasm_section(mod + off, 0x04,
                              table_body, sizeof(table_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Element section: 1 passive element segment with func refs */
    static const uint8_t elem_body[] = {
        0x01,               /* 1 segment */
        0x01,               /* passive, elemkind=funcref */
        0x00,               /* elemkind = funcref */
        0x02,               /* 2 indices */
        0x00, 0x01,         /* func 0, func 1 */
    };
    off += write_wasm_section(mod + off, 0x09, elem_body, sizeof(elem_body));

    /* Code section */
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x02; /* 2 code entries */

    /* Func 0: _start - table.size, table.grow, table.fill, table.init, elem.drop */
    {
        static const uint8_t body[] = {
            0x01, 0x01, 0x7F,           /* 1 local: i32 */
            0xFC, 0x10, 0x00,           /* table.size table=0 */
            0x21, 0x00,                 /* local.set 0 */
            0xD0, 0x70,                 /* ref.null funcref */
            0x41, 0x02,                 /* i32.const 2 (grow by 2) */
            0xFC, 0x0F, 0x00,           /* table.grow table=0 */
            0x1A,                       /* drop (returns previous size or -1) */
            0x41, 0x00,                 /* i32.const 0 (dest in table) */
            0x41, 0x00,                 /* i32.const 0 (src in elem) */
            0x41, 0x02,                 /* i32.const 2 (count) */
            0xFC, 0x0C, 0x00, 0x00,     /* table.init table=0 elem=0 */
            0xFC, 0x0D, 0x00,           /* elem.drop seg=0 */
            0x41, 0x02,                 /* i32.const 2 (start idx) */
            0xD0, 0x70,                 /* ref.null funcref */
            0x41, 0x02,                 /* i32.const 2 (count) */
            0xFC, 0x11, 0x00,           /* table.fill table=0 */
            0x0B,                       /* end */
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    /* Func 1: (i32) -> (i32) - identity */
    {
        static const uint8_t body[] = {
            0x00,
            0x20, 0x00,
            0x0B,
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with trapping operations to exercise error handling paths.
 * Generates modules that may trap (integer division by zero, unreachable,
 * etc.) to test the interpreter's trap handling and exception paths.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (trap handling, exception setting),
 *   wasm_set_exception, exception propagation paths
 */
static void
harness_wasm_trapping_ops(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_sec[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_sec, sizeof(func_sec));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int trap_kind = g_fdp->ConsumeIntegralInRange<int>(0, 4);
    uint8_t code_buf[128];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (trap_kind) {
        case 0: {
            /* Integer division by zero: i32.div_s(1, 0) */
            static const uint8_t body[] = {
                0x00,
                0x41, 0x01,     /* i32.const 1 */
                0x41, 0x00,     /* i32.const 0 */
                0x6D,           /* i32.div_s -> trap! */
                0x1A,           /* drop */
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* Integer overflow: i32.div_s(INT32_MIN, -1) */
            static const uint8_t body[] = {
                0x00,
                0x41, 0x80, 0x80, 0x80, 0x80, 0x78, /* i32.const 0x80000000 */
                0x41, 0x7F,     /* i32.const -1 */
                0x6D,           /* i32.div_s -> trap! */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 2: {
            /* Out-of-bounds memory access */
            static const uint8_t body[] = {
                0x00,
                0x41, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, /* i32.const very large */
                0x28, 0x02, 0x00,       /* i32.load offset=0 -> trap! */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 3: {
            /* Unreachable instruction */
            static const uint8_t body[] = {
                0x00,
                0x00,           /* unreachable -> trap! */
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 4: {
            /* i32.rem_s and i32.rem_u with fuzzed operands */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,   /* 1 local: i32 */
                0x41, 0x0A,         /* i32.const 10 */
                0x41, 0x03,         /* i32.const 3 */
                0x6F,               /* i32.rem_s */
                0x21, 0x00,         /* local.set 0 */
                0x41, 0x0A,         /* i32.const 10 */
                0x41, 0x03,         /* i32.const 3 */
                0x70,               /* i32.rem_u */
                0x20, 0x00,         /* local.get 0 */
                0x6A,               /* i32.add */
                0x1A,               /* drop */
                0x41, 0x0A,         /* i32.const 10 */
                0x41, 0x03,         /* i32.const 3 */
                0x6E,               /* i32.div_u */
                0x1A,               /* drop */
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with larger fuzzed bytecode through ecall_iwasm_main.
 * Similar to harness_valid_wasm_fuzz_body but with a larger body and
 * multiple function types (including result types) to increase interpreter
 * path coverage. The module has multiple types so the fuzzer can generate
 * valid function signatures.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (broader opcode dispatch),
 *   wasm_loader_prepare_bytecode (validation of many opcodes),
 *   load_code_section
 */
static void
harness_valid_wasm_large_fuzz_body(void)
{
    if (g_fdp->remaining_bytes() < 32)
        return;

    size_t body_len = g_fdp->ConsumeIntegralInRange<size_t>(64, 1024);

    uint8_t *module_buf = (uint8_t *)calloc(1, 8192);
    g_alloc_mgr.push_back(module_buf);
    if (!module_buf)
        return;

    size_t off = 0;
    memcpy(module_buf, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 4 types for variety */
    static const uint8_t type_body[] = {
        0x04,
        0x60, 0x00, 0x00,                         /* type 0: () -> () */
        0x60, 0x01, 0x7F, 0x01, 0x7F,             /* type 1: (i32) -> (i32) */
        0x60, 0x02, 0x7D, 0x7D, 0x01, 0x7D,       /* type 2: (f32,f32) -> (f32) */
        0x60, 0x01, 0x7E, 0x01, 0x7E,             /* type 3: (i64) -> (i64) */
    };
    off += write_wasm_section(module_buf + off, 0x01,
                              type_body, sizeof(type_body));

    /* Function section: 2 functions */
    static const uint8_t func_body[] = { 0x02, 0x00, 0x01 };
    off += write_wasm_section(module_buf + off, 0x03,
                              func_body, sizeof(func_body));

    /* Memory section: min=1 max=4 */
    static const uint8_t mem_body[] = { 0x01, 0x01, 0x01, 0x04 };
    off += write_wasm_section(module_buf + off, 0x05,
                              mem_body, sizeof(mem_body));

    /* Global section: 2 mutable globals */
    static const uint8_t global_body[] = {
        0x02,
        0x7F, 0x01, 0x41, 0x00, 0x0B, /* i32, mutable, init=0 */
        0x7E, 0x01, 0x42, 0x00, 0x0B, /* i64, mutable, init=0 */
    };
    off += write_wasm_section(module_buf + off, 0x06,
                              global_body, sizeof(global_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(module_buf + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: 2 entries */
    uint8_t code_buf[2048];
    size_t cb_off = 0;
    code_buf[cb_off++] = 0x02; /* 2 code entries */

    /* Func 0: () -> () with fuzzed bytecode */
    {
        uint8_t func_bytes[1100];
        size_t fb_off = 0;
        /* Declare 2 locals (i32 and f32) so fuzzed bytecode has operands */
        func_bytes[fb_off++] = 0x02;   /* 2 local groups */
        func_bytes[fb_off++] = 0x02;   /* 2 x i32 */
        func_bytes[fb_off++] = 0x7F;
        func_bytes[fb_off++] = 0x01;   /* 1 x f32 */
        func_bytes[fb_off++] = 0x7D;

        size_t actual = body_len;
        if (g_fdp->remaining_bytes() < actual)
            actual = g_fdp->remaining_bytes();
        if (actual > 0)
            g_fdp->ConsumeData(func_bytes + fb_off, actual);
        fb_off += actual;
        /* Ensure end opcode */
        func_bytes[fb_off - 1] = 0x0B;

        cb_off += write_u32_leb128(code_buf + cb_off, (uint32_t)fb_off);
        memcpy(code_buf + cb_off, func_bytes, fb_off);
        cb_off += fb_off;
    }

    /* Func 1: (i32) -> (i32) with fuzzed body */
    {
        size_t body2_len = g_fdp->ConsumeIntegralInRange<size_t>(2, 128);
        uint8_t func_bytes[200];
        size_t fb_off = 0;
        func_bytes[fb_off++] = 0x01;   /* 1 local group */
        func_bytes[fb_off++] = 0x01;   /* 1 x i32 */
        func_bytes[fb_off++] = 0x7F;

        size_t actual = body2_len;
        if (g_fdp->remaining_bytes() < actual)
            actual = g_fdp->remaining_bytes();
        if (actual > 0)
            g_fdp->ConsumeData(func_bytes + fb_off, actual);
        fb_off += actual;
        if (fb_off > 3)
            func_bytes[fb_off - 1] = 0x0B;
        else {
            func_bytes[fb_off++] = 0x20; /* local.get */
            func_bytes[fb_off++] = 0x00; /* index 0 */
            func_bytes[fb_off++] = 0x0B; /* end */
        }

        cb_off += write_u32_leb128(code_buf + cb_off, (uint32_t)fb_off);
        memcpy(code_buf + cb_off, func_bytes, fb_off);
        cb_off += fb_off;
    }

    off += write_wasm_section(module_buf + off, 0x0A, code_buf, cb_off);
    ecall_iwasm_main(__g_harness_eid, module_buf, (uint32_t)off);
}

/*
 * Structured AOT module targeting deeper AOT loading paths.
 * Constructs a more complete AOT file header with target info, section info
 * table, and fuzzed section data to exercise aot_load_from_aot_file
 * beyond the initial magic/version check.
 *
 * Targets bottlenecks in:
 *   aot_load_from_aot_file, create_sections, resolve_execute_mode,
 *   aot_load_from_sections, read_target_info
 */
static void
harness_aot_structured(void)
{
    if (g_fdp->remaining_bytes() < 32)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;

    /* AOT magic: \0aot */
    memcpy(mod, aot_magic_hdr, 4);
    off = 4;

    /* AOT version (2 = current version) */
    uint32_t aot_ver = 2;
    memcpy(mod + off, &aot_ver, 4);
    off += 4;

    /* Target info section (section type 0) */
    /* This needs to be somewhat valid to pass target_info reading */
    uint8_t target_buf[128];
    size_t tb_off = 0;

    /* bin_type: 0=ELF, 1=AotBinary, 2=XIP */
    uint16_t bin_type = g_fdp->ConsumeIntegralInRange<uint16_t>(0, 2);
    memcpy(target_buf + tb_off, &bin_type, 2);
    tb_off += 2;

    /* abi_type: 0=Linux_SGX for SGX enclave */
    uint16_t abi_type = 5; /* Linux SGX */
    memcpy(target_buf + tb_off, &abi_type, 2);
    tb_off += 2;

    /* e_type: ET_REL=1, ET_DYN=3 */
    uint16_t e_type = g_fdp->ConsumeIntegralInRange<uint16_t>(1, 3);
    memcpy(target_buf + tb_off, &e_type, 2);
    tb_off += 2;

    /* e_machine: EM_X86_64=62 */
    uint16_t e_machine = 62;
    memcpy(target_buf + tb_off, &e_machine, 2);
    tb_off += 2;

    /* e_version */
    uint32_t e_version = 1;
    memcpy(target_buf + tb_off, &e_version, 4);
    tb_off += 4;

    /* e_flags */
    uint32_t e_flags = 0;
    memcpy(target_buf + tb_off, &e_flags, 4);
    tb_off += 4;

    /* feature_flags */
    uint32_t feature_flags = g_fdp->ConsumeIntegral<uint32_t>();
    memcpy(target_buf + tb_off, &feature_flags, 4);
    tb_off += 4;

    /* reserved */
    uint64_t reserved = 0;
    memcpy(target_buf + tb_off, &reserved, 8);
    tb_off += 8;

    /* arch string (null-terminated, 16 bytes) */
    memset(target_buf + tb_off, 0, 16);
    memcpy(target_buf + tb_off, "x86_64", 6);
    tb_off += 16;

    /* Write target info as AOT section: type(4) + size(4) + data */
    uint32_t sec_type = 0; /* AOT_SECTION_TYPE_TARGET_INFO */
    uint32_t sec_size = (uint32_t)tb_off;
    memcpy(mod + off, &sec_type, 4);
    off += 4;
    memcpy(mod + off, &sec_size, 4);
    off += 4;
    memcpy(mod + off, target_buf, tb_off);
    off += tb_off;

    /* Add fuzzed additional sections */
    size_t remaining = g_fdp->ConsumeIntegralInRange<size_t>(0, 2048);
    if (remaining > g_fdp->remaining_bytes())
        remaining = g_fdp->remaining_bytes();
    if (remaining > 0 && off + remaining < 4096) {
        g_fdp->ConsumeData(mod + off, remaining);
        off += remaining;
    }

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Command workflow that exercises exec_app_func with various argument patterns.
 * Tests the function lookup and argument parsing paths more thoroughly
 * by using different export names, argument counts, and argument formats.
 *
 * Targets bottlenecks in:
 *   handle_cmd_exec_app_func, wasm_application_execute_func,
 *   argument parsing/conversion, function lookup by name
 */
static void
harness_cmd_exec_func_variants(void)
{
    if (g_fdp->remaining_bytes() < 32)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Init runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        goto cleanup;

    /* Load module with multiple exported functions of different types */
    {
        static const uint8_t wasm_mod[] = {
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            /* Type: 4 types */
            0x01, 0x12, 0x04,
            0x60, 0x00, 0x00,                           /* () -> () */
            0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,         /* (i32,i32) -> (i32) */
            0x60, 0x01, 0x7F, 0x01, 0x7F,               /* (i32) -> (i32) */
            0x60, 0x00, 0x01, 0x7F,                     /* () -> (i32) */
            /* Function: 4 funcs */
            0x03, 0x05, 0x04, 0x00, 0x01, 0x02, 0x03,
            /* Memory: min=1 */
            0x05, 0x03, 0x01, 0x00, 0x01,
            /* Export: memory, _start, add, double, answer */
            0x07, 0x2B, 0x05,
            0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
            0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            0x03, 0x61, 0x64, 0x64, 0x00, 0x01,
            0x06, 0x64, 0x6F, 0x75, 0x62, 0x6C, 0x65, 0x00, 0x02,
            0x06, 0x61, 0x6E, 0x73, 0x77, 0x65, 0x72, 0x00, 0x03,
            /* Code: 4 entries */
            0x0A, 0x19, 0x04,
            0x02, 0x00, 0x0B,                              /* _start: end */
            0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B, /* add: get0+get1+add+end */
            0x07, 0x00, 0x20, 0x00, 0x41, 0x02, 0x6C, 0x0B, /* double: get0*2+end */
            0x04, 0x00, 0x41, 0x2A, 0x0B,                   /* answer: const 42+end */
        };
        uint8_t *wf = (uint8_t *)calloc(1, sizeof(wasm_mod));
        g_alloc_mgr.push_back(wf);
        if (!wf)
            goto cleanup;
        memcpy(wf, wasm_mod, sizeof(wasm_mod));

        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)wf;
        load_args[1] = (uint64_t)sizeof(wasm_mod);
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Instantiate */
        memset(error_buf, 0, sizeof(error_buf));
        uint64_t inst_args[5];
        inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
        inst_args[1] = (uint64_t)(32 * 1024);
        inst_args[2] = (uint64_t)(32 * 1024);
        inst_args[3] = (uint64_t)(uintptr_t)error_buf;
        inst_args[4] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid,
                             HARNESS_CMD_INSTANTIATE_MODULE,
                             (uint8_t *)inst_args, sizeof(inst_args));

        void *module_inst = (void *)(uintptr_t)inst_args[0];
        if (module_inst) {
            /* Choose which function to call */
            int func_choice = g_fdp->ConsumeIntegralInRange<int>(0, 3);

            switch (func_choice) {
                case 0: {
                    /* Call "add" with fuzzed args */
                    char *fn = (char *)calloc(1, 8);
                    g_alloc_mgr.push_back((uint8_t *)fn);
                    char *a1 = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)a1);
                    char *a2 = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)a2);
                    if (fn && a1 && a2) {
                        memcpy(fn, "add", 4);
                        int v1 = g_fdp->ConsumeIntegralInRange<int>(-1000, 1000);
                        int v2 = g_fdp->ConsumeIntegralInRange<int>(-1000, 1000);
                        snprintf(a1, 16, "%d", v1);
                        snprintf(a2, 16, "%d", v2);
                        uint64_t exec_args[5];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = (uint64_t)(uintptr_t)fn;
                        exec_args[2] = 2;
                        exec_args[3] = (uint64_t)(uintptr_t)a1;
                        exec_args[4] = (uint64_t)(uintptr_t)a2;
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_FUNC,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                    break;
                }
                case 1: {
                    /* Call "double" with fuzzed arg */
                    char *fn = (char *)calloc(1, 8);
                    g_alloc_mgr.push_back((uint8_t *)fn);
                    char *a1 = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)a1);
                    if (fn && a1) {
                        memcpy(fn, "double", 7);
                        int v = g_fdp->ConsumeIntegral<int>();
                        snprintf(a1, 16, "%d", v);
                        uint64_t exec_args[4];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = (uint64_t)(uintptr_t)fn;
                        exec_args[2] = 1;
                        exec_args[3] = (uint64_t)(uintptr_t)a1;
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_FUNC,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                    break;
                }
                case 2: {
                    /* Call "answer" with no args */
                    char *fn = (char *)calloc(1, 8);
                    g_alloc_mgr.push_back((uint8_t *)fn);
                    if (fn) {
                        memcpy(fn, "answer", 7);
                        uint64_t exec_args[3];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = (uint64_t)(uintptr_t)fn;
                        exec_args[2] = 0;
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_FUNC,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                    break;
                }
                case 3: {
                    /* Call nonexistent function to test lookup failure */
                    char *fn = (char *)calloc(1, 16);
                    g_alloc_mgr.push_back((uint8_t *)fn);
                    if (fn) {
                        memcpy(fn, "nonexist", 9);
                        uint64_t exec_args[3];
                        exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                        exec_args[1] = (uint64_t)(uintptr_t)fn;
                        exec_args[2] = 0;
                        ecall_handle_command(__g_harness_eid,
                                             HARNESS_CMD_EXEC_APP_FUNC,
                                             (uint8_t *)exec_args,
                                             sizeof(exec_args));
                    }
                    break;
                }
            }

            /* Get exception */
            {
                char exc_buf[256];
                memset(exc_buf, 0, sizeof(exc_buf));
                uint64_t exc_args[3];
                exc_args[0] = (uint64_t)(uintptr_t)module_inst;
                exc_args[1] = (uint64_t)(uintptr_t)exc_buf;
                exc_args[2] = (uint64_t)sizeof(exc_buf);
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_GET_EXCEPTION,
                                     (uint8_t *)exc_args,
                                     sizeof(exc_args));
            }

            /* Deinstantiate */
            uint64_t deinst[1];
            deinst[0] = (uint64_t)(uintptr_t)module_inst;
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_DEINSTANTIATE_MODULE,
                                 (uint8_t *)deinst, sizeof(deinst));
        }

        /* Unload */
        uint64_t unload[1];
        unload[0] = (uint64_t)(uintptr_t)enclave_module;
        ecall_handle_command(__g_harness_eid,
                             HARNESS_CMD_UNLOAD_MODULE,
                             (uint8_t *)unload, sizeof(unload));
    }

cleanup:
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * WASM module with shared memory and atomic operations (0xFE prefix).
 * Shared memory requires flag 0x03 in the memory section (has_max | shared).
 * WASM_ENABLE_SHARED_MEMORY=1 and WASM_ENABLE_THREAD_MGR=1 are enabled
 * but no existing harness exercises these paths.
 *
 * Targets:
 *   load_memory_section (shared flag path),
 *   wasm_interp (WASM_OP_ATOMIC_PREFIX handler),
 *   atomic load/store/RMW interpreter paths
 */
static void
harness_wasm_shared_memory_atomic(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: 1 shared memory, min=1 max=4
     * flag 0x03 = has_max (0x01) | shared (0x02) */
    static const uint8_t mem_body[] = { 0x01, 0x03, 0x01, 0x04 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 3);
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /* i32 atomic store, load, rmw.add */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,           /* 1 local: i32 */
                0x41, 0x00,                 /* i32.const 0 (addr) */
                0x41, 0x2A,                 /* i32.const 42 */
                0xFE, 0x17, 0x02, 0x00,     /* i32.atomic.store align=2 offset=0 */
                0x41, 0x00,                 /* i32.const 0 */
                0xFE, 0x10, 0x02, 0x00,     /* i32.atomic.load align=2 offset=0 */
                0x21, 0x00,                 /* local.set 0 */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x01,                 /* i32.const 1 */
                0xFE, 0x1E, 0x02, 0x00,     /* i32.atomic.rmw.add align=2 offset=0 */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* i32 atomic rmw sub, and, or, xor */
            static const uint8_t body[] = {
                0x00,                       /* 0 locals */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x7F,                 /* i32.const 127 */
                0xFE, 0x17, 0x02, 0x00,     /* i32.atomic.store */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x01,                 /* i32.const 1 */
                0xFE, 0x20, 0x02, 0x00,     /* i32.atomic.rmw.sub align=2 offset=0 */
                0x1A,                       /* drop */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x0F,                 /* i32.const 15 */
                0xFE, 0x22, 0x02, 0x00,     /* i32.atomic.rmw.and align=2 offset=0 */
                0x1A,                       /* drop */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x70,                 /* i32.const 112 */
                0xFE, 0x24, 0x02, 0x00,     /* i32.atomic.rmw.or align=2 offset=0 */
                0x1A,                       /* drop */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x55,                 /* i32.const 85 */
                0xFE, 0x26, 0x02, 0x00,     /* i32.atomic.rmw.xor align=2 offset=0 */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 2: {
            /* atomic xchg, cmpxchg, fence */
            static const uint8_t body[] = {
                0x00,                       /* 0 locals */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x64,                 /* i32.const 100 */
                0xFE, 0x17, 0x02, 0x00,     /* i32.atomic.store */
                0xFE, 0x03, 0x00,           /* atomic.fence */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x64,                 /* i32.const 100 */
                0xFE, 0x28, 0x02, 0x00,     /* i32.atomic.rmw.xchg align=2 offset=0 */
                0x1A,                       /* drop */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x64,                 /* i32.const 100 (expected) */
                0x41, 0x60,                 /* i32.const 96 (replacement) */
                0xFE, 0x48, 0x02, 0x00,     /* i32.atomic.rmw.cmpxchg align=2 offset=0 */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 3: {
            /* 8-bit and 16-bit atomic operations */
            static const uint8_t body[] = {
                0x00,                       /* 0 locals */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x42,                 /* i32.const 0x42 */
                0xFE, 0x19, 0x00, 0x00,     /* i32.atomic.store8 align=0 offset=0 */
                0x41, 0x00,                 /* i32.const 0 */
                0xFE, 0x12, 0x00, 0x00,     /* i32.atomic.load8_u align=0 offset=0 */
                0x1A,                       /* drop */
                0x41, 0x04,                 /* i32.const 4 */
                0x41, 0x7F,                 /* i32.const 127 */
                0xFE, 0x1A, 0x01, 0x00,     /* i32.atomic.store16 align=1 offset=0 */
                0x41, 0x04,                 /* i32.const 4 */
                0xFE, 0x13, 0x01, 0x00,     /* i32.atomic.load16_u align=1 offset=0 */
                0x1A,                       /* drop */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0x01,                 /* i32.const 1 */
                0xFE, 0x2A, 0x00, 0x00,     /* i32.atomic.rmw8.add_u align=0 offset=0 */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with a start section (section ID 8).
 * The start function executes automatically during instantiation,
 * exercising execute_post_instantiate_functions and start function paths.
 * No existing harness uses a start section.
 *
 * Targets:
 *   load_start_section, execute_post_instantiate_functions (start path),
 *   start function validation and execution
 */
static void
harness_wasm_start_function(void)
{
    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () and () -> (i32) */
    static const uint8_t type_body[] = {
        0x02,
        0x60, 0x00, 0x00,              /* type 0: () -> () */
        0x60, 0x00, 0x01, 0x7F,        /* type 1: () -> (i32) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 2 functions */
    static const uint8_t func_body[] = { 0x02, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Global: 1 mutable i32 initialized to 0 */
    static const uint8_t global_body[] = {
        0x01,
        0x7F, 0x01, 0x41, 0x00, 0x0B,  /* i32, mutable, init=0 */
    };
    off += write_wasm_section(mod + off, 0x06,
                              global_body, sizeof(global_body));

    /* Export: memory + _start (func 1) */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Start section: start function = func 0 */
    static const uint8_t start_body[] = { 0x00 };
    off += write_wasm_section(mod + off, 0x08,
                              start_body, sizeof(start_body));

    /* Code section: 2 entries */
    uint8_t code_buf[128];
    size_t cc = 0;
    code_buf[cc++] = 0x02; /* 2 code entries */

    /* Func 0 (start): initializes global to 42, stores to memory */
    {
        static const uint8_t body[] = {
            0x00,               /* 0 locals */
            0x41, 0x2A,         /* i32.const 42 */
            0x24, 0x00,         /* global.set 0 */
            0x41, 0x00,         /* i32.const 0 (addr) */
            0x41, 0x2A,         /* i32.const 42 */
            0x36, 0x02, 0x00,   /* i32.store offset=0 */
            0x0B,               /* end */
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    /* Func 1 (_start): reads global set by start function */
    {
        static const uint8_t body[] = {
            0x00,               /* 0 locals */
            0x23, 0x00,         /* global.get 0 */
            0x41, 0x04,         /* i32.const 4 */
            0x36, 0x02, 0x00,   /* i32.store align=2 offset=0 */
            0x0B,               /* end */
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with globals of reference types (funcref, externref).
 * WASM_ENABLE_REF_TYPES=1 is enabled but no existing harness tests
 * global section parsing with ref type init expressions (ref.null, ref.func).
 *
 * Targets:
 *   load_global_section (ref type globals),
 *   ref.null/ref.is_null/ref.func init expression parsing,
 *   global.get/set with reference types
 */
static void
harness_wasm_globals_reftypes(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () and (i32) -> (i32) */
    static const uint8_t type_body[] = {
        0x02,
        0x60, 0x00, 0x00,              /* type 0: () -> () */
        0x60, 0x01, 0x7F, 0x01, 0x7F,  /* type 1: (i32) -> (i32) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 2 functions */
    static const uint8_t func_body[] = { 0x02, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Table section: 1 funcref table min=4 max=8 */
    static const uint8_t table_body[] = { 0x01, 0x70, 0x01, 0x04, 0x08 };
    off += write_wasm_section(mod + off, 0x04,
                              table_body, sizeof(table_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Global section: variant-dependent */
    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 2);
    uint8_t global_buf[64];
    size_t gb_off = 0;

    switch (variant) {
        case 0: {
            /* funcref globals: null + ref.func 0 + mutable i32 */
            global_buf[gb_off++] = 0x03; /* 3 globals */
            /* global 0: immutable funcref = ref.null funcref */
            global_buf[gb_off++] = 0x70; /* funcref */
            global_buf[gb_off++] = 0x00; /* immutable */
            global_buf[gb_off++] = 0xD0; /* ref.null */
            global_buf[gb_off++] = 0x70; /* funcref */
            global_buf[gb_off++] = 0x0B; /* end */
            /* global 1: mutable funcref = ref.func 0 (exported) */
            global_buf[gb_off++] = 0x70; /* funcref */
            global_buf[gb_off++] = 0x01; /* mutable */
            global_buf[gb_off++] = 0xD2; /* ref.func */
            global_buf[gb_off++] = 0x00; /* func idx 0 */
            global_buf[gb_off++] = 0x0B; /* end */
            /* global 2: mutable i32 = 0 */
            global_buf[gb_off++] = 0x7F; /* i32 */
            global_buf[gb_off++] = 0x01; /* mutable */
            global_buf[gb_off++] = 0x41; /* i32.const */
            global_buf[gb_off++] = 0x00; /* 0 */
            global_buf[gb_off++] = 0x0B; /* end */
            break;
        }
        case 1: {
            /* externref global: null + i32 */
            global_buf[gb_off++] = 0x02; /* 2 globals */
            /* global 0: immutable externref = ref.null externref */
            global_buf[gb_off++] = 0x6F; /* externref */
            global_buf[gb_off++] = 0x00; /* immutable */
            global_buf[gb_off++] = 0xD0; /* ref.null */
            global_buf[gb_off++] = 0x6F; /* externref */
            global_buf[gb_off++] = 0x0B; /* end */
            /* global 1: mutable i32 = 0 */
            global_buf[gb_off++] = 0x7F; /* i32 */
            global_buf[gb_off++] = 0x01; /* mutable */
            global_buf[gb_off++] = 0x41; /* i32.const */
            global_buf[gb_off++] = 0x00; /* 0 */
            global_buf[gb_off++] = 0x0B; /* end */
            break;
        }
        case 2: {
            /* Multiple funcref globals: ref.func 0 + ref.null */
            global_buf[gb_off++] = 0x02; /* 2 globals */
            /* global 0: mutable funcref = ref.func 0 (exported) */
            global_buf[gb_off++] = 0x70; /* funcref */
            global_buf[gb_off++] = 0x01; /* mutable */
            global_buf[gb_off++] = 0xD2; /* ref.func */
            global_buf[gb_off++] = 0x00; /* func idx 0 */
            global_buf[gb_off++] = 0x0B; /* end */
            /* global 1: mutable funcref = ref.null funcref */
            global_buf[gb_off++] = 0x70; /* funcref */
            global_buf[gb_off++] = 0x01; /* mutable */
            global_buf[gb_off++] = 0xD0; /* ref.null */
            global_buf[gb_off++] = 0x70; /* funcref */
            global_buf[gb_off++] = 0x0B; /* end */
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x06, global_buf, gb_off);

    /* Export: memory + _start (func 0) */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: 2 entries */
    uint8_t code_buf[128];
    size_t cc = 0;
    code_buf[cc++] = 0x02; /* 2 code entries */

    /* Func 0 (_start): ref.is_null on global 0 */
    {
        static const uint8_t body[] = {
            0x00,               /* 0 locals */
            0x23, 0x00,         /* global.get 0 (funcref or externref) */
            0xD1,               /* ref.is_null */
            0x1A,               /* drop */
            0x0B,               /* end */
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    /* Func 1: (i32) -> (i32) identity */
    {
        static const uint8_t body[] = {
            0x00,               /* 0 locals */
            0x20, 0x00,         /* local.get 0 */
            0x0B,               /* end */
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with saturating truncation operations (0xFC 0x00-0x07).
 * These differ from bulk memory ops (0xFC 0x08+) and are untested.
 * Tests with special float values: Inf, -Inf, NaN, max values.
 *
 * Targets:
 *   wasm_interp (WASM_OP_MISC_PREFIX, sat trunc handlers),
 *   wasm_loader_prepare_bytecode (0xFC sub-opcode validation)
 */
static void
harness_wasm_saturating_trunc(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 1);
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /* f32/f64 -> i32 saturating truncations with special values */
            static const uint8_t body[] = {
                0x00,                                   /* 0 locals */
                /* i32.trunc_sat_f32_s(+Inf) */
                0x43, 0x00, 0x00, 0x80, 0x7F,           /* f32.const +Inf */
                0xFC, 0x00,                              /* i32.trunc_sat_f32_s */
                0x1A,                                    /* drop */
                /* i32.trunc_sat_f32_u(-Inf) */
                0x43, 0x00, 0x00, 0x80, 0xFF,           /* f32.const -Inf */
                0xFC, 0x01,                              /* i32.trunc_sat_f32_u */
                0x1A,                                    /* drop */
                /* i32.trunc_sat_f64_s(+Inf) */
                0x44, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xF0, 0x7F,                 /* f64.const +Inf */
                0xFC, 0x02,                              /* i32.trunc_sat_f64_s */
                0x1A,                                    /* drop */
                /* i32.trunc_sat_f64_u(NaN) */
                0x44, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xF8, 0x7F,                 /* f64.const NaN */
                0xFC, 0x03,                              /* i32.trunc_sat_f64_u */
                0x1A,                                    /* drop */
                0x0B,                                    /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* f32/f64 -> i64 saturating truncations */
            static const uint8_t body[] = {
                0x00,                                   /* 0 locals */
                /* i64.trunc_sat_f32_s(NaN) */
                0x43, 0x00, 0x00, 0xC0, 0x7F,           /* f32.const NaN */
                0xFC, 0x04,                              /* i64.trunc_sat_f32_s */
                0x1A,                                    /* drop */
                /* i64.trunc_sat_f32_u(1.5) */
                0x43, 0x00, 0x00, 0xC0, 0x3F,           /* f32.const 1.5 */
                0xFC, 0x05,                              /* i64.trunc_sat_f32_u */
                0x1A,                                    /* drop */
                /* i64.trunc_sat_f64_s(-1.0) */
                0x44, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xF0, 0xBF,                 /* f64.const -1.0 */
                0xFC, 0x06,                              /* i64.trunc_sat_f64_s */
                0x1A,                                    /* drop */
                /* i64.trunc_sat_f64_u(DBL_MAX) */
                0x44, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xEF, 0x7F,                 /* f64.const DBL_MAX */
                0xFC, 0x07,                              /* i64.trunc_sat_f64_u */
                0x1A,                                    /* drop */
                0x0B,                                    /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module focused on i64 operations: arithmetic, conversions,
 * comparisons, and memory load/store variants.
 * No existing harness specifically targets i64 opcode paths.
 *
 * Targets:
 *   wasm_interp (i64 arithmetic/comparison handlers),
 *   i32<->i64 conversion paths (wrap, extend),
 *   i64 memory access (load8/16/32, store), reinterpret
 */
static void
harness_wasm_i64_ops(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 2);
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /* i64 arithmetic: add, mul, and, or, xor, shl, shr_u, clz, ctz, popcnt */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7E,           /* 1 local: i64 */
                0x42, 0x0A,                 /* i64.const 10 */
                0x42, 0x03,                 /* i64.const 3 */
                0x7C,                       /* i64.add */
                0x42, 0x02,                 /* i64.const 2 */
                0x7E,                       /* i64.mul */
                0x42, 0x05,                 /* i64.const 5 */
                0x7D,                       /* i64.sub */
                0x42, 0x7F,                 /* i64.const 127 */
                0x83,                       /* i64.and */
                0x42, 0x0F,                 /* i64.const 15 */
                0x84,                       /* i64.or */
                0x42, 0x05,                 /* i64.const 5 */
                0x85,                       /* i64.xor */
                0x42, 0x04,                 /* i64.const 4 */
                0x86,                       /* i64.shl */
                0x42, 0x02,                 /* i64.const 2 */
                0x88,                       /* i64.shr_u */
                0x21, 0x00,                 /* local.set 0 */
                0x20, 0x00,                 /* local.get 0 */
                0x79,                       /* i64.clz */
                0x1A,                       /* drop */
                0x20, 0x00,                 /* local.get 0 */
                0x7A,                       /* i64.ctz */
                0x1A,                       /* drop */
                0x20, 0x00,                 /* local.get 0 */
                0x7B,                       /* i64.popcnt */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* i32<->i64 conversions and i64 comparisons */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7E,           /* 1 local: i64 */
                /* i64.extend_i32_s(-1) */
                0x41, 0x7F,                 /* i32.const -1 */
                0xAC,                       /* i64.extend_i32_s */
                0x21, 0x00,                 /* local.set 0 */
                /* i64.extend_i32_u(0xFFFF) */
                0x41, 0xFF, 0xFF, 0x03,     /* i32.const 65535 */
                0xAD,                       /* i64.extend_i32_u */
                0x1A,                       /* drop */
                /* i32.wrap_i64 */
                0x20, 0x00,                 /* local.get 0 */
                0xA7,                       /* i32.wrap_i64 */
                0x1A,                       /* drop */
                /* i64.eqz */
                0x20, 0x00,                 /* local.get 0 */
                0x50,                       /* i64.eqz */
                0x1A,                       /* drop */
                /* i64.eq */
                0x20, 0x00,                 /* local.get 0 */
                0x42, 0x7F,                 /* i64.const -1 */
                0x51,                       /* i64.eq */
                0x1A,                       /* drop */
                /* i64.lt_s */
                0x20, 0x00,                 /* local.get 0 */
                0x42, 0x00,                 /* i64.const 0 */
                0x53,                       /* i64.lt_s */
                0x1A,                       /* drop */
                /* i64.gt_u */
                0x20, 0x00,                 /* local.get 0 */
                0x42, 0x00,                 /* i64.const 0 */
                0x56,                       /* i64.gt_u */
                0x1A,                       /* drop */
                /* i64.le_s */
                0x20, 0x00,                 /* local.get 0 */
                0x42, 0x00,                 /* i64.const 0 */
                0x57,                       /* i64.le_s */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 2: {
            /* i64 memory load/store + reinterpret */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7E,           /* 1 local: i64 */
                /* i64.store at addr 0 */
                0x41, 0x00,                 /* i32.const 0 (addr) */
                0x42, 0x2A,                 /* i64.const 42 */
                0x37, 0x03, 0x00,           /* i64.store align=3 offset=0 */
                /* i64.load */
                0x41, 0x00,                 /* i32.const 0 */
                0x29, 0x03, 0x00,           /* i64.load align=3 offset=0 */
                0x21, 0x00,                 /* local.set 0 */
                /* i64.load8_s */
                0x41, 0x00,                 /* i32.const 0 */
                0x30, 0x00, 0x00,           /* i64.load8_s align=0 offset=0 */
                0x1A,                       /* drop */
                /* i64.load16_s */
                0x41, 0x00,                 /* i32.const 0 */
                0x32, 0x01, 0x00,           /* i64.load16_s align=1 offset=0 */
                0x1A,                       /* drop */
                /* i64.load32_s */
                0x41, 0x00,                 /* i32.const 0 */
                0x34, 0x02, 0x00,           /* i64.load32_s align=2 offset=0 */
                0x1A,                       /* drop */
                /* f64.reinterpret_i64 */
                0x20, 0x00,                 /* local.get 0 */
                0xBF,                       /* f64.reinterpret_i64 */
                0x1A,                       /* drop */
                /* i64.reinterpret_f64 */
                0x44, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xF0, 0x3F,     /* f64.const 1.0 */
                0xBD,                       /* i64.reinterpret_f64 */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with select, typed select (0x1C), and sign extension
 * operations (0xC0-0xC4), plus type conversion ops.
 * None of these are targeted by existing harnesses.
 *
 * Targets:
 *   wasm_interp (select, typed select handlers),
 *   sign extension ops (i32.extend8_s, i32.extend16_s, etc.),
 *   type conversion opcodes (promote, demote, convert, reinterpret)
 */
static void
harness_wasm_select_convert(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 1);
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /* select + typed select + sign extension ops */
            static const uint8_t body[] = {
                0x00,                       /* 0 locals */
                /* untyped select: 10, 20, condition=1 -> 10 */
                0x41, 0x0A,                 /* i32.const 10 */
                0x41, 0x14,                 /* i32.const 20 */
                0x41, 0x01,                 /* i32.const 1 (condition) */
                0x1B,                       /* select */
                0x1A,                       /* drop */
                /* typed select [i32]: 30, 40, condition=0 -> 40 */
                0x41, 0x1E,                 /* i32.const 30 */
                0x41, 0x28,                 /* i32.const 40 */
                0x41, 0x00,                 /* i32.const 0 (condition) */
                0x1C, 0x01, 0x7F,           /* select [i32] */
                0x1A,                       /* drop */
                /* i32.extend8_s: 0xFF -> -1 */
                0x41, 0xFF, 0x01,           /* i32.const 255 */
                0xC0,                       /* i32.extend8_s */
                0x1A,                       /* drop */
                /* i32.extend16_s: 0xFFFF -> -1 */
                0x41, 0xFF, 0xFF, 0x03,     /* i32.const 65535 */
                0xC1,                       /* i32.extend16_s */
                0x1A,                       /* drop */
                /* i64.extend8_s */
                0x42, 0x7F,                 /* i64.const 127 */
                0xC2,                       /* i64.extend8_s */
                0x1A,                       /* drop */
                /* i64.extend16_s */
                0x42, 0xFF, 0xFF, 0x03,     /* i64.const 65535 */
                0xC3,                       /* i64.extend16_s */
                0x1A,                       /* drop */
                /* i64.extend32_s */
                0x42, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, /* i64.const 0xFFFFFFFF */
                0xC4,                       /* i64.extend32_s */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* Type conversions: promote, demote, convert, reinterpret */
            static const uint8_t body[] = {
                0x00,                       /* 0 locals */
                /* f32.convert_i32_s(42) */
                0x41, 0x2A,                 /* i32.const 42 */
                0xB2,                       /* f32.convert_i32_s */
                0x1A,                       /* drop */
                /* f64.convert_i32_s(42) */
                0x41, 0x2A,                 /* i32.const 42 */
                0xB7,                       /* f64.convert_i32_s */
                0x1A,                       /* drop */
                /* f64.promote_f32(1.0) */
                0x43, 0x00, 0x00, 0x80, 0x3F, /* f32.const 1.0 */
                0xBB,                       /* f64.promote_f32 */
                0x1A,                       /* drop */
                /* f32.demote_f64(1.0) */
                0x44, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xF0, 0x3F,     /* f64.const 1.0 */
                0xB6,                       /* f32.demote_f64 */
                0x1A,                       /* drop */
                /* f32.reinterpret_i32(0x3F800000 = 1.0) */
                0x41, 0x80, 0x80, 0x80, 0xFC, 0x07, /* i32.const 0x3F800000 */
                0xBE,                       /* f32.reinterpret_i32 */
                0x1A,                       /* drop */
                /* i32.reinterpret_f32 */
                0x43, 0x00, 0x00, 0x80, 0x3F, /* f32.const 1.0 */
                0xBC,                       /* i32.reinterpret_f32 */
                0x1A,                       /* drop */
                /* f32.convert_i32_u(100) */
                0x41, 0x64,                 /* i32.const 100 */
                0xB3,                       /* f32.convert_i32_u */
                0x1A,                       /* drop */
                /* f64.convert_i32_u(100) */
                0x41, 0x64,                 /* i32.const 100 */
                0xB8,                       /* f64.convert_i32_u */
                0x1A,                       /* drop */
                0x0B,                       /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with SIMD v128 operations (0xFD prefix).
 * WAMR_BUILD_SIMD=1 is enabled but no existing harness tests this feature.
 * Exercises the SIMD opcode dispatch paths in the fast interpreter.
 *
 * Variant 0: v128.const, splat, bitwise (AND, OR, XOR, NOT), any_true
 * Variant 1: i32x4 arithmetic (add, sub, mul, neg, abs) + lane extract/replace
 * Variant 2: v128.load/store, load_splat, f32x4 arithmetic
 * Variant 3: i16x8/i8x16 ops (narrow, extend, shift, add_sat, sub_sat)
 * Variant 4: SIMD comparisons + bitselect + shuffle/swizzle
 * Variant 5: f64x2 ops, conversions (trunc_sat, convert, promote, demote)
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (WASM_OP_SIMD_PREFIX handler),
 *   wasm_loader_prepare_bytecode (SIMD validation paths)
 */
static void
harness_wasm_simd_ops(void)
{
    if (g_fdp->remaining_bytes() < 20)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 8192);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = {
        0x01, 0x60, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function using type 0 */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 (needed for v128.load/store) */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 5);

    uint8_t code_buf[2048];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /*
             * v128.const, splat, bitwise ops, any_true
             * Tests the fundamental v128 constant loading, splat construction,
             * and bitwise operations (AND, OR, XOR, NOT, ANDNOT, BITSELECT).
             */
            uint8_t c1[16], c2[16];
            for (int i = 0; i < 16; i++) {
                c1[i] = g_fdp->ConsumeIntegral<uint8_t>();
                c2[i] = g_fdp->ConsumeIntegral<uint8_t>();
            }
            uint8_t body[256];
            size_t bp = 0;
            /* 1 local of type v128 (0x7B) */
            body[bp++] = 0x01; body[bp++] = 0x01; body[bp++] = 0x7B;
            /* v128.const c1 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0C); /* SIMD_v128_const */
            memcpy(body + bp, c1, 16); bp += 16;
            /* v128.const c2 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0C);
            memcpy(body + bp, c2, 16); bp += 16;
            /* v128.and */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x4E);
            /* local.set 0 */
            body[bp++] = 0x21; body[bp++] = 0x00;
            /* i32.const 42 → i32x4.splat */
            body[bp++] = 0x41; body[bp++] = 0x2A;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x11); /* i32x4.splat */
            /* local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            /* v128.or */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x50);
            /* v128.not */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x4D);
            /* v128.const c1 (for xor) */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0C);
            memcpy(body + bp, c1, 16); bp += 16;
            /* v128.xor */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x51);
            /* v128.any_true → i32 result */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            /* drop */
            body[bp++] = 0x1A;
            /* bitselect: needs 3 v128 values on stack */
            /* v128.const c1 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0C);
            memcpy(body + bp, c1, 16); bp += 16;
            /* v128.const c2 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0C);
            memcpy(body + bp, c2, 16); bp += 16;
            /* i64.const 0xFF → i64x2.splat (mask) */
            body[bp++] = 0x42; body[bp++] = 0xFF; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x12); /* i64x2.splat */
            /* v128.bitselect */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x52);
            /* v128.any_true → i32 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            /* drop */
            body[bp++] = 0x1A;
            body[bp++] = 0x0B; /* end */

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bp);
            memcpy(code_buf + cc, body, bp);
            cc += bp;
            break;
        }
        case 1: {
            /*
             * i32x4 arithmetic: add, sub, mul, neg, abs, shl, shr_s
             * Also tests lane extract and replace operations.
             */
            int32_t val = g_fdp->ConsumeIntegral<int32_t>();
            uint8_t lane = g_fdp->ConsumeIntegralInRange<uint8_t>(0, 3);
            uint8_t body[256];
            size_t bp = 0;
            /* 1 local v128 */
            body[bp++] = 0x01; body[bp++] = 0x01; body[bp++] = 0x7B;
            /* i32.const val → i32x4.splat */
            body[bp++] = 0x41;
            bp += write_u32_leb128(body + bp, (uint32_t)val);
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x11); /* i32x4.splat */
            body[bp++] = 0x21; body[bp++] = 0x00; /* local.set 0 */
            /* i32.const 10 → i32x4.splat */
            body[bp++] = 0x41; body[bp++] = 0x0A;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x11);
            /* local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            /* i32x4.add */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xAE);
            /* local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            /* i32x4.sub */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xB1);
            /* local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            /* i32x4.mul */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xB5);
            /* i32x4.neg */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xA1);
            /* i32x4.abs */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xA0);
            /* i32.const 2 for shift amount */
            body[bp++] = 0x41; body[bp++] = 0x02;
            /* i32x4.shl */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xAB);
            /* i32.const 1 for shift amount */
            body[bp++] = 0x41; body[bp++] = 0x01;
            /* i32x4.shr_s */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xAC);
            /* i32x4.extract_lane lane */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x1B);
            body[bp++] = lane;
            /* drop */
            body[bp++] = 0x1A;
            /* Test replace_lane: splat + replace */
            body[bp++] = 0x41; body[bp++] = 0x00;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x11); /* i32x4.splat */
            body[bp++] = 0x41; body[bp++] = 0x63; /* i32.const 99 */
            /* i32x4.replace_lane lane */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x1C);
            body[bp++] = lane;
            /* i32x4.all_true → i32 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xA3);
            /* drop */
            body[bp++] = 0x1A;
            body[bp++] = 0x0B; /* end */

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bp);
            memcpy(code_buf + cc, body, bp);
            cc += bp;
            break;
        }
        case 2: {
            /*
             * v128.load / v128.store, load_splat, f32x4 arithmetic.
             * Exercises SIMD memory access paths and f32x4 lane operations.
             */
            uint8_t body[300];
            size_t bp = 0;
            /* 1 local v128 */
            body[bp++] = 0x01; body[bp++] = 0x01; body[bp++] = 0x7B;
            /* Store initial data: i32.const 0, i32.const 0x41200000 (10.0f),
               i32.store */
            body[bp++] = 0x41; body[bp++] = 0x00; /* addr 0 */
            body[bp++] = 0x41;
            bp += write_u32_leb128(body + bp, 0x41200000);
            body[bp++] = 0x36; body[bp++] = 0x02; body[bp++] = 0x00;
            /* v128.load from addr 0, align=0, offset=0 */
            body[bp++] = 0x41; body[bp++] = 0x00; /* i32.const 0 (addr) */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x00); /* v128.load */
            body[bp++] = 0x02; body[bp++] = 0x00; /* align=2, offset=0 */
            body[bp++] = 0x21; body[bp++] = 0x00; /* local.set 0 */
            /* f32.const 2.0 → f32x4.splat */
            body[bp++] = 0x43;
            body[bp++] = 0x00; body[bp++] = 0x00;
            body[bp++] = 0x00; body[bp++] = 0x40; /* 2.0f */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x13); /* f32x4.splat */
            /* local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            /* f32x4.add */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xE4);
            /* f32x4.neg */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xE1);
            /* f32x4.abs */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xE0);
            /* v128.store at addr 0 */
            body[bp++] = 0x41; body[bp++] = 0x00; /* addr 0 */
            body[bp++] = 0x20; body[bp++] = 0x00; /* local.get 0 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0B); /* v128.store */
            body[bp++] = 0x02; body[bp++] = 0x00; /* align=2, offset=0 */
            /* v128.load8_splat */
            body[bp++] = 0x41; body[bp++] = 0x00;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x07); /* v128.load8_splat */
            body[bp++] = 0x00; body[bp++] = 0x00; /* align=0, offset=0 */
            /* v128.any_true → i32 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            /* drop */
            body[bp++] = 0x1A;
            /* v128.load32_splat */
            body[bp++] = 0x41; body[bp++] = 0x00;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x09); /* v128.load32_splat */
            body[bp++] = 0x02; body[bp++] = 0x00;
            /* f32x4.sqrt */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xE3);
            /* f32x4.extract_lane 0 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x1F);
            body[bp++] = 0x00; /* lane 0 */
            /* drop */
            body[bp++] = 0x1A;
            body[bp++] = 0x0B; /* end */

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bp);
            memcpy(code_buf + cc, body, bp);
            cc += bp;
            break;
        }
        case 3: {
            /*
             * i16x8 / i8x16 operations: narrow, extend, shift, saturating
             * arithmetic. Tests the packed integer SIMD paths.
             */
            uint8_t shift_amt = g_fdp->ConsumeIntegralInRange<uint8_t>(0, 7);
            uint8_t body[300];
            size_t bp = 0;
            /* 2 locals: v128, v128 */
            body[bp++] = 0x01; body[bp++] = 0x02; body[bp++] = 0x7B;
            /* i32.const 100 → i16x8.splat */
            body[bp++] = 0x41; body[bp++] = 0x64;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x10); /* i16x8.splat */
            body[bp++] = 0x21; body[bp++] = 0x00; /* local.set 0 */
            /* i32.const 50 → i16x8.splat */
            body[bp++] = 0x41; body[bp++] = 0x32;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x10);
            body[bp++] = 0x21; body[bp++] = 0x01; /* local.set 1 */
            /* local.get 0, local.get 1 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x20; body[bp++] = 0x01;
            /* i16x8.add */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x8E);
            /* local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            /* i16x8.sub */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x91);
            /* local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            /* i16x8.mul */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x95);
            /* i32.const shift_amt → i16x8.shl */
            body[bp++] = 0x41; body[bp++] = shift_amt;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x8B);
            /* i32.const shift_amt → i16x8.shr_u */
            body[bp++] = 0x41; body[bp++] = shift_amt;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x8D);
            body[bp++] = 0x21; body[bp++] = 0x00; /* local.set 0 */
            /* Saturating add: local.get 0, local.get 1, i16x8.add_sat_s */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x8F); /* i16x8.add_sat_s */
            /* local.get 1, i16x8.sub_sat_u */
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x93); /* i16x8.sub_sat_u */
            /* i16x8.abs */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x80);
            /* i16x8.neg */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x81);
            /* i16x8.bitmask → i32 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x84);
            /* drop */
            body[bp++] = 0x1A;
            /* Narrowing: local.get 0, local.get 1, i8x16.narrow_i16x8_s */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x65); /* i8x16.narrow_i16x8_s */
            /* i8x16.all_true → i32 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x63);
            /* drop */
            body[bp++] = 0x1A;
            /* Extend: local.get 0, i16x8.extend_low_i8x16_s */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x87);
            /* i16x8.all_true → i32 */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x83);
            /* drop */
            body[bp++] = 0x1A;
            body[bp++] = 0x0B; /* end */

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bp);
            memcpy(code_buf + cc, body, bp);
            cc += bp;
            break;
        }
        case 4: {
            /*
             * SIMD comparisons + shuffle + swizzle.
             * Tests comparison return values (v128 of all-1s or all-0s)
             * and the complex shuffle/swizzle lane reordering paths.
             */
            uint8_t shuffle_lanes[16];
            for (int i = 0; i < 16; i++)
                shuffle_lanes[i] = g_fdp->ConsumeIntegralInRange<uint8_t>(0, 31);

            uint8_t body[350];
            size_t bp = 0;
            /* 2 locals: v128 */
            body[bp++] = 0x01; body[bp++] = 0x02; body[bp++] = 0x7B;
            /* i32.const 10 → i32x4.splat → local.set 0 */
            body[bp++] = 0x41; body[bp++] = 0x0A;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x11);
            body[bp++] = 0x21; body[bp++] = 0x00;
            /* i32.const 20 → i32x4.splat → local.set 1 */
            body[bp++] = 0x41; body[bp++] = 0x14;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x11);
            body[bp++] = 0x21; body[bp++] = 0x01;
            /* i32x4.eq */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x37);
            /* v128.any_true → drop */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            body[bp++] = 0x1A;
            /* i32x4.lt_s */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x39);
            /* v128.any_true → drop */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            body[bp++] = 0x1A;
            /* f32x4 comparisons: splat 1.0 and 2.0 */
            body[bp++] = 0x43;
            body[bp++] = 0x00; body[bp++] = 0x00;
            body[bp++] = 0x80; body[bp++] = 0x3F; /* 1.0f */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x13); /* f32x4.splat */
            body[bp++] = 0x43;
            body[bp++] = 0x00; body[bp++] = 0x00;
            body[bp++] = 0x00; body[bp++] = 0x40; /* 2.0f */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x13);
            /* f32x4.lt */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x43);
            /* v128.any_true → drop */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            body[bp++] = 0x1A;
            /* v8x16.shuffle: local.get 0, local.get 1, shuffle with
             * 16 lane indices */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0D); /* v8x16.shuffle */
            memcpy(body + bp, shuffle_lanes, 16); bp += 16;
            /* v128.any_true → drop */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            body[bp++] = 0x1A;
            /* v8x16.swizzle: local.get 0 (data), i32.const 3 → i8x16.splat
             * (indices) */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x41; body[bp++] = 0x03;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0F); /* i8x16.splat */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x0E); /* v8x16.swizzle */
            /* v128.any_true → drop */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x53);
            body[bp++] = 0x1A;
            body[bp++] = 0x0B; /* end */

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bp);
            memcpy(code_buf + cc, body, bp);
            cc += bp;
            break;
        }
        case 5: {
            /*
             * f64x2 operations and conversions (trunc_sat, convert,
             * promote/demote).
             * Tests the floating-point SIMD paths and type conversion ops.
             */
            uint8_t body[350];
            size_t bp = 0;
            /* 2 locals: v128, v128 */
            body[bp++] = 0x01; body[bp++] = 0x02; body[bp++] = 0x7B;
            /* f64.const 3.14 → f64x2.splat → local.set 0 */
            body[bp++] = 0x44;
            /* 3.14 in little-endian double */
            body[bp++] = 0x1F; body[bp++] = 0x85; body[bp++] = 0xEB;
            body[bp++] = 0x51; body[bp++] = 0xB8; body[bp++] = 0x1E;
            body[bp++] = 0x09; body[bp++] = 0x40;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x14); /* f64x2.splat */
            body[bp++] = 0x21; body[bp++] = 0x00;
            /* f64.const 1.0 → f64x2.splat → local.set 1 */
            body[bp++] = 0x44;
            body[bp++] = 0x00; body[bp++] = 0x00; body[bp++] = 0x00;
            body[bp++] = 0x00; body[bp++] = 0x00; body[bp++] = 0x00;
            body[bp++] = 0xF0; body[bp++] = 0x3F;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x14);
            body[bp++] = 0x21; body[bp++] = 0x01;
            /* f64x2.add */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xF0);
            /* f64x2.sub */
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xF1);
            /* f64x2.mul */
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xF2);
            /* f64x2.div */
            body[bp++] = 0x20; body[bp++] = 0x01;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xF3);
            /* f64x2.neg */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xED);
            /* f64x2.abs */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xEC);
            /* f64x2.sqrt */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xEF);
            body[bp++] = 0x21; body[bp++] = 0x00; /* local.set 0 */
            /* f32x4.demote_f64x2_zero: local.get 0 */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x5E);
            /* f64x2.promote_low_f32x4_zero */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x5F);
            /* i32x4.trunc_sat_f64x2_s_zero */
            body[bp++] = 0x20; body[bp++] = 0x00;
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xFC);
            /* f64x2.convert_low_i32x4_s */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0xFE);
            /* f64x2.extract_lane 0 → drop */
            body[bp++] = 0xFD;
            bp += write_u32_leb128(body + bp, 0x21);
            body[bp++] = 0x00;
            body[bp++] = 0x1A;
            body[bp++] = 0x0B; /* end */

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bp);
            memcpy(code_buf + cc, body, bp);
            cc += bp;
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with multi-value returns.
 * Tests functions that return multiple values, which is an always-on feature
 * in WAMR but not explicitly tested by any existing harness.
 *
 * Targets bottlenecks in:
 *   wasm_interp_call_func_bytecode (multi-return handling),
 *   wasm_loader_prepare_bytecode (multi-value type validation)
 */
static void
harness_wasm_multi_value(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 2);

    switch (variant) {
        case 0: {
            /*
             * Function returning (i32, i32) - two i32 results.
             * _start calls helper, receives two values, adds them.
             */
            /* Type section: type0=()->(), type1=()->(i32,i32),
               type2=(i32,i32)->() */
            static const uint8_t type_body[] = {
                0x03,
                0x60, 0x00, 0x00,                   /* type 0: () -> () */
                0x60, 0x00, 0x02, 0x7F, 0x7F,       /* type 1: () -> (i32,i32) */
                0x60, 0x02, 0x7F, 0x7F, 0x00,       /* type 2: (i32,i32) -> () */
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            /* Function section: func0=type0 (_start), func1=type1 (helper) */
            static const uint8_t func_body[] = { 0x02, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));

            /* Memory section */
            static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x05,
                                      mem_body, sizeof(mem_body));

            /* Export: _start=func0, memory */
            static const uint8_t export_body[] = {
                0x02,
                0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
                0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x07,
                                      export_body, sizeof(export_body));

            /* Code section: 2 functions */
            uint8_t code_buf[256];
            size_t cc = 0;
            code_buf[cc++] = 0x02; /* 2 code entries */

            /* func0 (_start): call func1, get (i32,i32), add, drop */
            static const uint8_t body0[] = {
                0x00,                   /* 0 locals */
                0x10, 0x01,             /* call func1 */
                0x6A,                   /* i32.add (consumes both returns) */
                0x1A,                   /* drop */
                0x0B,                   /* end */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body0));
            memcpy(code_buf + cc, body0, sizeof(body0)); cc += sizeof(body0);

            /* func1: returns (i32.const 10, i32.const 20) */
            int32_t v1 = g_fdp->ConsumeIntegral<int8_t>();
            int32_t v2 = g_fdp->ConsumeIntegral<int8_t>();
            uint8_t body1[32];
            size_t b1p = 0;
            body1[b1p++] = 0x00; /* 0 locals */
            body1[b1p++] = 0x41;
            b1p += write_u32_leb128(body1 + b1p, (uint32_t)v1);
            body1[b1p++] = 0x41;
            b1p += write_u32_leb128(body1 + b1p, (uint32_t)v2);
            body1[b1p++] = 0x0B; /* end */
            cc += write_u32_leb128(code_buf + cc, (uint32_t)b1p);
            memcpy(code_buf + cc, body1, b1p); cc += b1p;

            off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
            break;
        }
        case 1: {
            /*
             * Block with multi-value: block returning (i32, i64).
             */
            static const uint8_t type_body[] = {
                0x02,
                0x60, 0x00, 0x00,                   /* type 0: () -> () */
                0x60, 0x00, 0x02, 0x7F, 0x7E,       /* type 1: () -> (i32, i64) */
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            static const uint8_t func_body[] = { 0x01, 0x00 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));

            static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x05,
                                      mem_body, sizeof(mem_body));

            static const uint8_t export_body[] = {
                0x02,
                0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
                0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x07,
                                      export_body, sizeof(export_body));

            int32_t v1 = g_fdp->ConsumeIntegral<int8_t>();
            int64_t v2 = g_fdp->ConsumeIntegral<int16_t>();

            uint8_t code_buf[128];
            size_t cc = 0;
            code_buf[cc++] = 0x01; /* 1 code entry */

            /*
             * _start: block (type 1) returning (i32, i64),
             * drop both values.
             */
            uint8_t body[64];
            size_t bp = 0;
            body[bp++] = 0x00; /* 0 locals */
            /* block with type index 1 → returns (i32, i64) */
            body[bp++] = 0x02; /* block */
            body[bp++] = 0x01; /* type index 1 (multi-value) */
            body[bp++] = 0x41; /* i32.const */
            bp += write_u32_leb128(body + bp, (uint32_t)v1);
            body[bp++] = 0x42; /* i64.const */
            /* signed LEB128 for i64 */
            bp += write_u32_leb128(body + bp, (uint32_t)(v2 & 0xFFFFFFFF));
            body[bp++] = 0x0B; /* end block */
            body[bp++] = 0x1A; /* drop (i64) */
            body[bp++] = 0x1A; /* drop (i32) */
            body[bp++] = 0x0B; /* end func */

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bp);
            memcpy(code_buf + cc, body, bp); cc += bp;

            off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
            break;
        }
        case 2: {
            /*
             * If/else with multi-value returns: if returns (f32, f32).
             */
            static const uint8_t type_body[] = {
                0x02,
                0x60, 0x00, 0x00,                         /* type 0: () -> () */
                0x60, 0x00, 0x02, 0x7D, 0x7D,             /* type 1: () -> (f32, f32) */
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            static const uint8_t func_body[] = { 0x01, 0x00 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));

            static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x05,
                                      mem_body, sizeof(mem_body));

            static const uint8_t export_body[] = {
                0x02,
                0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
                0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x07,
                                      export_body, sizeof(export_body));

            bool cond = g_fdp->ConsumeBool();

            uint8_t code_buf[128];
            size_t cc = 0;
            code_buf[cc++] = 0x01;

            static const uint8_t body_true[] = {
                0x00,                   /* 0 locals */
                0x41, 0x01,             /* i32.const 1 (condition=true) */
                0x04, 0x01,             /* if type_index=1 → returns (f32,f32) */
                0x43, 0x00, 0x00, 0x80, 0x3F, /* f32.const 1.0 */
                0x43, 0x00, 0x00, 0x00, 0x40, /* f32.const 2.0 */
                0x05,                   /* else */
                0x43, 0x00, 0x00, 0x40, 0x40, /* f32.const 3.0 */
                0x43, 0x00, 0x00, 0x80, 0x40, /* f32.const 4.0 */
                0x0B,                   /* end if */
                0x92,                   /* f32.add */
                0x1A,                   /* drop */
                0x0B,                   /* end func */
            };
            static const uint8_t body_false[] = {
                0x00,                   /* 0 locals */
                0x41, 0x00,             /* i32.const 0 (condition=false) */
                0x04, 0x01,             /* if type_index=1 → returns (f32,f32) */
                0x43, 0x00, 0x00, 0x80, 0x3F, /* f32.const 1.0 */
                0x43, 0x00, 0x00, 0x00, 0x40, /* f32.const 2.0 */
                0x05,                   /* else */
                0x43, 0x00, 0x00, 0x40, 0x40, /* f32.const 3.0 */
                0x43, 0x00, 0x00, 0x80, 0x40, /* f32.const 4.0 */
                0x0B,                   /* end if */
                0x92,                   /* f32.add */
                0x1A,                   /* drop */
                0x0B,                   /* end func */
            };

            const uint8_t *body = cond ? body_true : body_false;
            size_t bsz = cond ? sizeof(body_true) : sizeof(body_false);

            cc += write_u32_leb128(code_buf + cc, (uint32_t)bsz);
            memcpy(code_buf + cc, body, bsz); cc += bsz;

            off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
            break;
        }
    }

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module importing WASI functions from wasi_snapshot_preview1.
 * Exercises the WASI function resolution/linking path during instantiation.
 * When ecall_iwasm_main loads a module with WASI imports, the runtime links
 * them to builtin WASI implementations via wasm_runtime_init_wasi.
 *
 * Targets:
 *   wasm_runtime_init_wasi, WASI import resolution, libc_wasi linking
 */
static void
harness_wasm_wasi_imports(void)
{
    if (g_fdp->remaining_bytes() < 8)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 3);

    switch (variant) {
        case 0: {
            /* Import fd_write + proc_exit, call fd_write then proc_exit(0)
             * fd_write: (i32 fd, i32 iovs, i32 iovs_len, i32 nwritten) -> i32
             * proc_exit: (i32 exitcode) -> () */
            static const uint8_t type_body[] = {
                0x03,
                0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, /* (i32x4)->i32 */
                0x60, 0x01, 0x7F, 0x00,                           /* (i32)->() */
                0x60, 0x00, 0x00,                                  /* ()->() */
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            /* Import section: 2 imports from wasi_snapshot_preview1 */
            static const uint8_t imp_body[] = {
                0x02, /* 2 imports */
                /* import 0: wasi_snapshot_preview1.fd_write */
                0x19, /* module name len = 25 */
                'w','a','s','i','_','s','n','a','p','s','h','o','t',
                '_','p','r','e','v','i','e','w','1',
                0x08, 'f','d','_','w','r','i','t','e', /* field name */
                0x00, 0x00, /* kind=func, type_idx=0 */
                /* import 1: wasi_snapshot_preview1.proc_exit */
                0x19, /* module name len = 25 */
                'w','a','s','i','_','s','n','a','p','s','h','o','t',
                '_','p','r','e','v','i','e','w','1',
                0x09, 'p','r','o','c','_','e','x','i','t', /* field name */
                0x00, 0x01, /* kind=func, type_idx=1 */
            };
            off += write_wasm_section(mod + off, 0x02,
                                      imp_body, sizeof(imp_body));

            /* Function section: 1 defined function, type 2 */
            static const uint8_t func_body[] = { 0x01, 0x02 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));

            /* Memory section: min=1 */
            static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x05,
                                      mem_body, sizeof(mem_body));

            /* Export: memory + _start (func idx 2 = after 2 imports) */
            static const uint8_t export_body[] = {
                0x02,
                0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
                0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x02,
            };
            off += write_wasm_section(mod + off, 0x07,
                                      export_body, sizeof(export_body));

            /* Code: _start calls proc_exit(0) */
            static const uint8_t code_body[] = {
                0x01, /* 1 code entry */
                0x04, /* func body size */
                0x00, /* 0 locals */
                0x41, 0x00, /* i32.const 0 */
                0x10, 0x01, /* call $proc_exit (import idx 1) */
                /* unreachable after proc_exit, but end needed for validation */
            };
            /* Actually proc_exit is noreturn, but WASM still needs end opcode */
            uint8_t code_buf[16];
            size_t cb = 0;
            code_buf[cb++] = 0x01; /* 1 code entry */
            code_buf[cb++] = 0x05; /* body size = 5 */
            code_buf[cb++] = 0x00; /* 0 locals */
            code_buf[cb++] = 0x41; /* i32.const */
            code_buf[cb++] = 0x00; /* 0 */
            code_buf[cb++] = 0x10; /* call */
            code_buf[cb++] = 0x01; /* func idx 1 = proc_exit */
            code_buf[cb++] = 0x0B; /* end */
            off += write_wasm_section(mod + off, 0x0A, code_buf, cb);
            break;
        }
        case 1: {
            /* Import args_get + args_sizes_get
             * args_sizes_get: (i32, i32) -> i32
             * args_get: (i32, i32) -> i32 */
            static const uint8_t type_body[] = {
                0x02,
                0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, /* (i32,i32)->i32 */
                0x60, 0x00, 0x00,                     /* ()->() */
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            static const uint8_t imp_body[] = {
                0x02,
                0x19,
                'w','a','s','i','_','s','n','a','p','s','h','o','t',
                '_','p','r','e','v','i','e','w','1',
                0x0F, 'a','r','g','s','_','s','i','z','e','s','_','g','e','t',
                0x00, 0x00,
                0x19,
                'w','a','s','i','_','s','n','a','p','s','h','o','t',
                '_','p','r','e','v','i','e','w','1',
                0x08, 'a','r','g','s','_','g','e','t',
                0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x02,
                                      imp_body, sizeof(imp_body));

            static const uint8_t func_body[] = { 0x01, 0x01 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));

            static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x05,
                                      mem_body, sizeof(mem_body));

            /* Export _start (func idx 2) + memory */
            static const uint8_t export_body[] = {
                0x02,
                0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
                0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x02,
            };
            off += write_wasm_section(mod + off, 0x07,
                                      export_body, sizeof(export_body));

            /* _start: call args_sizes_get(0, 4), drop result */
            uint8_t code_buf[32];
            size_t cb = 0;
            code_buf[cb++] = 0x01;
            code_buf[cb++] = 0x09; /* body size */
            code_buf[cb++] = 0x00; /* 0 locals */
            code_buf[cb++] = 0x41; code_buf[cb++] = 0x00; /* i32.const 0 */
            code_buf[cb++] = 0x41; code_buf[cb++] = 0x04; /* i32.const 4 */
            code_buf[cb++] = 0x10; code_buf[cb++] = 0x00; /* call $args_sizes_get */
            code_buf[cb++] = 0x1A; /* drop */
            code_buf[cb++] = 0x0B; /* end */
            off += write_wasm_section(mod + off, 0x0A, code_buf, cb);
            break;
        }
        case 2: {
            /* Import fd_read: (i32, i32, i32, i32) -> i32 */
            static const uint8_t type_body[] = {
                0x02,
                0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F,
                0x60, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            static const uint8_t imp_body[] = {
                0x01,
                0x19,
                'w','a','s','i','_','s','n','a','p','s','h','o','t',
                '_','p','r','e','v','i','e','w','1',
                0x07, 'f','d','_','r','e','a','d',
                0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x02,
                                      imp_body, sizeof(imp_body));

            static const uint8_t func_body[] = { 0x01, 0x01 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));

            static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x05,
                                      mem_body, sizeof(mem_body));

            static const uint8_t export_body[] = {
                0x02,
                0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
                0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01,
            };
            off += write_wasm_section(mod + off, 0x07,
                                      export_body, sizeof(export_body));

            /* _start: just end */
            static const uint8_t code_body[] = {
                0x01, 0x02, 0x00, 0x0B
            };
            off += write_wasm_section(mod + off, 0x0A,
                                      code_body, sizeof(code_body));
            break;
        }
        case 3: {
            /* Import environ_get + environ_sizes_get */
            static const uint8_t type_body[] = {
                0x02,
                0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
                0x60, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            static const uint8_t imp_body[] = {
                0x02,
                0x19,
                'w','a','s','i','_','s','n','a','p','s','h','o','t',
                '_','p','r','e','v','i','e','w','1',
                0x13, 'e','n','v','i','r','o','n','_','s','i','z','e','s',
                '_','g','e','t',
                0x00, 0x00,
                0x19,
                'w','a','s','i','_','s','n','a','p','s','h','o','t',
                '_','p','r','e','v','i','e','w','1',
                0x0B, 'e','n','v','i','r','o','n','_','g','e','t',
                0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x02,
                                      imp_body, sizeof(imp_body));

            static const uint8_t func_body[] = { 0x01, 0x01 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));

            static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
            off += write_wasm_section(mod + off, 0x05,
                                      mem_body, sizeof(mem_body));

            static const uint8_t export_body[] = {
                0x02,
                0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
                0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x02,
            };
            off += write_wasm_section(mod + off, 0x07,
                                      export_body, sizeof(export_body));

            /* _start: call environ_sizes_get(0, 4), drop */
            uint8_t code_buf[32];
            size_t cb = 0;
            code_buf[cb++] = 0x01;
            code_buf[cb++] = 0x09;
            code_buf[cb++] = 0x00;
            code_buf[cb++] = 0x41; code_buf[cb++] = 0x00;
            code_buf[cb++] = 0x41; code_buf[cb++] = 0x04;
            code_buf[cb++] = 0x10; code_buf[cb++] = 0x00;
            code_buf[cb++] = 0x1A;
            code_buf[cb++] = 0x0B;
            off += write_wasm_section(mod + off, 0x0A, code_buf, cb);
            break;
        }
    }

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with deeply nested control flow.
 * Tests interpreter control flow stack with nested blocks/loops/ifs.
 *
 * Targets:
 *   wasm_interp_call_func_bytecode control flow handling,
 *   block stack management, br depth resolution
 */
static void
harness_wasm_deep_nested_flow(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 3);
    uint8_t code_buf[300];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /* block { block { block { br 1 } } } */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,   /* 1 local: i32 */
                0x02, 0x40,         /* block L0 */
                0x02, 0x40,         /* block L1 */
                0x02, 0x40,         /* block L2 */
                0x41, 0x01,         /* i32.const 1 */
                0x0D, 0x01,         /* br_if 1 -> L1 */
                0x41, 0x02,         /* i32.const 2 */
                0x21, 0x00,         /* local.set 0 */
                0x0B,               /* end L2 */
                0x0B,               /* end L1 */
                0x0B,               /* end L0 */
                0x0B,               /* end func */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* loop { if { br 1 } else { br 0 } } - loop with conditional exit */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,   /* 1 local: i32 */
                0x41, 0x05,         /* i32.const 5 */
                0x21, 0x00,         /* local.set 0 */
                0x03, 0x40,         /* loop L0 */
                0x20, 0x00,         /* local.get 0 */
                0x04, 0x40,         /* if */
                0x20, 0x00,         /* local.get 0 */
                0x41, 0x01,         /* i32.const 1 */
                0x6B,               /* i32.sub */
                0x21, 0x00,         /* local.set 0 */
                0x0C, 0x01,         /* br 1 -> loop L0 */
                0x05,               /* else */
                0x0C, 0x01,         /* br 1 -> exit loop */
                0x0B,               /* end if */
                0x0B,               /* end loop */
                0x0B,               /* end func */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 2: {
            /* Nested block-loop-block-if pattern */
            static const uint8_t body[] = {
                0x01, 0x01, 0x7F,   /* 1 local: i32 */
                0x02, 0x40,         /* block L0 */
                0x03, 0x40,         /* loop L1 */
                0x02, 0x40,         /* block L2 */
                0x20, 0x00,         /* local.get 0 */
                0x41, 0x03,         /* i32.const 3 */
                0x48,               /* i32.lt_u */
                0x04, 0x40,         /* if */
                0x20, 0x00,         /* local.get 0 */
                0x41, 0x01,         /* i32.const 1 */
                0x6A,               /* i32.add */
                0x21, 0x00,         /* local.set 0 */
                0x0C, 0x02,         /* br 2 -> loop L1 */
                0x0B,               /* end if */
                0x0B,               /* end L2 */
                0x0C, 0x01,         /* br 1 -> exit block L0 */
                0x0B,               /* end L1 */
                0x0B,               /* end L0 */
                0x0B,               /* end func */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 3: {
            /* 5-deep nested blocks with br at various depths */
            static const uint8_t body[] = {
                0x00,               /* 0 locals */
                0x02, 0x40,         /* block L0 */
                0x02, 0x40,         /* block L1 */
                0x02, 0x40,         /* block L2 */
                0x02, 0x40,         /* block L3 */
                0x02, 0x40,         /* block L4 */
                0x0C, 0x03,         /* br 3 -> L1 */
                0x0B,               /* end L4 */
                0x0C, 0x02,         /* br 2 -> L1 */
                0x0B,               /* end L3 */
                0x0B,               /* end L2 */
                0x0B,               /* end L1 */
                0x0B,               /* end L0 */
                0x0B,               /* end func */
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with multiple functions calling each other.
 * Exercises interpreter function call/return mechanism and stack frame mgmt.
 *
 * Targets:
 *   wasm_interp_call_func_bytecode call/return paths,
 *   function frame push/pop, multi-function modules
 */
static void
harness_wasm_inter_func_calls(void)
{
    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: 3 types
     * type0: () -> ()
     * type1: (i32) -> (i32)
     * type2: (i32, i32) -> (i32)
     */
    static const uint8_t type_body[] = {
        0x03,
        0x60, 0x00, 0x00,
        0x60, 0x01, 0x7F, 0x01, 0x7F,
        0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 3 functions (types 0, 1, 2) */
    static const uint8_t func_body[] = { 0x03, 0x00, 0x01, 0x02 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start(func 0) + add(func 2) */
    static const uint8_t export_body[] = {
        0x03,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
        0x03, 0x61, 0x64, 0x64, 0x00, 0x02,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: 3 functions
     * func0 (_start): calls func2(10, 20), calls func1(result), drops
     * func1 (identity): param0 * 2, return
     * func2 (add): param0 + param1, call func1(result), return
     */
    uint8_t code_buf[256];
    size_t cc = 0;
    code_buf[cc++] = 0x03; /* 3 code entries */

    /* func0: () -> () */
    static const uint8_t func0[] = {
        0x00,               /* 0 locals */
        0x41, 0x0A,         /* i32.const 10 */
        0x41, 0x14,         /* i32.const 20 */
        0x10, 0x02,         /* call func2 */
        0x10, 0x01,         /* call func1 */
        0x1A,               /* drop */
        0x0B,               /* end */
    };
    cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(func0));
    memcpy(code_buf + cc, func0, sizeof(func0));
    cc += sizeof(func0);

    /* func1: (i32) -> (i32) - double the param */
    static const uint8_t func1[] = {
        0x00,               /* 0 locals */
        0x20, 0x00,         /* local.get 0 */
        0x41, 0x02,         /* i32.const 2 */
        0x6C,               /* i32.mul */
        0x0B,               /* end */
    };
    cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(func1));
    memcpy(code_buf + cc, func1, sizeof(func1));
    cc += sizeof(func1);

    /* func2: (i32, i32) -> (i32) - add params, call func1 on result */
    static const uint8_t func2[] = {
        0x00,               /* 0 locals */
        0x20, 0x00,         /* local.get 0 */
        0x20, 0x01,         /* local.get 1 */
        0x6A,               /* i32.add */
        0x10, 0x01,         /* call func1 */
        0x0B,               /* end */
    };
    cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(func2));
    memcpy(code_buf + cc, func2, sizeof(func2));
    cc += sizeof(func2);

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Command workflow with full WASI configuration:
 * environment variables, address pools, and multiple directories.
 * Exercises deeper paths in handle_cmd_set_wasi_args.
 *
 * Targets:
 *   handle_cmd_set_wasi_args env_list/addr_pool paths,
 *   wasm_runtime_set_wasi_args_ex with env vars,
 *   wasm_runtime_set_wasi_addr_pool
 */
static void
harness_cmd_workflow_env_addr(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Step 1: Init runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        goto cleanup;

    /* Step 2: Load valid WASM module */
    {
        static const uint8_t valid_wasm[] = {
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00,
            0x05, 0x03, 0x01, 0x00, 0x01,
            0x07, 0x13, 0x02,
            0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
            0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
            0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B,
        };
        uint8_t *wasm_file = (uint8_t *)calloc(1, sizeof(valid_wasm));
        g_alloc_mgr.push_back(wasm_file);
        if (!wasm_file)
            goto cleanup;
        memcpy(wasm_file, valid_wasm, sizeof(valid_wasm));

        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)wasm_file;
        load_args[1] = (uint64_t)sizeof(valid_wasm);
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Step 3: Set WASI args with env vars and addr pool */
        {
            /* Directories */
            char *dir_str = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir_str);
            char **dir_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)dir_arr);

            /* Environment variables */
            char *env_str1 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)env_str1);
            char *env_str2 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)env_str2);
            char **env_arr = (char **)calloc(2, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)env_arr);

            /* Address pool */
            char *addr_str = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)addr_str);
            char **addr_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)addr_arr);

            /* Argv */
            char *argv_str = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv_str);
            char **argv_arr = (char **)calloc(1, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)argv_arr);

            if (dir_str && dir_arr && env_str1 && env_str2 && env_arr
                && addr_str && addr_arr && argv_str && argv_arr) {
                memcpy(dir_str, ".", 2);
                dir_arr[0] = dir_str;

                memcpy(env_str1, "HOME=/tmp", 10);
                memcpy(env_str2, "PATH=/bin", 10);
                env_arr[0] = env_str1;
                env_arr[1] = env_str2;

                memcpy(addr_str, "127.0.0.1", 10);
                addr_arr[0] = addr_str;

                memcpy(argv_str, "test", 5);
                argv_arr[0] = argv_str;

                uint64_t wasi_args[12];
                wasi_args[0] = (uint64_t)(uintptr_t)enclave_module;
                wasi_args[1] = (uint64_t)(uintptr_t)dir_arr;
                wasi_args[2] = 1;  /* dir_list_size */
                wasi_args[3] = (uint64_t)(uintptr_t)env_arr;
                wasi_args[4] = 2;  /* env_list_size */
                wasi_args[5] = 0;  /* stdinfd */
                wasi_args[6] = 1;  /* stdoutfd */
                wasi_args[7] = 2;  /* stderrfd */
                wasi_args[8] = (uint64_t)(uintptr_t)argv_arr;
                wasi_args[9] = 1;  /* wasi_argc */
                wasi_args[10] = (uint64_t)(uintptr_t)addr_arr;
                wasi_args[11] = 1; /* addr_pool_list_size */
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_SET_WASI_ARGS,
                                     (uint8_t *)wasi_args,
                                     sizeof(wasi_args));
            }
        }

        /* Step 4: Instantiate */
        memset(error_buf, 0, sizeof(error_buf));
        {
            uint64_t inst_args[5];
            inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
            inst_args[1] = (uint64_t)(32 * 1024);
            inst_args[2] = (uint64_t)(32 * 1024);
            inst_args[3] = (uint64_t)(uintptr_t)error_buf;
            inst_args[4] = (uint64_t)sizeof(error_buf);
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_INSTANTIATE_MODULE,
                                 (uint8_t *)inst_args, sizeof(inst_args));

            void *module_inst = (void *)(uintptr_t)inst_args[0];
            if (module_inst) {
                /* Step 5: Execute main */
                char *main_arg = (char *)calloc(1, 16);
                g_alloc_mgr.push_back((uint8_t *)main_arg);
                if (main_arg) {
                    memcpy(main_arg, "test", 5);
                    uint64_t exec_args[3];
                    exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                    exec_args[1] = 1;
                    exec_args[2] = (uint64_t)(uintptr_t)main_arg;
                    ecall_handle_command(__g_harness_eid,
                                         HARNESS_CMD_EXEC_APP_MAIN,
                                         (uint8_t *)exec_args,
                                         sizeof(exec_args));
                }

                /* Step 6: Deinstantiate */
                uint64_t deinst_args[1];
                deinst_args[0] = (uint64_t)(uintptr_t)module_inst;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_DEINSTANTIATE_MODULE,
                                     (uint8_t *)deinst_args,
                                     sizeof(deinst_args));
            }
        }

        /* Step 7: Unload */
        uint64_t unload_args[1];
        unload_args[0] = (uint64_t)(uintptr_t)enclave_module;
        ecall_handle_command(__g_harness_eid,
                             HARNESS_CMD_UNLOAD_MODULE,
                             (uint8_t *)unload_args, sizeof(unload_args));
    }

cleanup:
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * WASM with diverse memory load/store operations using different
 * alignments, offsets, and data widths (8/16/32/64 bit).
 *
 * Targets:
 *   Memory access handlers in interpreter,
 *   alignment checking, offset computation, bounds checking
 */
static void
harness_wasm_memory_diverse(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* 2 pages min for larger offsets */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x02 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 2);
    uint8_t code_buf[300];
    size_t cc = 0;
    code_buf[cc++] = 0x01;

    switch (variant) {
        case 0: {
            /* i32 store/load at different offsets and natural alignments */
            static const uint8_t body[] = {
                0x00,                       /* 0 locals */
                /* store i32 at offset 0, align=2 */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0xAA, 0xAA, 0x03,    /* i32.const 0xAAAA */
                0x36, 0x02, 0x00,           /* i32.store align=2 offset=0 */
                /* store i32 at offset 100, align=0 (unaligned) */
                0x41, 0x00,                 /* i32.const 0 */
                0x41, 0xBB, 0xBB, 0x03,    /* i32.const 0xBBBB */
                0x36, 0x00, 0x64,           /* i32.store align=0 offset=100 */
                /* load i32 from offset 0 */
                0x41, 0x00,
                0x28, 0x02, 0x00,           /* i32.load align=2 offset=0 */
                0x1A,                       /* drop */
                /* load i32 from offset 100 */
                0x41, 0x00,
                0x28, 0x00, 0x64,           /* i32.load align=0 offset=100 */
                0x1A,
                /* store8 + load8_s + load8_u */
                0x41, 0x00,
                0x41, 0xFF, 0x01,           /* i32.const 255 */
                0x3A, 0x00, 0xC8, 0x01,     /* i32.store8 offset=200 */
                0x41, 0x00,
                0x2C, 0x00, 0xC8, 0x01,     /* i32.load8_s offset=200 */
                0x1A,
                0x41, 0x00,
                0x2D, 0x00, 0xC8, 0x01,     /* i32.load8_u offset=200 */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* i64 and f32/f64 store/load */
            static const uint8_t body[] = {
                0x00,
                /* i64 store + load */
                0x41, 0x00,
                0x42, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, /* i64.const 0xFFFFFFFF */
                0x37, 0x03, 0x00,           /* i64.store align=3 offset=0 */
                0x41, 0x00,
                0x29, 0x03, 0x00,           /* i64.load align=3 offset=0 */
                0x1A,
                /* f32 store + load */
                0x41, 0x10,                 /* i32.const 16 */
                0x43, 0x00, 0x00, 0x80, 0x3F, /* f32.const 1.0 */
                0x38, 0x02, 0x00,           /* f32.store align=2 offset=0 */
                0x41, 0x10,
                0x2A, 0x02, 0x00,           /* f32.load align=2 offset=0 */
                0x1A,
                /* f64 store + load */
                0x41, 0x20,                 /* i32.const 32 */
                0x44, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xF0, 0x3F,     /* f64.const 1.0 */
                0x39, 0x03, 0x00,           /* f64.store align=3 offset=0 */
                0x41, 0x20,
                0x2B, 0x03, 0x00,           /* f64.load align=3 offset=0 */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 2: {
            /* i64 sub-word loads: load8/16/32 signed/unsigned */
            static const uint8_t body[] = {
                0x00,
                /* Store i64 value at addr 0 */
                0x41, 0x00,
                0x42, 0x80, 0x80, 0x80, 0x80, 0x78, /* i64.const -0x80000000 */
                0x37, 0x03, 0x00,
                /* i64.load8_s */
                0x41, 0x00,
                0x30, 0x00, 0x00,           /* i64.load8_s */
                0x1A,
                /* i64.load8_u */
                0x41, 0x00,
                0x31, 0x00, 0x00,           /* i64.load8_u */
                0x1A,
                /* i64.load16_s */
                0x41, 0x00,
                0x32, 0x01, 0x00,           /* i64.load16_s */
                0x1A,
                /* i64.load16_u */
                0x41, 0x00,
                0x33, 0x01, 0x00,           /* i64.load16_u */
                0x1A,
                /* i64.load32_s */
                0x41, 0x00,
                0x34, 0x02, 0x00,           /* i64.load32_s */
                0x1A,
                /* i64.load32_u */
                0x41, 0x00,
                0x35, 0x02, 0x00,           /* i64.load32_u */
                0x1A,
                /* i64.store8 */
                0x41, 0x08,
                0x42, 0xFF, 0x01,           /* i64.const 255 */
                0x3C, 0x00, 0x00,           /* i64.store8 */
                /* i64.store16 */
                0x41, 0x10,
                0x42, 0xFF, 0xFF, 0x03,     /* i64.const 0xFFFF */
                0x3D, 0x01, 0x00,           /* i64.store16 */
                /* i64.store32 */
                0x41, 0x18,
                0x42, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F,
                0x3E, 0x02, 0x00,           /* i64.store32 */
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * AOT file with structured init_data section.
 * Exercises deeper AOT loading paths beyond just target_info.
 *
 * Targets:
 *   aot_load_from_aot_file init_data section parsing,
 *   memory/table/type/function init data handling
 */
static void
harness_aot_init_data(void)
{
    if (g_fdp->remaining_bytes() < 32)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 8192);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;

    /* AOT magic */
    memcpy(mod, aot_magic_hdr, 4);
    off = 4;

    /* AOT version 2 */
    uint32_t aot_ver = 2;
    memcpy(mod + off, &aot_ver, 4);
    off += 4;

    /* Section 0: TARGET_INFO */
    {
        uint8_t target[64];
        size_t tb = 0;

        uint16_t bin_type = 0; /* ELF */
        memcpy(target + tb, &bin_type, 2); tb += 2;
        uint16_t abi_type = 5; /* Linux SGX */
        memcpy(target + tb, &abi_type, 2); tb += 2;
        uint16_t e_type = 1; /* ET_REL */
        memcpy(target + tb, &e_type, 2); tb += 2;
        uint16_t e_machine = 62; /* EM_X86_64 */
        memcpy(target + tb, &e_machine, 2); tb += 2;
        uint32_t e_version = 1;
        memcpy(target + tb, &e_version, 4); tb += 4;
        uint32_t e_flags = 0;
        memcpy(target + tb, &e_flags, 4); tb += 4;
        /* feature_flags: enable bulk_memory(bit0) + ref_types(bit7) */
        uint32_t features = g_fdp->ConsumeIntegral<uint32_t>();
        memcpy(target + tb, &features, 4); tb += 4;
        uint64_t reserved = 0;
        memcpy(target + tb, &reserved, 8); tb += 8;
        /* arch string */
        memset(target + tb, 0, 16);
        memcpy(target + tb, "x86_64", 6);
        tb += 16;

        uint32_t sec_type = 0;
        memcpy(mod + off, &sec_type, 4); off += 4;
        uint32_t sec_size = (uint32_t)tb;
        memcpy(mod + off, &sec_size, 4); off += 4;
        memcpy(mod + off, target, tb); off += tb;
    }

    /* Section 1: INIT_DATA - fuzzed content after proper header */
    {
        size_t init_data_size = g_fdp->ConsumeIntegralInRange<size_t>(16, 1024);
        if (init_data_size > g_fdp->remaining_bytes())
            init_data_size = g_fdp->remaining_bytes();
        if (init_data_size > 0 && off + 8 + init_data_size < 8192) {
            uint32_t sec_type = 1; /* AOT_SECTION_TYPE_INIT_DATA */
            memcpy(mod + off, &sec_type, 4); off += 4;
            uint32_t sec_size = (uint32_t)init_data_size;
            memcpy(mod + off, &sec_size, 4); off += 4;
            g_fdp->ConsumeData(mod + off, init_data_size);
            off += init_data_size;
        }
    }

    /* Optionally add more fuzzed sections */
    if (g_fdp->remaining_bytes() > 16) {
        /* Section 2: TEXT (fuzzed) */
        size_t text_size = g_fdp->ConsumeIntegralInRange<size_t>(4, 512);
        if (text_size > g_fdp->remaining_bytes())
            text_size = g_fdp->remaining_bytes();
        if (text_size > 0 && off + 8 + text_size < 8192) {
            uint32_t sec_type = 2; /* AOT_SECTION_TYPE_TEXT */
            memcpy(mod + off, &sec_type, 4); off += 4;
            uint32_t sec_size = (uint32_t)text_size;
            memcpy(mod + off, &sec_size, 4); off += 4;
            g_fdp->ConsumeData(mod + off, text_size);
            off += text_size;
        }
    }

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Comparison and branch opcodes: i32/i64/f32/f64 comparisons, eqz,
 * div, rem, shifts, clz, ctz, popcnt, nop, return, local.tee.
 *
 * These opcodes appear in the interpreter dispatch table but none of
 * the existing harnesses generate code that exercises them all.
 *
 * Targets:
 *   wasm_interp_call_func_bytecode (13% coverage) - comparison/logic handlers
 *   wasm_loader_prepare_bytecode (38%) - validation of these opcodes
 */
static void
harness_wasm_comparison_branch_ops(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    uint8_t code_buf[512];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 5);

    switch (variant) {
        case 0: {
            /* i32 comparisons: eq, ne, lt_s, lt_u, gt_s, gt_u,
             * le_s, le_u, ge_s, ge_u */
            static const uint8_t body[] = {
                0x00,                       /* 0 locals */
                0x41, 0x0A, 0x41, 0x14,     /* i32.const 10, 20 */
                0x46,                       /* i32.eq */
                0x1A,                       /* drop */
                0x41, 0x0A, 0x41, 0x14,
                0x47,                       /* i32.ne */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x48,                       /* i32.lt_s */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x49,                       /* i32.lt_u */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x4A,                       /* i32.gt_s */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x4B,                       /* i32.gt_u */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x4C,                       /* i32.le_s */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x4D,                       /* i32.le_u */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x4E,                       /* i32.ge_s */
                0x1A,
                0x41, 0x0A, 0x41, 0x14,
                0x4F,                       /* i32.ge_u */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 1: {
            /* nop, i32.eqz, div, rem, shr_s, rotr, clz, ctz, popcnt */
            static const uint8_t body[] = {
                0x00,
                0x01,                       /* nop */
                0x41, 0x2A,                 /* i32.const 42 */
                0x45,                       /* i32.eqz */
                0x1A,
                0x41, 0x64, 0x41, 0x07,     /* 100, 7 */
                0x6D,                       /* i32.div_s */
                0x1A,
                0x41, 0x64, 0x41, 0x07,
                0x6E,                       /* i32.div_u */
                0x1A,
                0x41, 0x64, 0x41, 0x07,
                0x6F,                       /* i32.rem_s */
                0x1A,
                0x41, 0x64, 0x41, 0x07,
                0x70,                       /* i32.rem_u */
                0x1A,
                0x41, 0x2A, 0x41, 0x03,
                0x75,                       /* i32.shr_s */
                0x1A,
                0x41, 0x2A, 0x41, 0x03,
                0x78,                       /* i32.rotr */
                0x1A,
                0x41, 0x2A,
                0x67,                       /* i32.clz */
                0x1A,
                0x41, 0x2A,
                0x68,                       /* i32.ctz */
                0x1A,
                0x41, 0x2A,
                0x69,                       /* i32.popcnt */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 2: {
            /* return, local.tee, local ops, i64.eqz */
            static const uint8_t body[] = {
                0x02, 0x01, 0x7F, 0x01, 0x7E,  /* 2 local groups: 1xi32, 1xi64 */
                0x41, 0x05,                 /* i32.const 5 */
                0x21, 0x00,                 /* local.set 0 */
                0x20, 0x00,                 /* local.get 0 */
                0x22, 0x00,                 /* local.tee 0 */
                0x1A,                       /* drop */
                0x42, 0x64,                 /* i64.const 100 */
                0x21, 0x01,                 /* local.set 1 */
                0x20, 0x01,                 /* local.get 1 */
                0x50,                       /* i64.eqz */
                0x1A,                       /* drop */
                0x0F,                       /* return */
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 3: {
            /* i64 comparisons: eq, ne, lt_s, lt_u, gt_s, gt_u,
             * le_s, le_u, ge_s, ge_u */
            static const uint8_t body[] = {
                0x00,
                0x42, 0x0A, 0x42, 0x14,     /* i64.const 10, 20 */
                0x51,                       /* i64.eq */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x52,                       /* i64.ne */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x53,                       /* i64.lt_s */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x54,                       /* i64.lt_u */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x55,                       /* i64.gt_s */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x56,                       /* i64.gt_u */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x57,                       /* i64.le_s */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x58,                       /* i64.le_u */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x59,                       /* i64.ge_s */
                0x1A,
                0x42, 0x0A, 0x42, 0x14,
                0x5A,                       /* i64.ge_u */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 4: {
            /* f32 comparisons: eq, ne, lt, gt, le, ge */
            static const uint8_t body[] = {
                0x00,
                0x43, 0x00, 0x00, 0xC0, 0x3F,  /* f32.const 1.5 */
                0x43, 0x00, 0x00, 0x20, 0x40,  /* f32.const 2.5 */
                0x5B,                       /* f32.eq */
                0x1A,
                0x43, 0x00, 0x00, 0xC0, 0x3F,
                0x43, 0x00, 0x00, 0x20, 0x40,
                0x5C,                       /* f32.ne */
                0x1A,
                0x43, 0x00, 0x00, 0xC0, 0x3F,
                0x43, 0x00, 0x00, 0x20, 0x40,
                0x5D,                       /* f32.lt */
                0x1A,
                0x43, 0x00, 0x00, 0xC0, 0x3F,
                0x43, 0x00, 0x00, 0x20, 0x40,
                0x5E,                       /* f32.gt */
                0x1A,
                0x43, 0x00, 0x00, 0xC0, 0x3F,
                0x43, 0x00, 0x00, 0x20, 0x40,
                0x5F,                       /* f32.le */
                0x1A,
                0x43, 0x00, 0x00, 0xC0, 0x3F,
                0x43, 0x00, 0x00, 0x20, 0x40,
                0x60,                       /* f32.ge */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
        case 5: {
            /* f64 comparisons: eq, ne, lt, gt, le, ge */
            static const uint8_t body[] = {
                0x00,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0xF8, 0x3F,  /* f64.const 1.5 */
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x04, 0x40,  /* f64.const 2.5 */
                0x61,                       /* f64.eq */
                0x1A,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0xF8, 0x3F,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x04, 0x40,
                0x62,                       /* f64.ne */
                0x1A,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0xF8, 0x3F,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x04, 0x40,
                0x63,                       /* f64.lt */
                0x1A,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0xF8, 0x3F,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x04, 0x40,
                0x64,                       /* f64.gt */
                0x1A,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0xF8, 0x3F,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x04, 0x40,
                0x65,                       /* f64.le */
                0x1A,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0xF8, 0x3F,
                0x44, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x04, 0x40,
                0x66,                       /* f64.ge */
                0x1A,
                0x0B,
            };
            cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
            memcpy(code_buf + cc, body, sizeof(body));
            cc += sizeof(body);
            break;
        }
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * UTF-8 diverse names: generates modules with multi-byte UTF-8 sequences
 * in export names and custom section names. Exercises all branches in
 * wasm_check_utf8_str (7% coverage).
 *
 * Targets:
 *   wasm_check_utf8_str - 2-byte, 3-byte, 4-byte UTF-8 validation paths
 *   wasm_const_str_list_insert (16%) - string constant handling
 *   load_export_section (30%) - export name parsing
 *   load_user_section (28%) - custom section name parsing
 */
static void
harness_wasm_utf8_diverse_names(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: () -> () */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 5);

    /* Build export section with UTF-8 names */
    uint8_t export_buf[256];
    size_t ec = 0;
    export_buf[ec++] = 0x02; /* 2 exports */

    /* Export 0: memory as "memory" */
    export_buf[ec++] = 0x06;
    memcpy(export_buf + ec, "memory", 6); ec += 6;
    export_buf[ec++] = 0x02; export_buf[ec++] = 0x00;

    /* Export 1: _start as a UTF-8 name */
    switch (variant) {
        case 0: {
            /* 2-byte UTF-8: U+00C4 "Ä" = C3 84 + ASCII suffix */
            uint8_t name[] = { 0xC3, 0x84, 0x73, 0x74 }; /* "Äst" */
            export_buf[ec++] = (uint8_t)sizeof(name);
            memcpy(export_buf + ec, name, sizeof(name)); ec += sizeof(name);
            break;
        }
        case 1: {
            /* 3-byte UTF-8: U+20AC "€" = E2 82 AC */
            uint8_t name[] = { 0xE2, 0x82, 0xAC };
            export_buf[ec++] = (uint8_t)sizeof(name);
            memcpy(export_buf + ec, name, sizeof(name)); ec += sizeof(name);
            break;
        }
        case 2: {
            /* 3-byte edge: 0xE0 prefix (second byte must be A0-BF) */
            uint8_t name[] = { 0xE0, 0xA0, 0x80 }; /* U+0800 */
            export_buf[ec++] = (uint8_t)sizeof(name);
            memcpy(export_buf + ec, name, sizeof(name)); ec += sizeof(name);
            break;
        }
        case 3: {
            /* 3-byte edge: 0xED prefix (second byte must be 80-9F) */
            uint8_t name[] = { 0xED, 0x9F, 0xBF }; /* U+D7FF (last valid) */
            export_buf[ec++] = (uint8_t)sizeof(name);
            memcpy(export_buf + ec, name, sizeof(name)); ec += sizeof(name);
            break;
        }
        case 4: {
            /* 4-byte UTF-8: 0xF0 prefix (second byte must be 90-BF) */
            uint8_t name[] = { 0xF0, 0x90, 0x80, 0x80 }; /* U+10000 */
            export_buf[ec++] = (uint8_t)sizeof(name);
            memcpy(export_buf + ec, name, sizeof(name)); ec += sizeof(name);
            break;
        }
        case 5: {
            /* 4-byte edge: 0xF4 prefix (second byte must be 80-8F) */
            uint8_t name[] = { 0xF4, 0x8F, 0xBF, 0xBF }; /* U+10FFFF */
            export_buf[ec++] = (uint8_t)sizeof(name);
            memcpy(export_buf + ec, name, sizeof(name)); ec += sizeof(name);
            break;
        }
    }
    export_buf[ec++] = 0x00; export_buf[ec++] = 0x00; /* func 0 */
    off += write_wasm_section(mod + off, 0x07, export_buf, ec);

    /* Code section: trivial function */
    static const uint8_t code_body[] = {
        0x01,               /* 1 code entry */
        0x02,               /* body size = 2 */
        0x00,               /* 0 locals */
        0x0B,               /* end */
    };
    off += write_wasm_section(mod + off, 0x0A, code_body, sizeof(code_body));

    /* Custom section with multi-byte UTF-8 name */
    uint8_t custom_buf[64];
    size_t cb = 0;
    switch (variant) {
        case 0: case 1: {
            /* 4-byte UTF-8 name in custom section: F1 80 80 80 */
            uint8_t cname[] = { 0xF1, 0x80, 0x80, 0x80 };
            custom_buf[cb++] = sizeof(cname);
            memcpy(custom_buf + cb, cname, sizeof(cname));
            cb += sizeof(cname);
            break;
        }
        case 2: case 3: {
            /* Mix of 2-byte and 3-byte */
            uint8_t cname[] = { 0xC3, 0xA9, 0xE1, 0x80, 0x80 }; /* éက */
            custom_buf[cb++] = sizeof(cname);
            memcpy(custom_buf + cb, cname, sizeof(cname));
            cb += sizeof(cname);
            break;
        }
        default: {
            /* ASCII custom section name */
            uint8_t cname[] = "test";
            custom_buf[cb++] = 4;
            memcpy(custom_buf + cb, cname, 4);
            cb += 4;
            break;
        }
    }
    /* Custom section data: small fuzz payload */
    size_t fuzz_len = g_fdp->ConsumeIntegralInRange<size_t>(0, 16);
    if (fuzz_len > 0 && g_fdp->remaining_bytes() >= fuzz_len) {
        g_fdp->ConsumeData(custom_buf + cb, fuzz_len);
        cb += fuzz_len;
    }
    off += write_wasm_section(mod + off, 0x00, custom_buf, cb);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASI ABI compatibility variants: generates modules with _start and/or
 * _initialize exports with correct or incorrect signatures, testing
 * check_wasi_abi_compatibility (25% coverage).
 *
 * Targets:
 *   check_wasi_abi_compatibility - _start/_initialize validation
 *   wasm_runtime_lookup_wasi_start_function (20%)
 *   execute_main (16%) - various entry point paths
 *   execute_post_instantiate_functions (37%)
 */
static void
harness_wasm_wasi_abi_check(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 4);

    /* Type section: multiple types for different signatures */
    static const uint8_t type_body[] = {
        0x03,                           /* 3 types */
        0x60, 0x00, 0x00,               /* type 0: () -> () */
        0x60, 0x01, 0x7F, 0x00,         /* type 1: (i32) -> () */
        0x60, 0x00, 0x01, 0x7F,         /* type 2: () -> (i32) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 2 functions */
    uint8_t func_sec[4];
    size_t fs = 0;
    switch (variant) {
        case 0: /* both funcs type 0: () -> () */
            func_sec[fs++] = 0x02;
            func_sec[fs++] = 0x00;
            func_sec[fs++] = 0x00;
            break;
        case 1: /* func0: (i32)->(), func1: ()->() - _start with wrong sig */
            func_sec[fs++] = 0x02;
            func_sec[fs++] = 0x01;
            func_sec[fs++] = 0x00;
            break;
        case 2: /* func0: ()->(i32), func1: ()->() - _start returns i32 */
            func_sec[fs++] = 0x02;
            func_sec[fs++] = 0x02;
            func_sec[fs++] = 0x00;
            break;
        case 3: /* 3 funcs: ()->(), ()->(), (i32)->() */
            func_sec[fs++] = 0x03;
            func_sec[fs++] = 0x00;
            func_sec[fs++] = 0x00;
            func_sec[fs++] = 0x01;
            break;
        default: /* 2 funcs both () -> () */
            func_sec[fs++] = 0x02;
            func_sec[fs++] = 0x00;
            func_sec[fs++] = 0x00;
            break;
    }
    off += write_wasm_section(mod + off, 0x03, func_sec, fs);

    /* Memory section: min=1 */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export section: varies by variant */
    uint8_t export_buf[128];
    size_t ec = 0;

    switch (variant) {
        case 0: {
            /* _start (correct ()->()) + _initialize (correct ()->()) */
            export_buf[ec++] = 0x03; /* 3 exports */
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "memory", 6);
            ec += 6; export_buf[ec++] = 0x02; export_buf[ec++] = 0x00;
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "_start", 6);
            ec += 6; export_buf[ec++] = 0x00; export_buf[ec++] = 0x00;
            export_buf[ec++] = 0x0B;
            memcpy(export_buf + ec, "_initialize", 11);
            ec += 11; export_buf[ec++] = 0x00; export_buf[ec++] = 0x01;
            break;
        }
        case 1: {
            /* _start with wrong sig (i32)->() */
            export_buf[ec++] = 0x02;
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "memory", 6);
            ec += 6; export_buf[ec++] = 0x02; export_buf[ec++] = 0x00;
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "_start", 6);
            ec += 6; export_buf[ec++] = 0x00; export_buf[ec++] = 0x00;
            break;
        }
        case 2: {
            /* Only _initialize (correct ()->()) */
            export_buf[ec++] = 0x02;
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "memory", 6);
            ec += 6; export_buf[ec++] = 0x02; export_buf[ec++] = 0x00;
            export_buf[ec++] = 0x0B;
            memcpy(export_buf + ec, "_initialize", 11);
            ec += 11; export_buf[ec++] = 0x00; export_buf[ec++] = 0x01;
            break;
        }
        case 3: {
            /* "main" export (alternative entry point) */
            export_buf[ec++] = 0x02;
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "memory", 6);
            ec += 6; export_buf[ec++] = 0x02; export_buf[ec++] = 0x00;
            export_buf[ec++] = 0x04; memcpy(export_buf + ec, "main", 4);
            ec += 4; export_buf[ec++] = 0x00; export_buf[ec++] = 0x00;
            break;
        }
        default: {
            /* _start only (correct) */
            export_buf[ec++] = 0x02;
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "memory", 6);
            ec += 6; export_buf[ec++] = 0x02; export_buf[ec++] = 0x00;
            export_buf[ec++] = 0x06; memcpy(export_buf + ec, "_start", 6);
            ec += 6; export_buf[ec++] = 0x00; export_buf[ec++] = 0x00;
            break;
        }
    }
    off += write_wasm_section(mod + off, 0x07, export_buf, ec);

    /* Code section: depends on variant */
    uint8_t code_buf[64];
    size_t cc = 0;
    int num_funcs = (variant == 3) ? 3 : 2;
    code_buf[cc++] = (uint8_t)num_funcs;
    for (int i = 0; i < num_funcs; i++) {
        code_buf[cc++] = 0x02; /* body size */
        code_buf[cc++] = 0x00; /* 0 locals */
        code_buf[cc++] = 0x0B; /* end */
    }
    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Memory configuration variants: tests different memory flags (shared,
 * has_max, no_max) and sizes to exercise memory instantiation paths.
 *
 * Targets:
 *   memory_instantiate (32%) - different memory configurations
 *   wasm_memory_check_flags (66%) - flag validation branches
 *   check_memory_init_size (50%) - size validation
 *   check_memory_max_size (40%) - max size validation
 *   wasm_shared_memory_init (50%) - shared memory initialization
 *   wasm_allocate_linear_memory (66%) - linear memory allocation
 */
static void
harness_wasm_memory_variants(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 4);

    /* Memory section with different configurations */
    uint8_t mem_buf[16];
    size_t mc = 0;
    mem_buf[mc++] = 0x01; /* 1 memory */

    switch (variant) {
        case 0:
            /* No max, min=0 */
            mem_buf[mc++] = 0x00; /* flags: no max */
            mem_buf[mc++] = 0x00; /* init=0 pages */
            break;
        case 1:
            /* Has max, min=2, max=10 */
            mem_buf[mc++] = 0x01; /* flags: has max */
            mem_buf[mc++] = 0x02; /* init=2 */
            mem_buf[mc++] = 0x0A; /* max=10 */
            break;
        case 2:
            /* Shared memory: flags=0x03 (has_max|shared), min=1, max=4 */
            mem_buf[mc++] = 0x03;
            mem_buf[mc++] = 0x01; /* init=1 */
            mem_buf[mc++] = 0x04; /* max=4 */
            break;
        case 3:
            /* Large initial: min=8, max=16 */
            mem_buf[mc++] = 0x01;
            mem_buf[mc++] = 0x08; /* init=8 */
            mem_buf[mc++] = 0x10; /* max=16 */
            break;
        case 4:
            /* Fuzzed min/max within valid bounds */
            mem_buf[mc++] = 0x01;
            mc += write_u32_leb128(mem_buf + mc,
                g_fdp->ConsumeIntegralInRange<uint32_t>(0, 16));
            mc += write_u32_leb128(mem_buf + mc,
                g_fdp->ConsumeIntegralInRange<uint32_t>(16, 64));
            break;
    }
    off += write_wasm_section(mod + off, 0x05, mem_buf, mc);

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: simple function that touches memory */
    uint8_t code_buf[64];
    size_t cc = 0;
    code_buf[cc++] = 0x01; /* 1 code entry */

    if (variant == 0) {
        /* With 0 pages, just return - can't access memory */
        static const uint8_t body[] = { 0x00, 0x0B };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }
    else {
        /* Store and load to exercise memory access */
        static const uint8_t body[] = {
            0x00,                       /* 0 locals */
            0x41, 0x00,                 /* i32.const 0 */
            0x41, 0x2A,                 /* i32.const 42 */
            0x36, 0x02, 0x00,           /* i32.store align=2 offset=0 */
            0x41, 0x00,                 /* i32.const 0 */
            0x28, 0x02, 0x00,           /* i32.load align=2 offset=0 */
            0x1A,                       /* drop */
            0x0B,
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }

    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);
    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Diverse init expressions: modules with globals initialized using various
 * init expression types (i32, i64, f32, f64, ref.null, ref.func).
 *
 * Targets:
 *   load_init_expr (16%) - init expression parsing
 *   load_global_section (30%) - global with different value types
 *   get_init_value_recursive (33%) - init value resolution
 *   globals_instantiate (54%) - global initialization during instantiation
 *   wasm_value_type_size_internal (30%) - value type size handling
 */
static void
harness_wasm_init_expr_types(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 3);

    /* Global section with diverse init expressions */
    uint8_t global_buf[128];
    size_t gc = 0;

    switch (variant) {
        case 0: {
            /* i32 + i64 globals */
            global_buf[gc++] = 0x02; /* 2 globals */
            /* global 0: mutable i32 = fuzzed value */
            global_buf[gc++] = 0x7F; /* i32 */
            global_buf[gc++] = 0x01; /* mutable */
            global_buf[gc++] = 0x41; /* i32.const */
            gc += write_u32_leb128(global_buf + gc,
                g_fdp->ConsumeIntegral<uint32_t>());
            global_buf[gc++] = 0x0B; /* end */
            /* global 1: mutable i64 = fuzzed value */
            global_buf[gc++] = 0x7E; /* i64 */
            global_buf[gc++] = 0x01; /* mutable */
            global_buf[gc++] = 0x42; /* i64.const */
            gc += write_u32_leb128(global_buf + gc,
                g_fdp->ConsumeIntegral<uint32_t>());
            global_buf[gc++] = 0x0B;
            break;
        }
        case 1: {
            /* f32 + f64 globals */
            global_buf[gc++] = 0x02; /* 2 globals */
            /* global 0: immutable f32 */
            global_buf[gc++] = 0x7D; /* f32 */
            global_buf[gc++] = 0x00; /* immutable */
            global_buf[gc++] = 0x43; /* f32.const */
            float fval = 3.14f;
            memcpy(global_buf + gc, &fval, 4); gc += 4;
            global_buf[gc++] = 0x0B;
            /* global 1: immutable f64 */
            global_buf[gc++] = 0x7C; /* f64 */
            global_buf[gc++] = 0x00; /* immutable */
            global_buf[gc++] = 0x44; /* f64.const */
            double dval = 2.71828;
            memcpy(global_buf + gc, &dval, 8); gc += 8;
            global_buf[gc++] = 0x0B;
            break;
        }
        case 2: {
            /* funcref global (ref.null + ref.func) */
            global_buf[gc++] = 0x02;
            /* global 0: funcref = ref.null funcref */
            global_buf[gc++] = 0x70; /* funcref */
            global_buf[gc++] = 0x01; /* mutable */
            global_buf[gc++] = 0xD0; /* ref.null */
            global_buf[gc++] = 0x70; /* funcref */
            global_buf[gc++] = 0x0B;
            /* global 1: funcref = ref.func 0 */
            global_buf[gc++] = 0x70; /* funcref */
            global_buf[gc++] = 0x00; /* immutable */
            global_buf[gc++] = 0xD2; /* ref.func */
            global_buf[gc++] = 0x00; /* func index 0 */
            global_buf[gc++] = 0x0B;
            break;
        }
        case 3: {
            /* externref global (ref.null externref) + i32 */
            global_buf[gc++] = 0x02;
            /* global 0: externref = ref.null externref */
            global_buf[gc++] = 0x6F; /* externref */
            global_buf[gc++] = 0x01; /* mutable */
            global_buf[gc++] = 0xD0; /* ref.null */
            global_buf[gc++] = 0x6F; /* externref */
            global_buf[gc++] = 0x0B;
            /* global 1: i32 = 0 */
            global_buf[gc++] = 0x7F; /* i32 */
            global_buf[gc++] = 0x00; /* immutable */
            global_buf[gc++] = 0x41; global_buf[gc++] = 0x00;
            global_buf[gc++] = 0x0B;
            break;
        }
    }
    off += write_wasm_section(mod + off, 0x06, global_buf, gc);

    /* Export: memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code section: function that reads globals */
    uint8_t code_buf[64];
    size_t cc = 0;
    code_buf[cc++] = 0x01;

    if (variant <= 1) {
        /* Read numeric globals */
        static const uint8_t body[] = {
            0x00,
            0x23, 0x00,         /* global.get 0 */
            0x1A,               /* drop */
            0x23, 0x01,         /* global.get 1 */
            0x1A,               /* drop */
            0x0B,
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }
    else {
        /* Read ref globals - use ref.is_null */
        static const uint8_t body[] = {
            0x00,
            0x23, 0x00,         /* global.get 0 */
            0xD1,               /* ref.is_null */
            0x1A,               /* drop */
            0x0B,
        };
        cc += write_u32_leb128(code_buf + cc, (uint32_t)sizeof(body));
        memcpy(code_buf + cc, body, sizeof(body));
        cc += sizeof(body);
    }
    off += write_wasm_section(mod + off, 0x0A, code_buf, cc);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * Import section with properly linked WASI functions. Tests that modules
 * with WASI imports successfully link and can be instantiated with WASI.
 *
 * Targets:
 *   load_import_section (3%) - import parsing with valid format
 *   check_linked_symbol (18%) - symbol linking (WASI functions link natively)
 *   wasm_runtime_init_wasi (2%) - WASI environment initialization
 *   check_wasi_abi_compatibility (25%) - WASI ABI checking
 *   copy_string_array (26%) - string array processing in WASI init
 *   fd_table_init, fd_prestats_init - WASI file descriptor tables
 */
static void
harness_wasm_import_link_wasi(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 8192);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 3);

    /* Type section */
    uint8_t type_buf[64];
    size_t tc = 0;

    switch (variant) {
        case 0: {
            /* 2 types: (i32,i32,i32,i32)->i32 [fd_write], ()->() [_start] */
            type_buf[tc++] = 0x02;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x04; /* 4 params */
            type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F; /* -> i32 */
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x00; type_buf[tc++] = 0x00; /* () -> () */
            break;
        }
        case 1: {
            /* 2 types: (i32)->() [proc_exit], ()->() */
            type_buf[tc++] = 0x02;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x00; /* (i32) -> () */
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x00; type_buf[tc++] = 0x00;
            break;
        }
        case 2: {
            /* 3 types: fd_write, proc_exit, ()->() */
            type_buf[tc++] = 0x03;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x04;
            type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x00;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x00; type_buf[tc++] = 0x00;
            break;
        }
        case 3: {
            /* 3 types for fd_read: (i32,i32,i32,i32)->i32, (i32,i32)->i32, ()->() */
            type_buf[tc++] = 0x03;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x04;
            type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x02; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x00; type_buf[tc++] = 0x00;
            break;
        }
    }
    off += write_wasm_section(mod + off, 0x01, type_buf, tc);

    /* Import section */
    static const char wasi_mod[] = "wasi_snapshot_preview1";
    size_t wasi_mod_len = sizeof(wasi_mod) - 1; /* 22 bytes */

    uint8_t import_buf[256];
    size_t ic = 0;

    switch (variant) {
        case 0: {
            /* Import fd_write from wasi */
            import_buf[ic++] = 0x01; /* 1 import */
            ic += write_u32_leb128(import_buf + ic, (uint32_t)wasi_mod_len);
            memcpy(import_buf + ic, wasi_mod, wasi_mod_len);
            ic += wasi_mod_len;
            static const char fn[] = "fd_write";
            import_buf[ic++] = sizeof(fn) - 1;
            memcpy(import_buf + ic, fn, sizeof(fn) - 1);
            ic += sizeof(fn) - 1;
            import_buf[ic++] = 0x00; /* kind: func */
            import_buf[ic++] = 0x00; /* type index 0 */
            break;
        }
        case 1: {
            /* Import proc_exit */
            import_buf[ic++] = 0x01;
            ic += write_u32_leb128(import_buf + ic, (uint32_t)wasi_mod_len);
            memcpy(import_buf + ic, wasi_mod, wasi_mod_len);
            ic += wasi_mod_len;
            static const char fn[] = "proc_exit";
            import_buf[ic++] = sizeof(fn) - 1;
            memcpy(import_buf + ic, fn, sizeof(fn) - 1);
            ic += sizeof(fn) - 1;
            import_buf[ic++] = 0x00;
            import_buf[ic++] = 0x00;
            break;
        }
        case 2: {
            /* Import fd_write + proc_exit */
            import_buf[ic++] = 0x02;
            /* fd_write */
            ic += write_u32_leb128(import_buf + ic, (uint32_t)wasi_mod_len);
            memcpy(import_buf + ic, wasi_mod, wasi_mod_len);
            ic += wasi_mod_len;
            { static const char fn[] = "fd_write";
              import_buf[ic++] = sizeof(fn) - 1;
              memcpy(import_buf + ic, fn, sizeof(fn) - 1);
              ic += sizeof(fn) - 1; }
            import_buf[ic++] = 0x00;
            import_buf[ic++] = 0x00;
            /* proc_exit */
            ic += write_u32_leb128(import_buf + ic, (uint32_t)wasi_mod_len);
            memcpy(import_buf + ic, wasi_mod, wasi_mod_len);
            ic += wasi_mod_len;
            { static const char fn[] = "proc_exit";
              import_buf[ic++] = sizeof(fn) - 1;
              memcpy(import_buf + ic, fn, sizeof(fn) - 1);
              ic += sizeof(fn) - 1; }
            import_buf[ic++] = 0x00;
            import_buf[ic++] = 0x01;
            break;
        }
        case 3: {
            /* Import fd_read + args_sizes_get */
            import_buf[ic++] = 0x02;
            ic += write_u32_leb128(import_buf + ic, (uint32_t)wasi_mod_len);
            memcpy(import_buf + ic, wasi_mod, wasi_mod_len);
            ic += wasi_mod_len;
            { static const char fn[] = "fd_read";
              import_buf[ic++] = sizeof(fn) - 1;
              memcpy(import_buf + ic, fn, sizeof(fn) - 1);
              ic += sizeof(fn) - 1; }
            import_buf[ic++] = 0x00;
            import_buf[ic++] = 0x00;
            ic += write_u32_leb128(import_buf + ic, (uint32_t)wasi_mod_len);
            memcpy(import_buf + ic, wasi_mod, wasi_mod_len);
            ic += wasi_mod_len;
            { static const char fn[] = "args_sizes_get";
              import_buf[ic++] = sizeof(fn) - 1;
              memcpy(import_buf + ic, fn, sizeof(fn) - 1);
              ic += sizeof(fn) - 1; }
            import_buf[ic++] = 0x00;
            import_buf[ic++] = 0x01;
            break;
        }
    }
    off += write_wasm_section(mod + off, 0x02, import_buf, ic);

    /* Function section: 1 local function (after imports) */
    uint8_t fsec[] = { 0x01 };
    switch (variant) {
        case 0: fsec[0] = 0x01; break;
        case 1: fsec[0] = 0x01; break;
        case 2: {
            static const uint8_t f[] = { 0x01, 0x02 };
            off += write_wasm_section(mod + off, 0x03, f, sizeof(f));
            goto after_func_sec;
        }
        case 3: {
            static const uint8_t f[] = { 0x01, 0x02 };
            off += write_wasm_section(mod + off, 0x03, f, sizeof(f));
            goto after_func_sec;
        }
    }
    {
        uint8_t ftype = (variant <= 1) ? 0x01 : 0x02;
        uint8_t f[] = { 0x01, ftype };
        off += write_wasm_section(mod + off, 0x03, f, sizeof(f));
    }
after_func_sec:

    /* Memory section: min=1 */
    static const uint8_t mbody[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mbody, sizeof(mbody));

    /* Export: memory + _start */
    uint8_t ebuf[64];
    size_t eoff = 0;
    ebuf[eoff++] = 0x02;
    ebuf[eoff++] = 0x06; memcpy(ebuf + eoff, "memory", 6); eoff += 6;
    ebuf[eoff++] = 0x02; ebuf[eoff++] = 0x00;
    ebuf[eoff++] = 0x06; memcpy(ebuf + eoff, "_start", 6); eoff += 6;
    ebuf[eoff++] = 0x00;
    /* _start function index = import_count + 0 */
    int import_count = (variant == 2 || variant == 3) ? 2 : 1;
    eoff += write_u32_leb128(ebuf + eoff, (uint32_t)import_count);
    off += write_wasm_section(mod + off, 0x07, ebuf, eoff);

    /* Code section: trivial _start */
    static const uint8_t cbody[] = {
        0x01, 0x02, 0x00, 0x0B
    };
    off += write_wasm_section(mod + off, 0x0A, cbody, sizeof(cbody));

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASI imports combined with command pipeline WASI args.
 * Key insight: existing harnesses either use WASI imports via ecall_iwasm_main
 * (which never calls set_wasi_args) or set WASI args on modules without WASI
 * imports. This harness combines both: a WASM module with real WASI imports
 * loaded and instantiated through the command pipeline with full WASI args
 * (dir_list, env, argv, addr_pool).
 *
 * Targets:
 *   wasm_runtime_init_wasi (2% -> deeper paths), copy_string_array (26%),
 *   fd_table_init (66%), fd_prestats_init (66%), fd_table_insert_existing (37%),
 *   fd_determine_type_rights (21%), fd_object_new (66%),
 *   check_linked_symbol (36%), wasm_native_resolve_symbol (43%)
 */
static void
harness_wasi_import_cmd_workflow(void)
{
    if (g_fdp->remaining_bytes() < 16)
        return;

    char error_buf[128];
    memset(error_buf, 0, sizeof(error_buf));

    /* Step 1: Init runtime */
    uint64_t init_args[1];
    init_args[0] = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_INIT_RUNTIME,
                         (uint8_t *)init_args, sizeof(init_args));
    if (!init_args[0])
        goto cleanup;

    /* Step 2: Build WASM with WASI imports */
    {
        uint8_t *mod = (uint8_t *)calloc(1, 4096);
        g_alloc_mgr.push_back(mod);
        if (!mod)
            goto cleanup;

        size_t off = 0;
        memcpy(mod, wasm_magic_hdr, 8);
        off = 8;

        int variant = g_fdp->ConsumeIntegralInRange<int>(0, 2);

        if (variant == 0) {
            /* fd_write + proc_exit */
            static const uint8_t type_body[] = {
                0x03,
                0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F,
                0x60, 0x01, 0x7F, 0x00,
                0x60, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            uint8_t imp[128];
            size_t ic = 0;
            imp[ic++] = 0x02; /* 2 imports */
            /* fd_write */
            imp[ic++] = 0x19;
            memcpy(imp + ic, "wasi_snapshot_preview1", 22); ic += 22;
            imp[ic++] = 0x08;
            memcpy(imp + ic, "fd_write", 8); ic += 8;
            imp[ic++] = 0x00; imp[ic++] = 0x00;
            /* proc_exit */
            imp[ic++] = 0x19;
            memcpy(imp + ic, "wasi_snapshot_preview1", 22); ic += 22;
            imp[ic++] = 0x09;
            memcpy(imp + ic, "proc_exit", 9); ic += 9;
            imp[ic++] = 0x00; imp[ic++] = 0x01;
            off += write_wasm_section(mod + off, 0x02, imp, ic);

            static const uint8_t func_body[] = { 0x01, 0x02 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));
        }
        else if (variant == 1) {
            /* fd_read + fd_close + args_sizes_get + args_get */
            static const uint8_t type_body[] = {
                0x04,
                0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F,
                0x60, 0x01, 0x7F, 0x01, 0x7F,
                0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
                0x60, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            uint8_t imp[256];
            size_t ic = 0;
            imp[ic++] = 0x04; /* 4 imports */
            static const char *names[] = { "fd_read", "fd_close",
                                           "args_sizes_get", "args_get" };
            uint8_t type_idxs[] = { 0x00, 0x01, 0x02, 0x02 };
            for (int i = 0; i < 4; i++) {
                imp[ic++] = 0x19;
                memcpy(imp + ic, "wasi_snapshot_preview1", 22); ic += 22;
                size_t nlen = strlen(names[i]);
                ic += write_u32_leb128(imp + ic, (uint32_t)nlen);
                memcpy(imp + ic, names[i], nlen); ic += nlen;
                imp[ic++] = 0x00;
                imp[ic++] = type_idxs[i];
            }
            off += write_wasm_section(mod + off, 0x02, imp, ic);

            static const uint8_t func_body[] = { 0x01, 0x03 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));
        }
        else {
            /* environ_get + environ_sizes_get + fd_write + fd_prestat_get */
            static const uint8_t type_body[] = {
                0x03,
                0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
                0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F,
                0x60, 0x00, 0x00,
            };
            off += write_wasm_section(mod + off, 0x01,
                                      type_body, sizeof(type_body));

            uint8_t imp[256];
            size_t ic = 0;
            imp[ic++] = 0x04; /* 4 imports */
            static const char *names[] = { "environ_get", "environ_sizes_get",
                                           "fd_write", "fd_prestat_get" };
            uint8_t type_idxs[] = { 0x00, 0x00, 0x01, 0x00 };
            for (int i = 0; i < 4; i++) {
                imp[ic++] = 0x19;
                memcpy(imp + ic, "wasi_snapshot_preview1", 22); ic += 22;
                size_t nlen = strlen(names[i]);
                ic += write_u32_leb128(imp + ic, (uint32_t)nlen);
                memcpy(imp + ic, names[i], nlen); ic += nlen;
                imp[ic++] = 0x00;
                imp[ic++] = type_idxs[i];
            }
            off += write_wasm_section(mod + off, 0x02, imp, ic);

            static const uint8_t func_body[] = { 0x01, 0x02 };
            off += write_wasm_section(mod + off, 0x03,
                                      func_body, sizeof(func_body));
        }

        /* Memory section: min=1 */
        static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
        off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

        /* Export memory + _start */
        uint8_t ebuf[64];
        size_t eoff = 0;
        ebuf[eoff++] = 0x02;
        ebuf[eoff++] = 0x06;
        memcpy(ebuf + eoff, "memory", 6); eoff += 6;
        ebuf[eoff++] = 0x02; ebuf[eoff++] = 0x00;
        ebuf[eoff++] = 0x06;
        memcpy(ebuf + eoff, "_start", 6); eoff += 6;
        ebuf[eoff++] = 0x00;
        int nimp = (variant == 0) ? 2 : 4;
        eoff += write_u32_leb128(ebuf + eoff, (uint32_t)nimp);
        off += write_wasm_section(mod + off, 0x07, ebuf, eoff);

        /* Code: trivial _start: just end */
        static const uint8_t code_body[] = {
            0x01, 0x02, 0x00, 0x0B
        };
        off += write_wasm_section(mod + off, 0x0A,
                                  code_body, sizeof(code_body));

        /* Load module */
        uint64_t load_args[4];
        load_args[0] = (uint64_t)(uintptr_t)mod;
        load_args[1] = (uint64_t)off;
        load_args[2] = (uint64_t)(uintptr_t)error_buf;
        load_args[3] = (uint64_t)sizeof(error_buf);
        ecall_handle_command(__g_harness_eid, HARNESS_CMD_LOAD_MODULE,
                             (uint8_t *)load_args, sizeof(load_args));

        void *enclave_module = (void *)(uintptr_t)load_args[0];
        if (!enclave_module)
            goto cleanup;

        /* Step 3: Set comprehensive WASI args */
        {
            char *dir1 = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir1);
            char *dir2 = (char *)calloc(1, 8);
            g_alloc_mgr.push_back((uint8_t *)dir2);
            char **dir_arr = (char **)calloc(2, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)dir_arr);

            char *argv0 = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv0);
            char *argv1 = (char *)calloc(1, 16);
            g_alloc_mgr.push_back((uint8_t *)argv1);
            char **argv_arr = (char **)calloc(2, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)argv_arr);

            char *env0 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)env0);
            char *env1 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)env1);
            char *env2 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)env2);
            char **env_arr = (char **)calloc(3, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)env_arr);

            char *addr0 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)addr0);
            char *addr1 = (char *)calloc(1, 32);
            g_alloc_mgr.push_back((uint8_t *)addr1);
            char **addr_arr = (char **)calloc(2, sizeof(char *));
            g_alloc_mgr.push_back((uint8_t *)addr_arr);

            if (dir1 && dir2 && dir_arr && argv0 && argv1 && argv_arr
                && env0 && env1 && env2 && env_arr && addr0 && addr1
                && addr_arr) {
                memcpy(dir1, ".", 2);
                memcpy(dir2, "/tmp", 5);
                dir_arr[0] = dir1;
                dir_arr[1] = dir2;

                memcpy(argv0, "test.wasm", 10);
                memcpy(argv1, "--verbose", 10);
                argv_arr[0] = argv0;
                argv_arr[1] = argv1;

                memcpy(env0, "HOME=/tmp", 10);
                memcpy(env1, "PATH=/usr/bin", 14);
                memcpy(env2, "LANG=C", 7);
                env_arr[0] = env0;
                env_arr[1] = env1;
                env_arr[2] = env2;

                memcpy(addr0, "127.0.0.1", 10);
                memcpy(addr1, "0.0.0.0/0", 10);
                addr_arr[0] = addr0;
                addr_arr[1] = addr1;

                uint64_t wasi_args[12];
                wasi_args[0] = (uint64_t)(uintptr_t)enclave_module;
                wasi_args[1] = (uint64_t)(uintptr_t)dir_arr;
                wasi_args[2] = 2;  /* dir_list_size */
                wasi_args[3] = (uint64_t)(uintptr_t)env_arr;
                wasi_args[4] = 3;  /* env_list_size */
                wasi_args[5] = 0;  /* stdinfd */
                wasi_args[6] = 1;  /* stdoutfd */
                wasi_args[7] = 2;  /* stderrfd */
                wasi_args[8] = (uint64_t)(uintptr_t)argv_arr;
                wasi_args[9] = 2;  /* wasi_argc */
                wasi_args[10] = (uint64_t)(uintptr_t)addr_arr;
                wasi_args[11] = 2; /* addr_pool_list_size */
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_SET_WASI_ARGS,
                                     (uint8_t *)wasi_args,
                                     sizeof(wasi_args));
            }
        }

        /* Step 4: Instantiate */
        memset(error_buf, 0, sizeof(error_buf));
        {
            uint64_t inst_args[5];
            inst_args[0] = (uint64_t)(uintptr_t)enclave_module;
            inst_args[1] = (uint64_t)(32 * 1024);
            inst_args[2] = (uint64_t)(32 * 1024);
            inst_args[3] = (uint64_t)(uintptr_t)error_buf;
            inst_args[4] = (uint64_t)sizeof(error_buf);
            ecall_handle_command(__g_harness_eid,
                                 HARNESS_CMD_INSTANTIATE_MODULE,
                                 (uint8_t *)inst_args, sizeof(inst_args));

            void *module_inst = (void *)(uintptr_t)inst_args[0];
            if (module_inst) {
                /* Step 5: Execute main */
                char *main_arg = (char *)calloc(1, 16);
                g_alloc_mgr.push_back((uint8_t *)main_arg);
                if (main_arg) {
                    memcpy(main_arg, "test.wasm", 10);
                    uint64_t exec_args[3];
                    exec_args[0] = (uint64_t)(uintptr_t)module_inst;
                    exec_args[1] = 1;
                    exec_args[2] = (uint64_t)(uintptr_t)main_arg;
                    ecall_handle_command(__g_harness_eid,
                                         HARNESS_CMD_EXEC_APP_MAIN,
                                         (uint8_t *)exec_args,
                                         sizeof(exec_args));
                }

                /* Get exception */
                char exc_buf[128];
                memset(exc_buf, 0, sizeof(exc_buf));
                uint64_t exc_args[3];
                exc_args[0] = (uint64_t)(uintptr_t)module_inst;
                exc_args[1] = (uint64_t)(uintptr_t)exc_buf;
                exc_args[2] = (uint64_t)sizeof(exc_buf);
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_GET_EXCEPTION,
                                     (uint8_t *)exc_args,
                                     sizeof(exc_args));

                /* Deinstantiate */
                uint64_t deinst_args[1];
                deinst_args[0] = (uint64_t)(uintptr_t)module_inst;
                ecall_handle_command(__g_harness_eid,
                                     HARNESS_CMD_DEINSTANTIATE_MODULE,
                                     (uint8_t *)deinst_args,
                                     sizeof(deinst_args));
            }
        }

        /* Unload */
        uint64_t unload_args[1];
        unload_args[0] = (uint64_t)(uintptr_t)enclave_module;
        ecall_handle_command(__g_harness_eid,
                             HARNESS_CMD_UNLOAD_MODULE,
                             (uint8_t *)unload_args, sizeof(unload_args));
    }

cleanup:
    ecall_handle_command(__g_harness_eid, HARNESS_CMD_DESTROY_RUNTIME,
                         NULL, 0);
}

/*
 * WASM module with memory import to test load_memory_import paths.
 * Normal WASM modules define their own memory; importing memory from
 * another module exercises a completely different code path in the loader.
 *
 * Targets:
 *   load_memory_import (18%), load_import_section (31%),
 *   wasm_memory_check_flags (66%), check_memory_init_size (50%),
 *   check_memory_max_size (40%)
 */
static void
harness_wasm_memory_import_module(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section: ()->() */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Import section with memory import */
    uint8_t imp[128];
    size_t ic = 0;

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 3);

    switch (variant) {
        case 0: {
            /* Import memory with min only (no max) */
            imp[ic++] = 0x01; /* 1 import */
            imp[ic++] = 0x03; memcpy(imp + ic, "env", 3); ic += 3;
            imp[ic++] = 0x06; memcpy(imp + ic, "memory", 6); ic += 6;
            imp[ic++] = 0x02; /* kind: memory */
            imp[ic++] = 0x00; /* flags: no max */
            uint32_t min_pages = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 10);
            ic += write_u32_leb128(imp + ic, min_pages);
            break;
        }
        case 1: {
            /* Import memory with min and max */
            imp[ic++] = 0x01;
            imp[ic++] = 0x03; memcpy(imp + ic, "env", 3); ic += 3;
            imp[ic++] = 0x06; memcpy(imp + ic, "memory", 6); ic += 6;
            imp[ic++] = 0x02; /* kind: memory */
            imp[ic++] = 0x01; /* flags: has max */
            uint32_t min_p = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
            uint32_t max_p = g_fdp->ConsumeIntegralInRange<uint32_t>(4, 256);
            ic += write_u32_leb128(imp + ic, min_p);
            ic += write_u32_leb128(imp + ic, max_p);
            break;
        }
        case 2: {
            /* Import shared memory (flags=0x03: has_max + shared) */
            imp[ic++] = 0x01;
            imp[ic++] = 0x03; memcpy(imp + ic, "env", 3); ic += 3;
            imp[ic++] = 0x06; memcpy(imp + ic, "memory", 6); ic += 6;
            imp[ic++] = 0x02; /* kind: memory */
            imp[ic++] = 0x03; /* flags: has_max + shared */
            uint32_t min_s = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 4);
            uint32_t max_s = g_fdp->ConsumeIntegralInRange<uint32_t>(4, 16);
            ic += write_u32_leb128(imp + ic, min_s);
            ic += write_u32_leb128(imp + ic, max_s);
            break;
        }
        case 3: {
            /* Import memory with large min/max to test boundary checks */
            imp[ic++] = 0x01;
            imp[ic++] = 0x03; memcpy(imp + ic, "env", 3); ic += 3;
            imp[ic++] = 0x06; memcpy(imp + ic, "memory", 6); ic += 6;
            imp[ic++] = 0x02; /* kind: memory */
            imp[ic++] = 0x01; /* flags: has max */
            uint32_t min_l = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 65536);
            uint32_t max_l = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 65536);
            ic += write_u32_leb128(imp + ic, min_l);
            ic += write_u32_leb128(imp + ic, max_l);
            break;
        }
    }
    off += write_wasm_section(mod + off, 0x02, imp, ic);

    /* Function section */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Export _start (func idx 0, no import funcs) */
    static const uint8_t export_body[] = {
        0x01,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code: trivial _start */
    static const uint8_t code_body[] = { 0x01, 0x02, 0x00, 0x0B };
    off += write_wasm_section(mod + off, 0x0A, code_body, sizeof(code_body));

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module that executes memory.grow operations to trigger
 * wasm_enlarge_memory_internal. The function body does memory.grow
 * with various page counts.
 *
 * Targets:
 *   wasm_enlarge_memory_internal (19%), wasm_enlarge_memory (57%),
 *   wasm_mremap_linear_memory (66%), gc_migrate (21%),
 *   os_mremap_slow (50%), SET_LINEAR_MEMORY_SIZE (66%)
 */
static void
harness_wasm_memory_grow_exec(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type: ()->() and ()->(i32) */
    static const uint8_t type_body[] = {
        0x02,
        0x60, 0x00, 0x00,       /* type 0: ()->() */
        0x60, 0x00, 0x01, 0x7F, /* type 1: ()->(i32) */
    };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    /* Function section: 1 function of type 0 */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section: min=1, max=64 (allow growth) */
    static const uint8_t mem_body[] = { 0x01, 0x01, 0x01, 0x40 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code: _start does multiple memory.grow with varying sizes, drops results */
    uint8_t code[128];
    size_t cc = 0;
    code[cc++] = 0x01; /* 1 code entry */

    uint8_t fbody[96];
    size_t fc = 0;
    fbody[fc++] = 0x00; /* 0 local groups */

    /* Generate 3-6 memory.grow operations with fuzzed page counts */
    int grow_count = g_fdp->ConsumeIntegralInRange<int>(3, 6);
    for (int i = 0; i < grow_count; i++) {
        uint32_t pages = g_fdp->ConsumeIntegralInRange<uint32_t>(1, 16);
        fbody[fc++] = 0x41; /* i32.const */
        fc += write_u32_leb128(fbody + fc, pages);
        fbody[fc++] = 0x40; /* memory.grow */
        fbody[fc++] = 0x00; /* memory index 0 */
        fbody[fc++] = 0x1A; /* drop */
    }
    fbody[fc++] = 0x0B; /* end */

    cc += write_u32_leb128(code + cc, (uint32_t)fc);
    memcpy(code + cc, fbody, fc);
    cc += fc;

    off += write_wasm_section(mod + off, 0x0A, code, cc);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with many diverse function types to exercise
 * load_type_section deeper paths and type-related checks.
 * Includes types with i32, i64, f32, f64 params and results,
 * multi-return types, and types with many parameters.
 *
 * Targets:
 *   load_type_section (30%), is_valid_value_type (85%),
 *   is_valid_value_type_for_interpreter (66%),
 *   wasm_value_type_size_internal (70%), destroy_wasm_type (66%),
 *   create_module (66%)
 */
static void
harness_wasm_diverse_types(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 8192);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type section with many diverse signatures */
    uint8_t type_buf[512];
    size_t tc = 0;

    int num_types = g_fdp->ConsumeIntegralInRange<int>(5, 12);
    tc += write_u32_leb128(type_buf + tc, (uint32_t)num_types);

    for (int i = 0; i < num_types && tc < 480; i++) {
        type_buf[tc++] = 0x60; /* func type marker */

        int kind = g_fdp->ConsumeIntegralInRange<int>(0, 7);
        switch (kind) {
            case 0: /* () -> () */
                type_buf[tc++] = 0x00;
                type_buf[tc++] = 0x00;
                break;
            case 1: /* (i32) -> (i32) */
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
                break;
            case 2: /* (i64) -> (i64) */
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7E;
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7E;
                break;
            case 3: /* (f32, f32) -> (f32) */
                type_buf[tc++] = 0x02; type_buf[tc++] = 0x7D;
                type_buf[tc++] = 0x7D;
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7D;
                break;
            case 4: /* (f64) -> (f64) */
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7C;
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7C;
                break;
            case 5: /* (i32, i64, f32, f64) -> (i32) */
                type_buf[tc++] = 0x04;
                type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7E;
                type_buf[tc++] = 0x7D; type_buf[tc++] = 0x7C;
                type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
                break;
            case 6: /* () -> (i32, i64) multi-value return */
                type_buf[tc++] = 0x00;
                type_buf[tc++] = 0x02; type_buf[tc++] = 0x7F;
                type_buf[tc++] = 0x7E;
                break;
            case 7: { /* (i32 x N) -> () with fuzzed param count */
                int np = g_fdp->ConsumeIntegralInRange<int>(3, 8);
                tc += write_u32_leb128(type_buf + tc, (uint32_t)np);
                for (int j = 0; j < np && tc < 490; j++)
                    type_buf[tc++] = 0x7F;
                type_buf[tc++] = 0x00;
                break;
            }
        }
    }
    off += write_wasm_section(mod + off, 0x01, type_buf, tc);

    /* Function section: 1 function of type 0 */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export memory + _start */
    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code: trivial _start */
    static const uint8_t code_body[] = { 0x01, 0x02, 0x00, 0x0B };
    off += write_wasm_section(mod + off, 0x0A, code_body, sizeof(code_body));

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with _start that has non-standard signature.
 * WASI spec requires _start: () -> (), but this creates modules where
 * _start has parameters or return values to exercise error paths.
 *
 * Targets:
 *   wasm_runtime_lookup_wasi_start_function (30%),
 *   check_main_func_type (33%), execute_main (38%)
 */
static void
harness_wasm_start_bad_sig(void)
{
    if (g_fdp->remaining_bytes() < 2)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    int variant = g_fdp->ConsumeIntegralInRange<int>(0, 3);

    uint8_t type_buf[32];
    size_t tc = 0;

    switch (variant) {
        case 0:
            /* _start: (i32) -> () - has params */
            type_buf[tc++] = 0x01;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x00;
            break;
        case 1:
            /* _start: () -> (i32) - has return */
            type_buf[tc++] = 0x01;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x00;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            break;
        case 2:
            /* _start: (i32, i32) -> (i32) - has both */
            type_buf[tc++] = 0x01;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x02; type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            break;
        case 3:
            /* main: (i32, i32) -> (i32) - argc/argv style */
            type_buf[tc++] = 0x01;
            type_buf[tc++] = 0x60;
            type_buf[tc++] = 0x02; type_buf[tc++] = 0x7F; type_buf[tc++] = 0x7F;
            type_buf[tc++] = 0x01; type_buf[tc++] = 0x7F;
            break;
    }
    off += write_wasm_section(mod + off, 0x01, type_buf, tc);

    /* Function section */
    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    /* Memory section */
    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    /* Export: memory + _start or main */
    uint8_t ebuf[64];
    size_t eoff = 0;
    ebuf[eoff++] = 0x02;
    ebuf[eoff++] = 0x06;
    memcpy(ebuf + eoff, "memory", 6); eoff += 6;
    ebuf[eoff++] = 0x02; ebuf[eoff++] = 0x00;
    if (variant == 3) {
        ebuf[eoff++] = 0x04;
        memcpy(ebuf + eoff, "main", 4); eoff += 4;
    }
    else {
        ebuf[eoff++] = 0x06;
        memcpy(ebuf + eoff, "_start", 6); eoff += 6;
    }
    ebuf[eoff++] = 0x00; ebuf[eoff++] = 0x00;
    off += write_wasm_section(mod + off, 0x07, ebuf, eoff);

    /* Code: function body that satisfies the type */
    uint8_t code[32];
    size_t cc = 0;
    code[cc++] = 0x01; /* 1 code entry */

    switch (variant) {
        case 0: {
            /* (i32)->(): just end */
            code[cc++] = 0x02; code[cc++] = 0x00; code[cc++] = 0x0B;
            break;
        }
        case 1: {
            /* ()->(i32): i32.const 0, end */
            code[cc++] = 0x04; code[cc++] = 0x00;
            code[cc++] = 0x41; code[cc++] = 0x00;
            code[cc++] = 0x0B;
            break;
        }
        case 2:
        case 3: {
            /* (i32,i32)->(i32): local.get 0, end */
            code[cc++] = 0x04; code[cc++] = 0x00;
            code[cc++] = 0x20; code[cc++] = 0x00;
            code[cc++] = 0x0B;
            break;
        }
    }
    off += write_wasm_section(mod + off, 0x0A, code, cc);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

/*
 * WASM module with diverse local variable types in function body
 * to exercise interpreter local handling paths with i32/i64/f32/f64.
 * Also uses local.get, local.set, local.tee operations.
 *
 * Targets:
 *   wasm_interp_call_func_bytecode (14%) - local access handlers,
 *   wasm_loader_prepare_bytecode (39%) - local validation,
 *   init_function_local_offsets (85%), preserve_referenced_local (64%)
 */
static void
harness_wasm_diverse_locals(void)
{
    if (g_fdp->remaining_bytes() < 4)
        return;

    uint8_t *mod = (uint8_t *)calloc(1, 4096);
    g_alloc_mgr.push_back(mod);
    if (!mod)
        return;

    size_t off = 0;
    memcpy(mod, wasm_magic_hdr, 8);
    off = 8;

    /* Type: ()->() */
    static const uint8_t type_body[] = { 0x01, 0x60, 0x00, 0x00 };
    off += write_wasm_section(mod + off, 0x01, type_body, sizeof(type_body));

    static const uint8_t func_body[] = { 0x01, 0x00 };
    off += write_wasm_section(mod + off, 0x03, func_body, sizeof(func_body));

    static const uint8_t mem_body[] = { 0x01, 0x00, 0x01 };
    off += write_wasm_section(mod + off, 0x05, mem_body, sizeof(mem_body));

    static const uint8_t export_body[] = {
        0x02,
        0x06, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
        0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
    };
    off += write_wasm_section(mod + off, 0x07,
                              export_body, sizeof(export_body));

    /* Code: function with diverse local types and operations */
    uint8_t code[256];
    size_t cc = 0;
    code[cc++] = 0x01; /* 1 code entry */

    uint8_t fbody[200];
    size_t fc = 0;

    /* 4 local groups: 2 i32, 1 i64, 1 f32, 1 f64 */
    fbody[fc++] = 0x04; /* 4 local groups */
    fbody[fc++] = 0x02; fbody[fc++] = 0x7F; /* 2 x i32 */
    fbody[fc++] = 0x01; fbody[fc++] = 0x7E; /* 1 x i64 */
    fbody[fc++] = 0x01; fbody[fc++] = 0x7D; /* 1 x f32 */
    fbody[fc++] = 0x01; fbody[fc++] = 0x7C; /* 1 x f64 */

    /* local.set 0 = i32.const fuzzed */
    uint32_t val0 = g_fdp->ConsumeIntegral<uint32_t>();
    fbody[fc++] = 0x41; /* i32.const */
    fc += write_u32_leb128(fbody + fc, val0);
    fbody[fc++] = 0x21; fbody[fc++] = 0x00; /* local.set 0 */

    /* local.set 1 = i32.const */
    fbody[fc++] = 0x41;
    fc += write_u32_leb128(fbody + fc, g_fdp->ConsumeIntegral<uint32_t>());
    fbody[fc++] = 0x21; fbody[fc++] = 0x01; /* local.set 1 */

    /* local.set 2 = i64.const */
    fbody[fc++] = 0x42; /* i64.const */
    fc += write_u32_leb128(fbody + fc,
                           g_fdp->ConsumeIntegralInRange<uint32_t>(0, 1000));
    fbody[fc++] = 0x21; fbody[fc++] = 0x02; /* local.set 2 */

    /* local.set 3 = f32.const */
    fbody[fc++] = 0x43; /* f32.const */
    float fval = 3.14f;
    memcpy(fbody + fc, &fval, 4); fc += 4;
    fbody[fc++] = 0x21; fbody[fc++] = 0x03; /* local.set 3 */

    /* local.set 4 = f64.const */
    fbody[fc++] = 0x44; /* f64.const */
    double dval = 2.718;
    memcpy(fbody + fc, &dval, 8); fc += 8;
    fbody[fc++] = 0x21; fbody[fc++] = 0x04; /* local.set 4 */

    /* local.get + local.tee + drop patterns */
    fbody[fc++] = 0x20; fbody[fc++] = 0x00; /* local.get 0 */
    fbody[fc++] = 0x22; fbody[fc++] = 0x01; /* local.tee 1 */
    fbody[fc++] = 0x1A; /* drop */

    /* i32 arithmetic on locals */
    fbody[fc++] = 0x20; fbody[fc++] = 0x00; /* local.get 0 */
    fbody[fc++] = 0x20; fbody[fc++] = 0x01; /* local.get 1 */
    fbody[fc++] = 0x6A; /* i32.add */
    fbody[fc++] = 0x1A; /* drop */

    /* i64 extend and arithmetic */
    fbody[fc++] = 0x20; fbody[fc++] = 0x02; /* local.get 2 */
    fbody[fc++] = 0x20; fbody[fc++] = 0x02; /* local.get 2 */
    fbody[fc++] = 0x7C; /* i64.add */
    fbody[fc++] = 0x1A; /* drop */

    /* f32 operations */
    fbody[fc++] = 0x20; fbody[fc++] = 0x03; /* local.get 3 */
    fbody[fc++] = 0x20; fbody[fc++] = 0x03; /* local.get 3 */
    fbody[fc++] = 0x92; /* f32.add */
    fbody[fc++] = 0x1A; /* drop */

    /* f64 operations */
    fbody[fc++] = 0x20; fbody[fc++] = 0x04; /* local.get 4 */
    fbody[fc++] = 0x20; fbody[fc++] = 0x04; /* local.get 4 */
    fbody[fc++] = 0xA0; /* f64.add */
    fbody[fc++] = 0x1A; /* drop */

    fbody[fc++] = 0x0B; /* end */

    cc += write_u32_leb128(code + cc, (uint32_t)fc);
    memcpy(code + cc, fbody, fc);
    cc += fc;

    off += write_wasm_section(mod + off, 0x0A, code, cc);

    ecall_iwasm_main(__g_harness_eid, mod, (uint32_t)off);
}

// ============================================================================
// Customized Initialization
// ============================================================================
// This function is called once during fuzzer initialization
// (LLVMFuzzerInitialize).
//
// REQUIRED: Register all test harnesses by filling test_harness_registry[]
//
// Usage:
//   test_harness_registry[test_harness_count++] = {harness_function, weight};
//
// IMPORTANT:
// - This function is called BEFORE any fuzzing iterations start
// - DO NOT create or initialize the enclave here (__g_harness_eid will be 0)
// - DO NOT access g_fdp here (it's not initialized yet)
// - Keep initialization lightweight and fast
// - Weight MUST be > 0 for all harnesses
//
// Optional: Add custom initialization such as:
// - Environment variable configuration (setenv, putenv)
// - Global state initialization
// - Logging/debugging setup
// - Resource pre-allocation
// - Configuration file loading
// ============================================================================

extern "C" void
customized_init()
{
    // ========================================================================
    // Step 1: Register all test harnesses
    // ========================================================================

    // === HIGHEST PRIORITY: Interpreter coverage ===

    // SIMD v128 operations (0xFD prefix) - NEW COVERAGE
    // WAMR_BUILD_SIMD=0 currently but harness exercises the loader/validator
    // SIMD opcode handling paths. High value for validation coverage.
    // Targets: WASM_OP_SIMD_PREFIX handler, SIMD opcode validation paths
    test_harness_registry[test_harness_count++] = {
        harness_wasm_simd_ops, 70
    };

    // Diverse opcodes: memory ops, control flow, arithmetic, conversions
    // Targets: wasm_interp_call_func_bytecode (integer dispatch paths)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_diverse_opcodes, 80
    };

    // Float/double operations - completely separate interpreter paths
    // Targets: f32/f64 opcode handlers, float comparisons, conversions
    test_harness_registry[test_harness_count++] = {
        harness_wasm_float_ops, 70
    };

    // Large fuzzed bytecode with multiple types and locals
    // Targets: broader opcode dispatch, validator paths
    test_harness_registry[test_harness_count++] = {
        harness_valid_wasm_large_fuzz_body, 60
    };

    // Bulk memory operations (0xFC prefix)
    // Targets: memory.fill, memory.copy, memory.init, data.drop
    test_harness_registry[test_harness_count++] = {
        harness_wasm_bulk_memory, 80
    };

    // Table operations (ref_types enabled)
    // Targets: table.grow/size/fill/init, elem.drop
    test_harness_registry[test_harness_count++] = {
        harness_wasm_table_ops, 70
    };

    // Trapping operations - exercises error/exception handling
    // Targets: div-by-zero, overflow, OOB memory, unreachable traps
    test_harness_registry[test_harness_count++] = {
        harness_wasm_trapping_ops, 60
    };

    // === NEW: Coverage expansion - untested opcode/section paths ===

    // Shared memory + atomic operations (0xFE prefix)
    // WASM_ENABLE_SHARED_MEMORY=1 is enabled in the build
    // Targets: shared memory flag path, atomic load/store/RMW handlers
    test_harness_registry[test_harness_count++] = {
        harness_wasm_shared_memory_atomic, 90
    };

    // i64 operations: arithmetic, conversions, memory load/store
    // Targets: i64 arithmetic/comparison opcode handlers, wrap/extend
    test_harness_registry[test_harness_count++] = {
        harness_wasm_i64_ops, 50
    };

    // Start section: triggers start function during instantiation
    // Targets: load_start_section, execute_post_instantiate_functions
    test_harness_registry[test_harness_count++] = {
        harness_wasm_start_function, 60
    };

    // Saturating truncation ops (0xFC 0x00-0x07)
    // Targets: MISC_PREFIX sat trunc handlers with special float values
    test_harness_registry[test_harness_count++] = {
        harness_wasm_saturating_trunc, 50
    };

    // Globals with reference types (funcref, externref)
    // REF_TYPES=1 enabled, targets load_global_section ref type paths
    test_harness_registry[test_harness_count++] = {
        harness_wasm_globals_reftypes, 50
    };

    // Select/typed select (0x1C) + sign extension ops (0xC0-0xC4)
    // Targets: select handlers, sign extension, type conversions
    test_harness_registry[test_harness_count++] = {
        harness_wasm_select_convert, 40
    };

    // Multi-value returns - always-on feature but never explicitly tested
    // Targets: multi-return handling in interpreter, multi-value block types
    test_harness_registry[test_harness_count++] = {
        harness_wasm_multi_value, 50
    };

    // call_indirect: table-based dispatch in interpreter
    test_harness_registry[test_harness_count++] = {
        harness_wasm_call_indirect, 60
    };

    // br_table: multi-way branching in interpreter
    test_harness_registry[test_harness_count++] = {
        harness_wasm_br_table, 60
    };

    // exec_app_func variants - different export names, arg counts
    // Targets: function lookup, argument parsing/conversion
    test_harness_registry[test_harness_count++] = {
        harness_cmd_exec_func_variants, 60
    };

    // Command workflow with "add" export - exercises execute_func
    test_harness_registry[test_harness_count++] = {
        harness_cmd_workflow_diverse_exec, 50
    };

    // === HIGH PRIORITY: Section-specific harnesses ===

    // WASM with data + datacount sections
    test_harness_registry[test_harness_count++] = {
        harness_wasm_data_section, 40
    };

    // WASM with element section
    test_harness_registry[test_harness_count++] = {
        harness_wasm_elem_section, 40
    };

    // WASM with import section
    test_harness_registry[test_harness_count++] = {
        harness_wasm_import_section, 60
    };

    // WASM with custom/name section
    test_harness_registry[test_harness_count++] = {
        harness_wasm_custom_section, 20
    };

    // WASM with multiple function types, locals, control flow
    test_harness_registry[test_harness_count++] = {
        harness_wasm_multi_func, 40
    };

    // === NEW: WASI import/linking and interpreter depth harnesses ===

    // WASM importing wasi_snapshot_preview1 functions - exercises WASI
    // function resolution/linking during module loading and instantiation
    // Targets: wasm_runtime_init_wasi, WASI import resolution paths
    test_harness_registry[test_harness_count++] = {
        harness_wasm_wasi_imports, 100
    };

    // Deeply nested control flow - tests interpreter block stack management
    // Targets: control flow stack, br depth resolution, nested block/loop/if
    test_harness_registry[test_harness_count++] = {
        harness_wasm_deep_nested_flow, 60
    };

    // Multiple functions calling each other - exercises call/return mechanism
    // Targets: function frame push/pop, multi-function module execution
    test_harness_registry[test_harness_count++] = {
        harness_wasm_inter_func_calls, 50
    };

    // Diverse memory load/store with different offsets, alignments, widths
    // Targets: memory access handlers, alignment checking, bounds checking
    test_harness_registry[test_harness_count++] = {
        harness_wasm_memory_diverse, 50
    };

    // Command workflow with env vars + address pool in WASI args
    // Targets: handle_cmd_set_wasi_args env_list/addr_pool_list paths
    test_harness_registry[test_harness_count++] = {
        harness_cmd_workflow_env_addr, 40
    };

    // AOT with structured init_data + text sections
    // Targets: aot_load_from_aot_file init_data section parsing
    test_harness_registry[test_harness_count++] = {
        harness_aot_init_data, 30
    };

    // === NEW: Critical bottleneck harnesses (iter analysis) ===

    // WASI imports + command pipeline + full WASI args
    // KEY: combines WASI imports with set_wasi_args for deep WASI init coverage
    // Targets: wasm_runtime_init_wasi (2%), copy_string_array (26%),
    //          fd_table_insert_existing (37%), fd_determine_type_rights (21%)
    test_harness_registry[test_harness_count++] = {
        harness_wasi_import_cmd_workflow, 120
    };

    // Memory import module - exercises load_memory_import
    // Targets: load_memory_import (18%), wasm_memory_check_flags (66%),
    //          check_memory_init_size (50%), check_memory_max_size (40%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_memory_import_module, 60
    };

    // Memory grow execution - triggers wasm_enlarge_memory_internal
    // Targets: wasm_enlarge_memory_internal (19%), gc_migrate (21%),
    //          os_mremap_slow (50%), SET_LINEAR_MEMORY_SIZE (66%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_memory_grow_exec, 60
    };

    // Diverse function types in type section
    // Targets: load_type_section (30%), is_valid_value_type (85%),
    //          wasm_value_type_size_internal (70%), create_module (66%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_diverse_types, 50
    };

    // Non-standard _start signature for error path coverage
    // Targets: wasm_runtime_lookup_wasi_start_function (30%),
    //          check_main_func_type (33%), execute_main (38%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_start_bad_sig, 50
    };

    // Diverse local types in function body
    // Targets: wasm_interp_call_func_bytecode (14%) local handlers,
    //          init_function_local_offsets (85%), preserve_referenced_local (64%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_diverse_locals, 50
    };

    // === Bottleneck-targeted harnesses (coverage expansion) ===

    // i32/i64/f32/f64 comparison ops + nop, return, eqz, div, rem, clz/ctz/popcnt
    // Targets: wasm_interp_call_func_bytecode (13% coverage) - comparison handlers
    test_harness_registry[test_harness_count++] = {
        harness_wasm_comparison_branch_ops, 100
    };

    // UTF-8 diverse names in exports and custom sections
    // Targets: wasm_check_utf8_str (7%) - multi-byte UTF-8 validation paths
    test_harness_registry[test_harness_count++] = {
        harness_wasm_utf8_diverse_names, 50
    };

    // WASI ABI compatibility variants (_start/_initialize with various signatures)
    // Targets: check_wasi_abi_compatibility (25%), execute_main (16%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_wasi_abi_check, 60
    };

    // Different memory configurations (no-max, has-max, shared, large, fuzzed)
    // Targets: memory_instantiate (32%), wasm_memory_check_flags (66%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_memory_variants, 60
    };

    // Diverse init expressions (i32, i64, f32, f64, ref.null, ref.func)
    // Targets: load_init_expr (16%), load_global_section (30%), globals_instantiate (54%)
    test_harness_registry[test_harness_count++] = {
        harness_wasm_init_expr_types, 50
    };

    // Import section with properly linked WASI functions
    // Targets: load_import_section (3%), check_linked_symbol (18%),
    //          wasm_runtime_init_wasi (2%), fd_table_init, fd_prestats_init
    test_harness_registry[test_harness_count++] = {
        harness_wasm_import_link_wasi, 90
    };

    // === MEDIUM PRIORITY: Workflow harnesses ===

    // Command workflow with full WASI args (env, addr pool)
    // Boosted: wasm_runtime_init_wasi still at 2%
    test_harness_registry[test_harness_count++] = {
        harness_cmd_workflow_wasi_full, 60
    };

    // Comprehensive WASM via command pipeline (data+elem+table+global)
    test_harness_registry[test_harness_count++] = {
        harness_cmd_comprehensive_wasm, 30
    };

    // Valid WASM with fuzzed bytecode - high value for interpreter
    test_harness_registry[test_harness_count++] = {
        harness_valid_wasm_fuzz_body, 30
    };

    // Command workflow with valid WASM and WASI args
    test_harness_registry[test_harness_count++] = {
        harness_cmd_workflow_valid_wasm, 20
    };

    // Structured AOT file - deeper AOT loading paths
    // Targets: aot_load_from_aot_file, target_info reading
    test_harness_registry[test_harness_count++] = {
        harness_aot_structured, 30
    };

    // === LOWER PRIORITY: Already covered or less impactful ===

    // Minimal valid WASM - basic execution paths
    test_harness_registry[test_harness_count++] = {
        harness_valid_wasm_minimal, 10
    };

    // Valid WASM with table, global, start sections
    test_harness_registry[test_harness_count++] = {
        harness_valid_wasm_rich, 10
    };

    // Full workflow with random WASM/AOT data
    test_harness_registry[test_harness_count++] = {harness_cmd_workflow, 5};

    // Structured iwasm_main with random WASM/AOT magic header
    test_harness_registry[test_harness_count++] = {
        harness_iwasm_main_structured, 5
    };

    // Targeted commands with proper argc sizing
    test_harness_registry[test_harness_count++] = {harness_cmd_targeted, 3};

    // NULL buffer edge case
    test_harness_registry[test_harness_count++] = {harness_cmd_null_buf, 1};

    // Generic ecall_handle_command (well-covered)
    test_harness_registry[test_harness_count++] = {
        _harness_ecall_handle_command, 1
    };

    // Generic ecall_iwasm_main (well-covered)
    test_harness_registry[test_harness_count++] = {
        _harness_ecall_iwasm_main, 1
    };

    // ========================================================================
    // Step 2: Calculate total weight for weighted random selection
    // ========================================================================

    if (test_harness_count == 0) {
        fprintf(stderr, "[!] Error: No test harnesses registered\n");
        abort();
    }

    total_weight = 0;
    for (unsigned int i = 0; i < test_harness_count; i++) {
        total_weight += test_harness_registry[i].weight;
    }

    if (total_weight == 0) {
        fprintf(stderr, "[!] Error: All harness weights are 0\n");
        abort();
    }
}

// ============================================================================
// Main Test Entry Point
// ============================================================================
// Called by LLVMFuzzerTestOneInput for each fuzzing iteration
// Performs weighted random selection of test harnesses
// ============================================================================

extern "C" void
customized_harness(void)
{
    // Weighted random selection
    do {
        int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight - 1);
        int cumulative = 0;
        for (unsigned int i = 0; i < test_harness_count; i++) {
            cumulative += test_harness_registry[i].weight;
            if (rand_val < cumulative) {
                test_harness_registry[i].function();
                break;
            }
        }
    } while (g_fdp->remaining_bytes() > 0);
}
