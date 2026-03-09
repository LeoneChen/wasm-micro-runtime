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

template<typename T>
constexpr size_t
safe_sizeof()
{
    return sizeof(
        typename std::conditional<std::is_void<T>::value, char, T>::type);
}

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
    auto ret =
        ecall_handle_command(__g_harness_eid, cmd, cmd_buf, cmd_buf_size);
    if (ret != SGX_SUCCESS && ret != SGX_ERROR_INVALID_PARAMETER
        && ret != SGX_ERROR_ECALL_NOT_ALLOWED) {
        fprintf(stderr, "ecall_handle_command returned with error code: 0x%X\n",
                ret);
        abort();
    }
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
    auto ret = ecall_iwasm_main(__g_harness_eid, wasm_file_buf, wasm_file_size);
    if (ret != SGX_SUCCESS && ret != SGX_ERROR_INVALID_PARAMETER
        && ret != SGX_ERROR_ECALL_NOT_ALLOWED) {
        fprintf(stderr, "ecall_iwasm_main returned with error code: 0x%X\n",
                ret);
        abort();
    }
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
    test_harness_registry[test_harness_count++] = {
        _harness_ecall_handle_command, 10
    }; // Test ecall_handle_command
    test_harness_registry[test_harness_count++] = {
        _harness_ecall_iwasm_main, 10
    }; // Test ecall_iwasm_main

    // ========================================================================
    // Step 2: Calculate total weight for weighted random selection
    // ========================================================================

    // Sanity check: ensure at least one harness is registered
    if (test_harness_count == 0) {
        fprintf(stderr, "[!] Error: No test harnesses registered\n");
        abort();
    }

    total_weight = 0;
    for (unsigned int i = 0; i < test_harness_count; i++) {
        total_weight += test_harness_registry[i].weight;
    }

    // Sanity check: ensure total weight > 0
    if (total_weight == 0) {
        fprintf(stderr, "[!] Error: All harness weights are 0\n");
        abort();
    }

    // ========================================================================
    // Step 3: Custom initialization (optional)
    // ========================================================================
    // Examples:
    // - setenv("SGX_AESM_ADDR", "1", 1);
    // - freopen("/tmp/fuzzer.log", "w", stderr);
    // - Initialize global variables
    // - Pre-load configuration files
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
