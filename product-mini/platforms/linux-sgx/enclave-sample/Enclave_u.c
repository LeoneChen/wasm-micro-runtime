#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_handle_command_t {
    unsigned int ms_cmd;
    uint8_t *ms_cmd_buf;
    unsigned int ms_cmd_buf_size;
} ms_ecall_handle_command_t;

typedef struct ms_ecall_iwasm_main_t {
    uint8_t *ms_wasm_file_buf;
    uint32_t ms_wasm_file_size;
} ms_ecall_iwasm_main_t;

typedef struct ms_ocall_print_t {
    int ms_retval;
    const char *ms_str;
} ms_ocall_print_t;

typedef struct ms_sgx_oc_cpuidex_t {
    int *ms_cpuinfo;
    int ms_leaf;
    int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
    int ms_retval;
    const void *ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
    int ms_retval;
    const void *ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
    int ms_retval;
    const void *ms_waiter;
    const void *ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
    int ms_retval;
    const void **ms_waiters;
    size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
    int ms_retval;
    unsigned long long ms_waiter;
    unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
    int ms_retval;
    unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
    int ms_retval;
    unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

typedef struct ms_ocall_open_t {
    int ms_retval;
    const char *ms_pathname;
    int ms_flags;
    bool ms_has_mode;
    unsigned int ms_mode;
} ms_ocall_open_t;

typedef struct ms_ocall_openat_t {
    int ms_retval;
    int ms_dirfd;
    const char *ms_pathname;
    int ms_flags;
    bool ms_has_mode;
    unsigned int ms_mode;
} ms_ocall_openat_t;

typedef struct ms_ocall_close_t {
    int ms_retval;
    int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_read_t {
    ssize_t ms_retval;
    int ms_fd;
    void *ms_buf;
    size_t ms_read_size;
} ms_ocall_read_t;

typedef struct ms_ocall_lseek_t {
    off_t ms_retval;
    int ms_fd;
    off_t ms_offset;
    int ms_whence;
} ms_ocall_lseek_t;

typedef struct ms_ocall_ftruncate_t {
    int ms_retval;
    int ms_fd;
    off_t ms_length;
} ms_ocall_ftruncate_t;

typedef struct ms_ocall_fsync_t {
    int ms_retval;
    int ms_fd;
} ms_ocall_fsync_t;

typedef struct ms_ocall_fdatasync_t {
    int ms_retval;
    int ms_fd;
} ms_ocall_fdatasync_t;

typedef struct ms_ocall_isatty_t {
    int ms_retval;
    int ms_fd;
} ms_ocall_isatty_t;

typedef struct ms_ocall_fdopendir_t {
    int ms_fd;
    void **ms_p_dirp;
} ms_ocall_fdopendir_t;

typedef struct ms_ocall_readdir_t {
    void *ms_retval;
    void *ms_dirp;
} ms_ocall_readdir_t;

typedef struct ms_ocall_rewinddir_t {
    void *ms_dirp;
} ms_ocall_rewinddir_t;

typedef struct ms_ocall_seekdir_t {
    void *ms_dirp;
    long int ms_loc;
} ms_ocall_seekdir_t;

typedef struct ms_ocall_telldir_t {
    long int ms_retval;
    void *ms_dirp;
} ms_ocall_telldir_t;

typedef struct ms_ocall_closedir_t {
    int ms_retval;
    void *ms_dirp;
} ms_ocall_closedir_t;

typedef struct ms_ocall_stat_t {
    int ms_retval;
    const char *ms_pathname;
    void *ms_buf;
    unsigned int ms_buf_len;
} ms_ocall_stat_t;

typedef struct ms_ocall_fstat_t {
    int ms_retval;
    int ms_fd;
    void *ms_buf;
    unsigned int ms_buf_len;
} ms_ocall_fstat_t;

typedef struct ms_ocall_fstatat_t {
    int ms_retval;
    int ms_dirfd;
    const char *ms_pathname;
    void *ms_buf;
    unsigned int ms_buf_len;
    int ms_flags;
} ms_ocall_fstatat_t;

typedef struct ms_ocall_mkdirat_t {
    int ms_retval;
    int ms_dirfd;
    const char *ms_pathname;
    unsigned int ms_mode;
} ms_ocall_mkdirat_t;

typedef struct ms_ocall_link_t {
    int ms_retval;
    const char *ms_oldpath;
    const char *ms_newpath;
} ms_ocall_link_t;

typedef struct ms_ocall_linkat_t {
    int ms_retval;
    int ms_olddirfd;
    const char *ms_oldpath;
    int ms_newdirfd;
    const char *ms_newpath;
    int ms_flags;
} ms_ocall_linkat_t;

typedef struct ms_ocall_unlinkat_t {
    int ms_retval;
    int ms_dirfd;
    const char *ms_pathname;
    int ms_flags;
} ms_ocall_unlinkat_t;

typedef struct ms_ocall_readlink_t {
    ssize_t ms_retval;
    const char *ms_pathname;
    char *ms_buf;
    size_t ms_bufsiz;
} ms_ocall_readlink_t;

typedef struct ms_ocall_readlinkat_t {
    ssize_t ms_retval;
    int ms_dirfd;
    const char *ms_pathname;
    char *ms_buf;
    size_t ms_bufsiz;
} ms_ocall_readlinkat_t;

typedef struct ms_ocall_renameat_t {
    int ms_retval;
    int ms_olddirfd;
    const char *ms_oldpath;
    int ms_newdirfd;
    const char *ms_newpath;
} ms_ocall_renameat_t;

typedef struct ms_ocall_symlinkat_t {
    int ms_retval;
    const char *ms_target;
    int ms_newdirfd;
    const char *ms_linkpath;
} ms_ocall_symlinkat_t;

typedef struct ms_ocall_ioctl_t {
    int ms_retval;
    int ms_fd;
    unsigned long int ms_request;
    void *ms_arg;
    unsigned int ms_arg_len;
} ms_ocall_ioctl_t;

typedef struct ms_ocall_fcntl_t {
    int ms_retval;
    int ms_fd;
    int ms_cmd;
} ms_ocall_fcntl_t;

typedef struct ms_ocall_fcntl_long_t {
    int ms_retval;
    int ms_fd;
    int ms_cmd;
    long int ms_arg;
} ms_ocall_fcntl_long_t;

typedef struct ms_ocall_realpath_t {
    int ms_retval;
    const char *ms_path;
    char *ms_buf;
    unsigned int ms_buf_len;
} ms_ocall_realpath_t;

typedef struct ms_ocall_posix_fallocate_t {
    int ms_retval;
    int ms_fd;
    off_t ms_offset;
    off_t ms_len;
} ms_ocall_posix_fallocate_t;

typedef struct ms_ocall_poll_t {
    int ms_retval;
    void *ms_fds;
    unsigned int ms_nfds;
    int ms_timeout;
    unsigned int ms_fds_len;
} ms_ocall_poll_t;

typedef struct ms_ocall_getopt_t {
    int ms_retval;
    int ms_argc;
    char *ms_argv_buf;
    unsigned int ms_argv_buf_len;
    const char *ms_optstring;
} ms_ocall_getopt_t;

typedef struct ms_ocall_readv_t {
    ssize_t ms_retval;
    int ms_fd;
    char *ms_iov_buf;
    unsigned int ms_buf_size;
    int ms_iovcnt;
    bool ms_has_offset;
    off_t ms_offset;
} ms_ocall_readv_t;

typedef struct ms_ocall_writev_t {
    ssize_t ms_retval;
    int ms_fd;
    char *ms_iov_buf;
    unsigned int ms_buf_size;
    int ms_iovcnt;
    bool ms_has_offset;
    off_t ms_offset;
} ms_ocall_writev_t;

typedef struct ms_ocall_clock_gettime_t {
    int ms_retval;
    unsigned int ms_clock_id;
    void *ms_tp_buf;
    unsigned int ms_tp_buf_size;
} ms_ocall_clock_gettime_t;

typedef struct ms_ocall_clock_getres_t {
    int ms_retval;
    int ms_clock_id;
    void *ms_res_buf;
    unsigned int ms_res_buf_size;
} ms_ocall_clock_getres_t;

typedef struct ms_ocall_utimensat_t {
    int ms_retval;
    int ms_dirfd;
    const char *ms_pathname;
    const void *ms_times_buf;
    unsigned int ms_times_buf_size;
    int ms_flags;
} ms_ocall_utimensat_t;

typedef struct ms_ocall_futimens_t {
    int ms_retval;
    int ms_fd;
    const void *ms_times_buf;
    unsigned int ms_times_buf_size;
} ms_ocall_futimens_t;

typedef struct ms_ocall_clock_nanosleep_t {
    int ms_retval;
    unsigned int ms_clock_id;
    int ms_flags;
    const void *ms_req_buf;
    unsigned int ms_req_buf_size;
    void *ms_rem_buf;
    unsigned int ms_rem_buf_size;
} ms_ocall_clock_nanosleep_t;

typedef struct ms_ocall_raise_t {
    int ms_retval;
    int ms_sig;
} ms_ocall_raise_t;

typedef struct ms_ocall_sched_yield_t {
    int ms_retval;
} ms_ocall_sched_yield_t;

typedef struct ms_ocall_pthread_rwlock_init_t {
    int ms_retval;
    void **ms_rwlock;
    void *ms_attr;
} ms_ocall_pthread_rwlock_init_t;

typedef struct ms_ocall_pthread_rwlock_destroy_t {
    int ms_retval;
    void *ms_rwlock;
} ms_ocall_pthread_rwlock_destroy_t;

typedef struct ms_ocall_pthread_rwlock_rdlock_t {
    int ms_retval;
    void *ms_rwlock;
} ms_ocall_pthread_rwlock_rdlock_t;

typedef struct ms_ocall_pthread_rwlock_wrlock_t {
    int ms_retval;
    void *ms_rwlock;
} ms_ocall_pthread_rwlock_wrlock_t;

typedef struct ms_ocall_pthread_rwlock_unlock_t {
    int ms_retval;
    void *ms_rwlock;
} ms_ocall_pthread_rwlock_unlock_t;

typedef struct ms_ocall_get_errno_t {
    int ms_retval;
} ms_ocall_get_errno_t;

typedef struct ms_ocall_accept_t {
    int ms_retval;
    int ms_sockfd;
    void *ms_addr;
    uint32_t *ms_addrlen;
    uint32_t ms_addr_size;
} ms_ocall_accept_t;

typedef struct ms_ocall_bind_t {
    int ms_retval;
    int ms_sockfd;
    const void *ms_addr;
    uint32_t ms_addrlen;
} ms_ocall_bind_t;

typedef struct ms_ocall_connect_t {
    int ms_retval;
    int ms_sockfd;
    void *ms_addr;
    uint32_t ms_addrlen;
} ms_ocall_connect_t;

typedef struct ms_ocall_getsockname_t {
    int ms_retval;
    int ms_sockfd;
    void *ms_addr;
    uint32_t *ms_addrlen;
    uint32_t ms_addr_size;
} ms_ocall_getsockname_t;

typedef struct ms_ocall_getpeername_t {
    int ms_retval;
    int ms_sockfd;
    void *ms_addr;
    uint32_t *ms_addrlen;
    uint32_t ms_addr_size;
} ms_ocall_getpeername_t;

typedef struct ms_ocall_getsockopt_t {
    int ms_retval;
    int ms_sockfd;
    int ms_level;
    int ms_optname;
    void *ms_val_buf;
    unsigned int ms_val_buf_size;
    void *ms_len_buf;
} ms_ocall_getsockopt_t;

typedef struct ms_ocall_listen_t {
    int ms_retval;
    int ms_sockfd;
    int ms_backlog;
} ms_ocall_listen_t;

typedef struct ms_ocall_recv_t {
    int ms_retval;
    int ms_sockfd;
    void *ms_buf;
    size_t ms_len;
    int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_recvfrom_t {
    ssize_t ms_retval;
    int ms_sockfd;
    void *ms_buf;
    size_t ms_len;
    int ms_flags;
    void *ms_src_addr;
    uint32_t *ms_addrlen;
    uint32_t ms_addr_size;
} ms_ocall_recvfrom_t;

typedef struct ms_ocall_recvmsg_t {
    ssize_t ms_retval;
    int ms_sockfd;
    void *ms_msg_buf;
    unsigned int ms_msg_buf_size;
    int ms_flags;
} ms_ocall_recvmsg_t;

typedef struct ms_ocall_send_t {
    int ms_retval;
    int ms_sockfd;
    const void *ms_buf;
    size_t ms_len;
    int ms_flags;
} ms_ocall_send_t;

typedef struct ms_ocall_sendto_t {
    ssize_t ms_retval;
    int ms_sockfd;
    const void *ms_buf;
    size_t ms_len;
    int ms_flags;
    void *ms_dest_addr;
    uint32_t ms_addrlen;
} ms_ocall_sendto_t;

typedef struct ms_ocall_sendmsg_t {
    ssize_t ms_retval;
    int ms_sockfd;
    void *ms_msg_buf;
    unsigned int ms_msg_buf_size;
    int ms_flags;
} ms_ocall_sendmsg_t;

typedef struct ms_ocall_setsockopt_t {
    int ms_retval;
    int ms_sockfd;
    int ms_level;
    int ms_optname;
    void *ms_optval;
    unsigned int ms_optlen;
} ms_ocall_setsockopt_t;

typedef struct ms_ocall_shutdown_t {
    int ms_retval;
    int ms_sockfd;
    int ms_how;
} ms_ocall_shutdown_t;

typedef struct ms_ocall_socket_t {
    int ms_retval;
    int ms_domain;
    int ms_type;
    int ms_protocol;
} ms_ocall_socket_t;

/* ========== Generated Fuzzing Harness Code ========== */

enum FuzzDataTy {
    FUZZ_STRING,
    FUZZ_WSTRING,
    FUZZ_DATA,
    FUZZ_SIZE,
    FUZZ_COUNT,
    FUZZ_RET,
};
/* DF Runtime function declarations */
extern uint8_t *
DFGetBytes(void *ptr, size_t byteArrLen, enum FuzzDataTy dataType);
extern size_t
DFGetCount(size_t size);
extern size_t
DFGetSize();
extern void *
DFManagedCalloc(size_t count, size_t size);
extern int
DFSetNull();
extern int
DFModifyOCallRet();
extern sgx_enclave_id_t __hidden_sgxfuzzer_harness_global_eid;

int
__ocall_wrapper_ocall_print(const char *str)
{
    int _fuzz_ret = ocall_print(str);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

void
__ocall_wrapper_sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
    sgx_oc_cpuidex(cpuinfo, leaf, subleaf);
    if (DFModifyOCallRet()) {
        for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
            DFGetBytes(&cpuinfo[i_0_0], sizeof(int), FUZZ_DATA);
        }
    }
}

int
__ocall_wrapper_sgx_thread_wait_untrusted_event_ocall(const void *self)
{
    int _fuzz_ret = sgx_thread_wait_untrusted_event_ocall(self);
    if (DFModifyOCallRet()) {
        size_t count_0_self = DFGetCount(1);
        DFGetBytes((void *)self, count_0_self * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_sgx_thread_set_untrusted_event_ocall(const void *waiter)
{
    int _fuzz_ret = sgx_thread_set_untrusted_event_ocall(waiter);
    if (DFModifyOCallRet()) {
        size_t count_0_waiter = DFGetCount(1);
        DFGetBytes((void *)waiter, count_0_waiter * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_sgx_thread_setwait_untrusted_events_ocall(const void *waiter,
                                                          const void *self)
{
    int _fuzz_ret = sgx_thread_setwait_untrusted_events_ocall(waiter, self);
    if (DFModifyOCallRet()) {
        size_t count_0_waiter = DFGetCount(1);
        DFGetBytes((void *)waiter, count_0_waiter * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        size_t count_0_self = DFGetCount(1);
        DFGetBytes((void *)self, count_0_self * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_sgx_thread_set_multiple_untrusted_events_ocall(
    const void **waiters, size_t total)
{
    int _fuzz_ret =
        sgx_thread_set_multiple_untrusted_events_ocall(waiters, total);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_pthread_wait_timeout_ocall(unsigned long long waiter,
                                           unsigned long long timeout)
{
    int _fuzz_ret = pthread_wait_timeout_ocall(waiter, timeout);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_pthread_create_ocall(unsigned long long self)
{
    int _fuzz_ret = pthread_create_ocall(self);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_pthread_wakeup_ocall(unsigned long long waiter)
{
    int _fuzz_ret = pthread_wakeup_ocall(waiter);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_open(const char *pathname, int flags, bool has_mode,
                           unsigned int mode)
{
    int _fuzz_ret = ocall_open(pathname, flags, has_mode, mode);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_openat(int dirfd, const char *pathname, int flags,
                             bool has_mode, unsigned int mode)
{
    int _fuzz_ret = ocall_openat(dirfd, pathname, flags, has_mode, mode);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_close(int fd)
{
    int _fuzz_ret = ocall_close(fd);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_read(int fd, void *buf, size_t read_size)
{
    ssize_t _fuzz_ret = ocall_read(fd, buf, read_size);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (read_size)) / 1;
        DFGetBytes((void *)buf, count_0_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

off_t
__ocall_wrapper_ocall_lseek(int fd, off_t offset, int whence)
{
    off_t _fuzz_ret = ocall_lseek(fd, offset, whence);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_ftruncate(int fd, off_t length)
{
    int _fuzz_ret = ocall_ftruncate(fd, length);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_fsync(int fd)
{
    int _fuzz_ret = ocall_fsync(fd);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_fdatasync(int fd)
{
    int _fuzz_ret = ocall_fdatasync(fd);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_isatty(int fd)
{
    int _fuzz_ret = ocall_isatty(fd);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

void
__ocall_wrapper_ocall_fdopendir(int fd, void **p_dirp)
{
    ocall_fdopendir(fd, p_dirp);
    if (DFModifyOCallRet()) {
        size_t count_0_p_dirp = ((1) * (sizeof(void *))) / sizeof(void *);
        for (size_t i_0_p_dirp = 0; i_0_p_dirp < count_0_p_dirp; i_0_p_dirp++) {
            void *p_dirp_0_deref = NULL;
            p_dirp_0_deref = p_dirp[i_0_p_dirp];
            size_t count_1_p_dirp_0_deref = DFGetCount(1);
            DFGetBytes((void *)p_dirp_0_deref, count_1_p_dirp_0_deref * 1,
                       FUZZ_DATA);
        }
    }
}

void *
__ocall_wrapper_ocall_readdir(void *dirp)
{
    void *_fuzz_ret = ocall_readdir(dirp);
    if (DFModifyOCallRet()) {
        size_t count_0_dirp = DFGetCount(1);
        DFGetBytes((void *)dirp, count_0_dirp * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        size_t count_0__fuzz_ret = DFGetCount(1);
        DFGetBytes((void *)_fuzz_ret, count_0__fuzz_ret * 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

void
__ocall_wrapper_ocall_rewinddir(void *dirp)
{
    ocall_rewinddir(dirp);
    if (DFModifyOCallRet()) {
        size_t count_0_dirp = DFGetCount(1);
        DFGetBytes((void *)dirp, count_0_dirp * 1, FUZZ_DATA);
    }
}

void
__ocall_wrapper_ocall_seekdir(void *dirp, long int loc)
{
    ocall_seekdir(dirp, loc);
    if (DFModifyOCallRet()) {
        size_t count_0_dirp = DFGetCount(1);
        DFGetBytes((void *)dirp, count_0_dirp * 1, FUZZ_DATA);
    }
}

long int
__ocall_wrapper_ocall_telldir(void *dirp)
{
    long int _fuzz_ret = ocall_telldir(dirp);
    if (DFModifyOCallRet()) {
        size_t count_0_dirp = DFGetCount(1);
        DFGetBytes((void *)dirp, count_0_dirp * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(long int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_closedir(void *dirp)
{
    int _fuzz_ret = ocall_closedir(dirp);
    if (DFModifyOCallRet()) {
        size_t count_0_dirp = DFGetCount(1);
        DFGetBytes((void *)dirp, count_0_dirp * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_stat(const char *pathname, void *buf,
                           unsigned int buf_len)
{
    int _fuzz_ret = ocall_stat(pathname, buf, buf_len);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (buf_len)) / 1;
        DFGetBytes((void *)buf, count_0_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_fstat(int fd, void *buf, unsigned int buf_len)
{
    int _fuzz_ret = ocall_fstat(fd, buf, buf_len);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (buf_len)) / 1;
        DFGetBytes((void *)buf, count_0_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_fstatat(int dirfd, const char *pathname, void *buf,
                              unsigned int buf_len, int flags)
{
    int _fuzz_ret = ocall_fstatat(dirfd, pathname, buf, buf_len, flags);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (buf_len)) / 1;
        DFGetBytes((void *)buf, count_0_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_mkdirat(int dirfd, const char *pathname,
                              unsigned int mode)
{
    int _fuzz_ret = ocall_mkdirat(dirfd, pathname, mode);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_link(const char *oldpath, const char *newpath)
{
    int _fuzz_ret = ocall_link(oldpath, newpath);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_linkat(int olddirfd, const char *oldpath, int newdirfd,
                             const char *newpath, int flags)
{
    int _fuzz_ret = ocall_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_unlinkat(int dirfd, const char *pathname, int flags)
{
    int _fuzz_ret = ocall_unlinkat(dirfd, pathname, flags);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    ssize_t _fuzz_ret = ocall_readlink(pathname, buf, bufsiz);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (bufsiz)) / sizeof(char);
        DFGetBytes((void *)buf, count_0_buf * sizeof(char), FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_readlinkat(int dirfd, const char *pathname, char *buf,
                                 size_t bufsiz)
{
    ssize_t _fuzz_ret = ocall_readlinkat(dirfd, pathname, buf, bufsiz);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (bufsiz)) / sizeof(char);
        DFGetBytes((void *)buf, count_0_buf * sizeof(char), FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_renameat(int olddirfd, const char *oldpath, int newdirfd,
                               const char *newpath)
{
    int _fuzz_ret = ocall_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_symlinkat(const char *target, int newdirfd,
                                const char *linkpath)
{
    int _fuzz_ret = ocall_symlinkat(target, newdirfd, linkpath);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_ioctl(int fd, unsigned long int request, void *arg,
                            unsigned int arg_len)
{
    int _fuzz_ret = ocall_ioctl(fd, request, arg, arg_len);
    if (DFModifyOCallRet()) {
        size_t count_0_arg = ((1) * (arg_len)) / 1;
        DFGetBytes((void *)arg, count_0_arg * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_fcntl(int fd, int cmd)
{
    int _fuzz_ret = ocall_fcntl(fd, cmd);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_fcntl_long(int fd, int cmd, long int arg)
{
    int _fuzz_ret = ocall_fcntl_long(fd, cmd, arg);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_realpath(const char *path, char *buf,
                               unsigned int buf_len)
{
    int _fuzz_ret = ocall_realpath(path, buf, buf_len);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (buf_len)) / sizeof(char);
        DFGetBytes((void *)buf, count_0_buf * sizeof(char), FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_posix_fallocate(int fd, off_t offset, off_t len)
{
    int _fuzz_ret = ocall_posix_fallocate(fd, offset, len);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_poll(void *fds, unsigned int nfds, int timeout,
                           unsigned int fds_len)
{
    int _fuzz_ret = ocall_poll(fds, nfds, timeout, fds_len);
    if (DFModifyOCallRet()) {
        size_t count_0_fds = ((1) * (fds_len)) / 1;
        DFGetBytes((void *)fds, count_0_fds * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_getopt(int argc, char *argv_buf,
                             unsigned int argv_buf_len, const char *optstring)
{
    int _fuzz_ret = ocall_getopt(argc, argv_buf, argv_buf_len, optstring);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_readv(int fd, char *iov_buf, unsigned int buf_size,
                            int iovcnt, bool has_offset, off_t offset)
{
    ssize_t _fuzz_ret =
        ocall_readv(fd, iov_buf, buf_size, iovcnt, has_offset, offset);
    if (DFModifyOCallRet()) {
        size_t count_0_iov_buf = ((1) * (buf_size)) / sizeof(char);
        DFGetBytes((void *)iov_buf, count_0_iov_buf * sizeof(char), FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_writev(int fd, char *iov_buf, unsigned int buf_size,
                             int iovcnt, bool has_offset, off_t offset)
{
    ssize_t _fuzz_ret =
        ocall_writev(fd, iov_buf, buf_size, iovcnt, has_offset, offset);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_clock_gettime(unsigned int clock_id, void *tp_buf,
                                    unsigned int tp_buf_size)
{
    int _fuzz_ret = ocall_clock_gettime(clock_id, tp_buf, tp_buf_size);
    if (DFModifyOCallRet()) {
        size_t count_0_tp_buf = ((1) * (tp_buf_size)) / 1;
        DFGetBytes((void *)tp_buf, count_0_tp_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_clock_getres(int clock_id, void *res_buf,
                                   unsigned int res_buf_size)
{
    int _fuzz_ret = ocall_clock_getres(clock_id, res_buf, res_buf_size);
    if (DFModifyOCallRet()) {
        size_t count_0_res_buf = ((1) * (res_buf_size)) / 1;
        DFGetBytes((void *)res_buf, count_0_res_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_utimensat(int dirfd, const char *pathname,
                                const void *times_buf,
                                unsigned int times_buf_size, int flags)
{
    int _fuzz_ret =
        ocall_utimensat(dirfd, pathname, times_buf, times_buf_size, flags);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_futimens(int fd, const void *times_buf,
                               unsigned int times_buf_size)
{
    int _fuzz_ret = ocall_futimens(fd, times_buf, times_buf_size);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_clock_nanosleep(unsigned int clock_id, int flags,
                                      const void *req_buf,
                                      unsigned int req_buf_size, void *rem_buf,
                                      unsigned int rem_buf_size)
{
    int _fuzz_ret = ocall_clock_nanosleep(clock_id, flags, req_buf,
                                          req_buf_size, rem_buf, rem_buf_size);
    if (DFModifyOCallRet()) {
        size_t count_0_rem_buf = ((1) * (rem_buf_size)) / 1;
        DFGetBytes((void *)rem_buf, count_0_rem_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_raise(int sig)
{
    int _fuzz_ret = ocall_raise(sig);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_sched_yield(void)
{
    int _fuzz_ret = ocall_sched_yield();
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_pthread_rwlock_init(void **rwlock, void *attr)
{
    int _fuzz_ret = ocall_pthread_rwlock_init(rwlock, attr);
    if (DFModifyOCallRet()) {
        size_t count_0_rwlock = ((1) * (sizeof(void *))) / sizeof(void *);
        for (size_t i_0_rwlock = 0; i_0_rwlock < count_0_rwlock; i_0_rwlock++) {
            void *rwlock_0_deref = NULL;
            rwlock_0_deref = rwlock[i_0_rwlock];
            size_t count_1_rwlock_0_deref = DFGetCount(1);
            DFGetBytes((void *)rwlock_0_deref, count_1_rwlock_0_deref * 1,
                       FUZZ_DATA);
        }
    }
    if (DFModifyOCallRet()) {
        size_t count_0_attr = DFGetCount(1);
        DFGetBytes((void *)attr, count_0_attr * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_pthread_rwlock_destroy(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_destroy(rwlock);
    if (DFModifyOCallRet()) {
        size_t count_0_rwlock = DFGetCount(1);
        DFGetBytes((void *)rwlock, count_0_rwlock * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_pthread_rwlock_rdlock(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_rdlock(rwlock);
    if (DFModifyOCallRet()) {
        size_t count_0_rwlock = DFGetCount(1);
        DFGetBytes((void *)rwlock, count_0_rwlock * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_pthread_rwlock_wrlock(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_wrlock(rwlock);
    if (DFModifyOCallRet()) {
        size_t count_0_rwlock = DFGetCount(1);
        DFGetBytes((void *)rwlock, count_0_rwlock * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_pthread_rwlock_unlock(void *rwlock)
{
    int _fuzz_ret = ocall_pthread_rwlock_unlock(rwlock);
    if (DFModifyOCallRet()) {
        size_t count_0_rwlock = DFGetCount(1);
        DFGetBytes((void *)rwlock, count_0_rwlock * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_get_errno(void)
{
    int _fuzz_ret = ocall_get_errno();
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_accept(int sockfd, void *addr, uint32_t *addrlen,
                             uint32_t addr_size)
{
    int _fuzz_ret = ocall_accept(sockfd, addr, addrlen, addr_size);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_bind(int sockfd, const void *addr, uint32_t addrlen)
{
    int _fuzz_ret = ocall_bind(sockfd, addr, addrlen);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_connect(int sockfd, void *addr, uint32_t addrlen)
{
    int _fuzz_ret = ocall_connect(sockfd, addr, addrlen);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_getsockname(int sockfd, void *addr, uint32_t *addrlen,
                                  uint32_t addr_size)
{
    int _fuzz_ret = ocall_getsockname(sockfd, addr, addrlen, addr_size);
    if (DFModifyOCallRet()) {
        size_t count_0_addr = ((1) * (addr_size)) / 1;
        DFGetBytes((void *)addr, count_0_addr * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        size_t count_0_addrlen = ((1) * (4)) / sizeof(uint32_t);
        DFGetBytes((void *)addrlen, count_0_addrlen * sizeof(uint32_t),
                   FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_getpeername(int sockfd, void *addr, uint32_t *addrlen,
                                  uint32_t addr_size)
{
    int _fuzz_ret = ocall_getpeername(sockfd, addr, addrlen, addr_size);
    if (DFModifyOCallRet()) {
        size_t count_0_addr = ((1) * (addr_size)) / 1;
        DFGetBytes((void *)addr, count_0_addr * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        size_t count_0_addrlen = ((1) * (4)) / sizeof(uint32_t);
        DFGetBytes((void *)addrlen, count_0_addrlen * sizeof(uint32_t),
                   FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_getsockopt(int sockfd, int level, int optname,
                                 void *val_buf, unsigned int val_buf_size,
                                 void *len_buf)
{
    int _fuzz_ret = ocall_getsockopt(sockfd, level, optname, val_buf,
                                     val_buf_size, len_buf);
    if (DFModifyOCallRet()) {
        size_t count_0_val_buf = ((1) * (val_buf_size)) / 1;
        DFGetBytes((void *)val_buf, count_0_val_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        size_t count_0_len_buf = ((1) * (4)) / 1;
        DFGetBytes((void *)len_buf, count_0_len_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_listen(int sockfd, int backlog)
{
    int _fuzz_ret = ocall_listen(sockfd, backlog);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    int _fuzz_ret = ocall_recv(sockfd, buf, len, flags);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (len)) / 1;
        DFGetBytes((void *)buf, count_0_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               void *src_addr, uint32_t *addrlen,
                               uint32_t addr_size)
{
    ssize_t _fuzz_ret =
        ocall_recvfrom(sockfd, buf, len, flags, src_addr, addrlen, addr_size);
    if (DFModifyOCallRet()) {
        size_t count_0_buf = ((1) * (len)) / 1;
        DFGetBytes((void *)buf, count_0_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        size_t count_0_src_addr = ((1) * (addr_size)) / 1;
        DFGetBytes((void *)src_addr, count_0_src_addr * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        size_t count_0_addrlen = ((1) * (4)) / sizeof(uint32_t);
        DFGetBytes((void *)addrlen, count_0_addrlen * sizeof(uint32_t),
                   FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_recvmsg(int sockfd, void *msg_buf,
                              unsigned int msg_buf_size, int flags)
{
    ssize_t _fuzz_ret = ocall_recvmsg(sockfd, msg_buf, msg_buf_size, flags);
    if (DFModifyOCallRet()) {
        size_t count_0_msg_buf = ((1) * (msg_buf_size)) / 1;
        DFGetBytes((void *)msg_buf, count_0_msg_buf * 1, FUZZ_DATA);
    }
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    int _fuzz_ret = ocall_send(sockfd, buf, len, flags);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_sendto(int sockfd, const void *buf, size_t len, int flags,
                             void *dest_addr, uint32_t addrlen)
{
    ssize_t _fuzz_ret =
        ocall_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

ssize_t
__ocall_wrapper_ocall_sendmsg(int sockfd, void *msg_buf,
                              unsigned int msg_buf_size, int flags)
{
    ssize_t _fuzz_ret = ocall_sendmsg(sockfd, msg_buf, msg_buf_size, flags);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, 1, FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_setsockopt(int sockfd, int level, int optname,
                                 void *optval, unsigned int optlen)
{
    int _fuzz_ret = ocall_setsockopt(sockfd, level, optname, optval, optlen);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_shutdown(int sockfd, int how)
{
    int _fuzz_ret = ocall_shutdown(sockfd, how);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}

int
__ocall_wrapper_ocall_socket(int domain, int type, int protocol)
{
    int _fuzz_ret = ocall_socket(domain, type, protocol);
    if (DFModifyOCallRet()) {
        DFGetBytes(&_fuzz_ret, sizeof(int), FUZZ_RET);
    }
    return _fuzz_ret;
}
static sgx_status_t SGX_CDECL
Enclave_ocall_print(void *pms)
{
    ms_ocall_print_t *ms = SGX_CAST(ms_ocall_print_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_print(ms->ms_str);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_sgx_oc_cpuidex(void *pms)
{
    ms_sgx_oc_cpuidex_t *ms = SGX_CAST(ms_sgx_oc_cpuidex_t *, pms);
    __ocall_wrapper_sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_sgx_thread_wait_untrusted_event_ocall(void *pms)
{
    ms_sgx_thread_wait_untrusted_event_ocall_t *ms =
        SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_sgx_thread_set_untrusted_event_ocall(void *pms)
{
    ms_sgx_thread_set_untrusted_event_ocall_t *ms =
        SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_sgx_thread_setwait_untrusted_events_ocall(void *pms)
{
    ms_sgx_thread_setwait_untrusted_events_ocall_t *ms =
        SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t *, pms);
    ms->ms_retval = __ocall_wrapper_sgx_thread_setwait_untrusted_events_ocall(
        ms->ms_waiter, ms->ms_self);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void *pms)
{
    ms_sgx_thread_set_multiple_untrusted_events_ocall_t *ms =
        SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_sgx_thread_set_multiple_untrusted_events_ocall(
            ms->ms_waiters, ms->ms_total);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_pthread_wait_timeout_ocall(void *pms)
{
    ms_pthread_wait_timeout_ocall_t *ms =
        SGX_CAST(ms_pthread_wait_timeout_ocall_t *, pms);
    ms->ms_retval = __ocall_wrapper_pthread_wait_timeout_ocall(ms->ms_waiter,
                                                               ms->ms_timeout);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_pthread_create_ocall(void *pms)
{
    ms_pthread_create_ocall_t *ms = SGX_CAST(ms_pthread_create_ocall_t *, pms);
    ms->ms_retval = __ocall_wrapper_pthread_create_ocall(ms->ms_self);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_pthread_wakeup_ocall(void *pms)
{
    ms_pthread_wakeup_ocall_t *ms = SGX_CAST(ms_pthread_wakeup_ocall_t *, pms);
    ms->ms_retval = __ocall_wrapper_pthread_wakeup_ocall(ms->ms_waiter);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_open(void *pms)
{
    ms_ocall_open_t *ms = SGX_CAST(ms_ocall_open_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_open(ms->ms_pathname, ms->ms_flags,
                                               ms->ms_has_mode, ms->ms_mode);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_openat(void *pms)
{
    ms_ocall_openat_t *ms = SGX_CAST(ms_ocall_openat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_openat(ms->ms_dirfd, ms->ms_pathname,
                                                 ms->ms_flags, ms->ms_has_mode,
                                                 ms->ms_mode);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_close(void *pms)
{
    ms_ocall_close_t *ms = SGX_CAST(ms_ocall_close_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_close(ms->ms_fd);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_read(void *pms)
{
    ms_ocall_read_t *ms = SGX_CAST(ms_ocall_read_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_read(ms->ms_fd, ms->ms_buf, ms->ms_read_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_lseek(void *pms)
{
    ms_ocall_lseek_t *ms = SGX_CAST(ms_ocall_lseek_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_lseek(ms->ms_fd, ms->ms_offset, ms->ms_whence);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_ftruncate(void *pms)
{
    ms_ocall_ftruncate_t *ms = SGX_CAST(ms_ocall_ftruncate_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_ftruncate(ms->ms_fd, ms->ms_length);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_fsync(void *pms)
{
    ms_ocall_fsync_t *ms = SGX_CAST(ms_ocall_fsync_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_fsync(ms->ms_fd);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_fdatasync(void *pms)
{
    ms_ocall_fdatasync_t *ms = SGX_CAST(ms_ocall_fdatasync_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_fdatasync(ms->ms_fd);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_isatty(void *pms)
{
    ms_ocall_isatty_t *ms = SGX_CAST(ms_ocall_isatty_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_isatty(ms->ms_fd);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_fdopendir(void *pms)
{
    ms_ocall_fdopendir_t *ms = SGX_CAST(ms_ocall_fdopendir_t *, pms);
    __ocall_wrapper_ocall_fdopendir(ms->ms_fd, ms->ms_p_dirp);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_readdir(void *pms)
{
    ms_ocall_readdir_t *ms = SGX_CAST(ms_ocall_readdir_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_readdir(ms->ms_dirp);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_rewinddir(void *pms)
{
    ms_ocall_rewinddir_t *ms = SGX_CAST(ms_ocall_rewinddir_t *, pms);
    __ocall_wrapper_ocall_rewinddir(ms->ms_dirp);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_seekdir(void *pms)
{
    ms_ocall_seekdir_t *ms = SGX_CAST(ms_ocall_seekdir_t *, pms);
    __ocall_wrapper_ocall_seekdir(ms->ms_dirp, ms->ms_loc);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_telldir(void *pms)
{
    ms_ocall_telldir_t *ms = SGX_CAST(ms_ocall_telldir_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_telldir(ms->ms_dirp);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_closedir(void *pms)
{
    ms_ocall_closedir_t *ms = SGX_CAST(ms_ocall_closedir_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_closedir(ms->ms_dirp);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_stat(void *pms)
{
    ms_ocall_stat_t *ms = SGX_CAST(ms_ocall_stat_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_stat(ms->ms_pathname, ms->ms_buf, ms->ms_buf_len);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_fstat(void *pms)
{
    ms_ocall_fstat_t *ms = SGX_CAST(ms_ocall_fstat_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_fstat(ms->ms_fd, ms->ms_buf, ms->ms_buf_len);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_fstatat(void *pms)
{
    ms_ocall_fstatat_t *ms = SGX_CAST(ms_ocall_fstatat_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_fstatat(ms->ms_dirfd, ms->ms_pathname, ms->ms_buf,
                                      ms->ms_buf_len, ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_mkdirat(void *pms)
{
    ms_ocall_mkdirat_t *ms = SGX_CAST(ms_ocall_mkdirat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_mkdirat(ms->ms_dirfd, ms->ms_pathname,
                                                  ms->ms_mode);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_link(void *pms)
{
    ms_ocall_link_t *ms = SGX_CAST(ms_ocall_link_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_link(ms->ms_oldpath, ms->ms_newpath);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_linkat(void *pms)
{
    ms_ocall_linkat_t *ms = SGX_CAST(ms_ocall_linkat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_linkat(
        ms->ms_olddirfd, ms->ms_oldpath, ms->ms_newdirfd, ms->ms_newpath,
        ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_unlinkat(void *pms)
{
    ms_ocall_unlinkat_t *ms = SGX_CAST(ms_ocall_unlinkat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_unlinkat(
        ms->ms_dirfd, ms->ms_pathname, ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_readlink(void *pms)
{
    ms_ocall_readlink_t *ms = SGX_CAST(ms_ocall_readlink_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_readlink(ms->ms_pathname, ms->ms_buf,
                                                   ms->ms_bufsiz);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_readlinkat(void *pms)
{
    ms_ocall_readlinkat_t *ms = SGX_CAST(ms_ocall_readlinkat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_readlinkat(
        ms->ms_dirfd, ms->ms_pathname, ms->ms_buf, ms->ms_bufsiz);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_renameat(void *pms)
{
    ms_ocall_renameat_t *ms = SGX_CAST(ms_ocall_renameat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_renameat(
        ms->ms_olddirfd, ms->ms_oldpath, ms->ms_newdirfd, ms->ms_newpath);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_symlinkat(void *pms)
{
    ms_ocall_symlinkat_t *ms = SGX_CAST(ms_ocall_symlinkat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_symlinkat(
        ms->ms_target, ms->ms_newdirfd, ms->ms_linkpath);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_ioctl(void *pms)
{
    ms_ocall_ioctl_t *ms = SGX_CAST(ms_ocall_ioctl_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_ioctl(ms->ms_fd, ms->ms_request,
                                                ms->ms_arg, ms->ms_arg_len);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_fcntl(void *pms)
{
    ms_ocall_fcntl_t *ms = SGX_CAST(ms_ocall_fcntl_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_fcntl(ms->ms_fd, ms->ms_cmd);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_fcntl_long(void *pms)
{
    ms_ocall_fcntl_long_t *ms = SGX_CAST(ms_ocall_fcntl_long_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_fcntl_long(ms->ms_fd, ms->ms_cmd, ms->ms_arg);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_realpath(void *pms)
{
    ms_ocall_realpath_t *ms = SGX_CAST(ms_ocall_realpath_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_realpath(ms->ms_path, ms->ms_buf, ms->ms_buf_len);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_posix_fallocate(void *pms)
{
    ms_ocall_posix_fallocate_t *ms =
        SGX_CAST(ms_ocall_posix_fallocate_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_posix_fallocate(
        ms->ms_fd, ms->ms_offset, ms->ms_len);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_poll(void *pms)
{
    ms_ocall_poll_t *ms = SGX_CAST(ms_ocall_poll_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_poll(ms->ms_fds, ms->ms_nfds,
                                               ms->ms_timeout, ms->ms_fds_len);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_getopt(void *pms)
{
    ms_ocall_getopt_t *ms = SGX_CAST(ms_ocall_getopt_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_getopt(
        ms->ms_argc, ms->ms_argv_buf, ms->ms_argv_buf_len, ms->ms_optstring);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_readv(void *pms)
{
    ms_ocall_readv_t *ms = SGX_CAST(ms_ocall_readv_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_readv(
        ms->ms_fd, ms->ms_iov_buf, ms->ms_buf_size, ms->ms_iovcnt,
        ms->ms_has_offset, ms->ms_offset);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_writev(void *pms)
{
    ms_ocall_writev_t *ms = SGX_CAST(ms_ocall_writev_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_writev(
        ms->ms_fd, ms->ms_iov_buf, ms->ms_buf_size, ms->ms_iovcnt,
        ms->ms_has_offset, ms->ms_offset);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_clock_gettime(void *pms)
{
    ms_ocall_clock_gettime_t *ms = SGX_CAST(ms_ocall_clock_gettime_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_clock_gettime(
        ms->ms_clock_id, ms->ms_tp_buf, ms->ms_tp_buf_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_clock_getres(void *pms)
{
    ms_ocall_clock_getres_t *ms = SGX_CAST(ms_ocall_clock_getres_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_clock_getres(
        ms->ms_clock_id, ms->ms_res_buf, ms->ms_res_buf_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_utimensat(void *pms)
{
    ms_ocall_utimensat_t *ms = SGX_CAST(ms_ocall_utimensat_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_utimensat(
        ms->ms_dirfd, ms->ms_pathname, ms->ms_times_buf, ms->ms_times_buf_size,
        ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_futimens(void *pms)
{
    ms_ocall_futimens_t *ms = SGX_CAST(ms_ocall_futimens_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_futimens(ms->ms_fd, ms->ms_times_buf,
                                                   ms->ms_times_buf_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_clock_nanosleep(void *pms)
{
    ms_ocall_clock_nanosleep_t *ms =
        SGX_CAST(ms_ocall_clock_nanosleep_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_clock_nanosleep(
        ms->ms_clock_id, ms->ms_flags, ms->ms_req_buf, ms->ms_req_buf_size,
        ms->ms_rem_buf, ms->ms_rem_buf_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_raise(void *pms)
{
    ms_ocall_raise_t *ms = SGX_CAST(ms_ocall_raise_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_raise(ms->ms_sig);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_sched_yield(void *pms)
{
    ms_ocall_sched_yield_t *ms = SGX_CAST(ms_ocall_sched_yield_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_sched_yield();

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_pthread_rwlock_init(void *pms)
{
    ms_ocall_pthread_rwlock_init_t *ms =
        SGX_CAST(ms_ocall_pthread_rwlock_init_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_pthread_rwlock_init(ms->ms_rwlock, ms->ms_attr);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_pthread_rwlock_destroy(void *pms)
{
    ms_ocall_pthread_rwlock_destroy_t *ms =
        SGX_CAST(ms_ocall_pthread_rwlock_destroy_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_pthread_rwlock_destroy(ms->ms_rwlock);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_pthread_rwlock_rdlock(void *pms)
{
    ms_ocall_pthread_rwlock_rdlock_t *ms =
        SGX_CAST(ms_ocall_pthread_rwlock_rdlock_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_pthread_rwlock_rdlock(ms->ms_rwlock);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_pthread_rwlock_wrlock(void *pms)
{
    ms_ocall_pthread_rwlock_wrlock_t *ms =
        SGX_CAST(ms_ocall_pthread_rwlock_wrlock_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_pthread_rwlock_wrlock(ms->ms_rwlock);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_pthread_rwlock_unlock(void *pms)
{
    ms_ocall_pthread_rwlock_unlock_t *ms =
        SGX_CAST(ms_ocall_pthread_rwlock_unlock_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_pthread_rwlock_unlock(ms->ms_rwlock);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_get_errno(void *pms)
{
    ms_ocall_get_errno_t *ms = SGX_CAST(ms_ocall_get_errno_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_get_errno();

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_accept(void *pms)
{
    ms_ocall_accept_t *ms = SGX_CAST(ms_ocall_accept_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_accept(
        ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen, ms->ms_addr_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_bind(void *pms)
{
    ms_ocall_bind_t *ms = SGX_CAST(ms_ocall_bind_t *, pms);
    ms->ms_retval =
        __ocall_wrapper_ocall_bind(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_connect(void *pms)
{
    ms_ocall_connect_t *ms = SGX_CAST(ms_ocall_connect_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_connect(ms->ms_sockfd, ms->ms_addr,
                                                  ms->ms_addrlen);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_getsockname(void *pms)
{
    ms_ocall_getsockname_t *ms = SGX_CAST(ms_ocall_getsockname_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_getsockname(
        ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen, ms->ms_addr_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_getpeername(void *pms)
{
    ms_ocall_getpeername_t *ms = SGX_CAST(ms_ocall_getpeername_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_getpeername(
        ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen, ms->ms_addr_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_getsockopt(void *pms)
{
    ms_ocall_getsockopt_t *ms = SGX_CAST(ms_ocall_getsockopt_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_getsockopt(
        ms->ms_sockfd, ms->ms_level, ms->ms_optname, ms->ms_val_buf,
        ms->ms_val_buf_size, ms->ms_len_buf);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_listen(void *pms)
{
    ms_ocall_listen_t *ms = SGX_CAST(ms_ocall_listen_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_listen(ms->ms_sockfd, ms->ms_backlog);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_recv(void *pms)
{
    ms_ocall_recv_t *ms = SGX_CAST(ms_ocall_recv_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_recv(ms->ms_sockfd, ms->ms_buf,
                                               ms->ms_len, ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_recvfrom(void *pms)
{
    ms_ocall_recvfrom_t *ms = SGX_CAST(ms_ocall_recvfrom_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_recvfrom(
        ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_src_addr,
        ms->ms_addrlen, ms->ms_addr_size);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_recvmsg(void *pms)
{
    ms_ocall_recvmsg_t *ms = SGX_CAST(ms_ocall_recvmsg_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_recvmsg(
        ms->ms_sockfd, ms->ms_msg_buf, ms->ms_msg_buf_size, ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_send(void *pms)
{
    ms_ocall_send_t *ms = SGX_CAST(ms_ocall_send_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_send(ms->ms_sockfd, ms->ms_buf,
                                               ms->ms_len, ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_sendto(void *pms)
{
    ms_ocall_sendto_t *ms = SGX_CAST(ms_ocall_sendto_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_sendto(
        ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_dest_addr,
        ms->ms_addrlen);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_sendmsg(void *pms)
{
    ms_ocall_sendmsg_t *ms = SGX_CAST(ms_ocall_sendmsg_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_sendmsg(
        ms->ms_sockfd, ms->ms_msg_buf, ms->ms_msg_buf_size, ms->ms_flags);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_setsockopt(void *pms)
{
    ms_ocall_setsockopt_t *ms = SGX_CAST(ms_ocall_setsockopt_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_setsockopt(
        ms->ms_sockfd, ms->ms_level, ms->ms_optname, ms->ms_optval,
        ms->ms_optlen);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_shutdown(void *pms)
{
    ms_ocall_shutdown_t *ms = SGX_CAST(ms_ocall_shutdown_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_shutdown(ms->ms_sockfd, ms->ms_how);

    return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL
Enclave_ocall_socket(void *pms)
{
    ms_ocall_socket_t *ms = SGX_CAST(ms_ocall_socket_t *, pms);
    ms->ms_retval = __ocall_wrapper_ocall_socket(ms->ms_domain, ms->ms_type,
                                                 ms->ms_protocol);

    return SGX_SUCCESS;
}

static const struct {
    size_t nr_ocall;
    void *table[73];
} ocall_table_Enclave = {
    73,
    {
        (void *)Enclave_ocall_print,
        (void *)Enclave_sgx_oc_cpuidex,
        (void *)Enclave_sgx_thread_wait_untrusted_event_ocall,
        (void *)Enclave_sgx_thread_set_untrusted_event_ocall,
        (void *)Enclave_sgx_thread_setwait_untrusted_events_ocall,
        (void *)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
        (void *)Enclave_pthread_wait_timeout_ocall,
        (void *)Enclave_pthread_create_ocall,
        (void *)Enclave_pthread_wakeup_ocall,
        (void *)Enclave_ocall_open,
        (void *)Enclave_ocall_openat,
        (void *)Enclave_ocall_close,
        (void *)Enclave_ocall_read,
        (void *)Enclave_ocall_lseek,
        (void *)Enclave_ocall_ftruncate,
        (void *)Enclave_ocall_fsync,
        (void *)Enclave_ocall_fdatasync,
        (void *)Enclave_ocall_isatty,
        (void *)Enclave_ocall_fdopendir,
        (void *)Enclave_ocall_readdir,
        (void *)Enclave_ocall_rewinddir,
        (void *)Enclave_ocall_seekdir,
        (void *)Enclave_ocall_telldir,
        (void *)Enclave_ocall_closedir,
        (void *)Enclave_ocall_stat,
        (void *)Enclave_ocall_fstat,
        (void *)Enclave_ocall_fstatat,
        (void *)Enclave_ocall_mkdirat,
        (void *)Enclave_ocall_link,
        (void *)Enclave_ocall_linkat,
        (void *)Enclave_ocall_unlinkat,
        (void *)Enclave_ocall_readlink,
        (void *)Enclave_ocall_readlinkat,
        (void *)Enclave_ocall_renameat,
        (void *)Enclave_ocall_symlinkat,
        (void *)Enclave_ocall_ioctl,
        (void *)Enclave_ocall_fcntl,
        (void *)Enclave_ocall_fcntl_long,
        (void *)Enclave_ocall_realpath,
        (void *)Enclave_ocall_posix_fallocate,
        (void *)Enclave_ocall_poll,
        (void *)Enclave_ocall_getopt,
        (void *)Enclave_ocall_readv,
        (void *)Enclave_ocall_writev,
        (void *)Enclave_ocall_clock_gettime,
        (void *)Enclave_ocall_clock_getres,
        (void *)Enclave_ocall_utimensat,
        (void *)Enclave_ocall_futimens,
        (void *)Enclave_ocall_clock_nanosleep,
        (void *)Enclave_ocall_raise,
        (void *)Enclave_ocall_sched_yield,
        (void *)Enclave_ocall_pthread_rwlock_init,
        (void *)Enclave_ocall_pthread_rwlock_destroy,
        (void *)Enclave_ocall_pthread_rwlock_rdlock,
        (void *)Enclave_ocall_pthread_rwlock_wrlock,
        (void *)Enclave_ocall_pthread_rwlock_unlock,
        (void *)Enclave_ocall_get_errno,
        (void *)Enclave_ocall_accept,
        (void *)Enclave_ocall_bind,
        (void *)Enclave_ocall_connect,
        (void *)Enclave_ocall_getsockname,
        (void *)Enclave_ocall_getpeername,
        (void *)Enclave_ocall_getsockopt,
        (void *)Enclave_ocall_listen,
        (void *)Enclave_ocall_recv,
        (void *)Enclave_ocall_recvfrom,
        (void *)Enclave_ocall_recvmsg,
        (void *)Enclave_ocall_send,
        (void *)Enclave_ocall_sendto,
        (void *)Enclave_ocall_sendmsg,
        (void *)Enclave_ocall_setsockopt,
        (void *)Enclave_ocall_shutdown,
        (void *)Enclave_ocall_socket,
    }
};

sgx_status_t
ecall_handle_command(sgx_enclave_id_t eid, unsigned int cmd, uint8_t *cmd_buf,
                     unsigned int cmd_buf_size)
{
    sgx_status_t status;
    ms_ecall_handle_command_t ms;
    ms.ms_cmd = cmd;
    ms.ms_cmd_buf = cmd_buf;
    ms.ms_cmd_buf_size = cmd_buf_size;
    status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
    return status;
}

sgx_status_t
ecall_iwasm_main(sgx_enclave_id_t eid, uint8_t *wasm_file_buf,
                 uint32_t wasm_file_size)
{
    sgx_status_t status;
    ms_ecall_iwasm_main_t ms;
    ms.ms_wasm_file_buf = wasm_file_buf;
    ms.ms_wasm_file_size = wasm_file_size;
    status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
    return status;
}

sgx_status_t
fuzz_ecall_handle_command(void)
{
    unsigned int cmd;
    DFGetBytes(&cmd, sizeof(unsigned int), FUZZ_DATA);
    cmd = cmd % 15;
    uint8_t *cmd_buf = NULL;
    unsigned int cmd_buf_size;
    cmd_buf_size = DFGetSize();
    cmd_buf = NULL;
    if (!DFSetNull()) {
        size_t count_0_cmd_buf =
            ((1) * (cmd_buf_size) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
        cmd_buf = (uint8_t *)DFManagedCalloc(count_0_cmd_buf, sizeof(uint8_t));
        DFGetBytes((void *)cmd_buf, count_0_cmd_buf * sizeof(uint8_t),
                   FUZZ_DATA);
    }
    sgx_status_t status = ecall_handle_command(
        __hidden_sgxfuzzer_harness_global_eid, cmd, cmd_buf, cmd_buf_size);
    return status;
}

sgx_status_t
fuzz_ecall_iwasm_main(void)
{
    uint8_t *wasm_file_buf = NULL;
    wasm_file_buf = NULL;
    if (!DFSetNull()) {
        size_t count_0_wasm_file_buf = DFGetCount(sizeof(uint8_t));
        wasm_file_buf =
            (uint8_t *)DFManagedCalloc(count_0_wasm_file_buf, sizeof(uint8_t));
        DFGetBytes((void *)wasm_file_buf,
                   count_0_wasm_file_buf * sizeof(uint8_t), FUZZ_DATA);
    }
    uint32_t wasm_file_size;
    DFGetBytes(&wasm_file_size, sizeof(uint32_t), FUZZ_DATA);
    sgx_status_t status = ecall_iwasm_main(
        __hidden_sgxfuzzer_harness_global_eid, wasm_file_buf, wasm_file_size);
    return status;
}
int gFuzzECallNum = 2;

sgx_status_t (*gFuzzECallArray[])(void) = { fuzz_ecall_handle_command,
                                            fuzz_ecall_iwasm_main };

const char *gFuzzECallNameArray[] = { "fuzz_ecall_handle_command",
                                      "fuzz_ecall_iwasm_main" };
