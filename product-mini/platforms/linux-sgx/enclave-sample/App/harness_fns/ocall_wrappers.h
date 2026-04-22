#pragma once

/* OCall wrappers for wasm-micro-runtime
 *
 * These hook the weak-symbol _harness_ocall_* points in Enclave_u.c,
 * replacing the real OCall implementations with fuzz-controlled responses.
 *
 * Without these, WASM code inside the enclave that tries to do file I/O,
 * networking, etc. would call the real App.cpp implementations, which may
 * fail unpredictably and prevent the fuzzer from reaching deeper paths.
 *
 * With these wrappers, the fuzzer controls what data comes back from OCalls,
 * enabling deeper exploration of the enclave's response to various I/O results.
 */

extern "C" {

/* ---- File I/O OCalls ---- */

/* ocall_print: suppress printf output during fuzzing */
int _harness_ocall_print(const char *str) {
    (void)str;
    return 0;
}

/* ocall_open: return a fake fd or -1 */
int _harness_ocall_open(const char *pathname, int flags, bool has_mode,
                        unsigned mode) {
    (void)pathname; (void)flags; (void)has_mode; (void)mode;
    /* 80% success with a fake fd, 20% error */
    if (g_fdp->ConsumeProbability<double>() < 0.2)
        return -1;
    return g_fdp->ConsumeIntegralInRange<int>(3, 1024);
}

/* ocall_openat */
int _harness_ocall_openat(int dirfd, const char *pathname, int flags,
                          bool has_mode, unsigned mode) {
    (void)dirfd; (void)pathname; (void)flags; (void)has_mode; (void)mode;
    if (g_fdp->ConsumeProbability<double>() < 0.2)
        return -1;
    return g_fdp->ConsumeIntegralInRange<int>(3, 1024);
}

/* ocall_close: mostly succeed */
int _harness_ocall_close(int fd) {
    (void)fd;
    return g_fdp->ConsumeProbability<double>() < 0.9 ? 0 : -1;
}

/* ocall_read: fill buffer with fuzz data */
ssize_t _harness_ocall_read(int fd, void *buf, size_t read_size) {
    (void)fd;
    if (!buf || read_size == 0) return 0;
    if (g_fdp->ConsumeProbability<double>() < 0.1)
        return -1; /* simulate read error */
    size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, read_size);
    if (n > 0 && g_fdp->remaining_bytes() >= n)
        g_fdp->ConsumeData(buf, n);
    return (ssize_t)n;
}

/* ocall_lseek */
off_t _harness_ocall_lseek(int fd, off_t offset, int whence) {
    (void)fd; (void)offset; (void)whence;
    if (g_fdp->ConsumeProbability<double>() < 0.1)
        return (off_t)-1;
    return g_fdp->ConsumeIntegralInRange<off_t>(0, 65536);
}

/* ocall_ftruncate */
int _harness_ocall_ftruncate(int fd, off_t length) {
    (void)fd; (void)length;
    return g_fdp->ConsumeProbability<double>() < 0.8 ? 0 : -1;
}

/* ocall_fsync */
int _harness_ocall_fsync(int fd) {
    (void)fd;
    return 0;
}

/* ocall_fdatasync */
int _harness_ocall_fdatasync(int fd) {
    (void)fd;
    return 0;
}

/* ocall_isatty */
int _harness_ocall_isatty(int fd) {
    (void)fd;
    return g_fdp->ConsumeProbability<double>() < 0.9 ? 0 : 1;
}

/* ocall_fdopendir */
void _harness_ocall_fdopendir(int fd, void **p_dirp) {
    (void)fd;
    if (p_dirp) {
        if (g_fdp->ConsumeProbability<double>() < 0.2)
            *p_dirp = NULL;
        else
            *p_dirp = (void *)(uintptr_t)g_fdp->ConsumeIntegral<uintptr_t>();
    }
}

/* ocall_readdir: return NULL most of the time to end quickly */
void *_harness_ocall_readdir(void *dirp) {
    (void)dirp;
    if (g_fdp->ConsumeProbability<double>() < 0.8)
        return NULL;
    /* Return a fake pointer — the enclave should handle this */
    return (void *)(uintptr_t)g_fdp->ConsumeIntegral<uintptr_t>();
}

/* ocall_rewinddir */
void _harness_ocall_rewinddir(void *dirp) {
    (void)dirp;
}

/* ocall_seekdir */
void _harness_ocall_seekdir(void *dirp, long loc) {
    (void)dirp; (void)loc;
}

/* ocall_telldir */
long _harness_ocall_telldir(void *dirp) {
    (void)dirp;
    return g_fdp->ConsumeIntegralInRange<long>(0, 1000);
}

/* ocall_closedir */
int _harness_ocall_closedir(void *dirp) {
    (void)dirp;
    return 0;
}

/* ---- File metadata OCalls ---- */

/* ocall_stat: fill stat buffer with fuzz data */
int _harness_ocall_stat(const char *pathname, void *buf, unsigned int buf_len) {
    (void)pathname;
    if (buf && buf_len > 0 && g_fdp->remaining_bytes() >= buf_len)
        g_fdp->ConsumeData(buf, buf_len);
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_fstat */
int _harness_ocall_fstat(int fd, void *buf, unsigned int buf_len) {
    (void)fd;
    if (buf && buf_len > 0 && g_fdp->remaining_bytes() >= buf_len)
        g_fdp->ConsumeData(buf, buf_len);
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_fstatat */
int _harness_ocall_fstatat(int dirfd, const char *pathname, void *buf,
                           unsigned int buf_len, int flags) {
    (void)dirfd; (void)pathname; (void)flags;
    if (buf && buf_len > 0 && g_fdp->remaining_bytes() >= buf_len)
        g_fdp->ConsumeData(buf, buf_len);
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_mkdirat */
int _harness_ocall_mkdirat(int dirfd, const char *pathname, unsigned mode) {
    (void)dirfd; (void)pathname; (void)mode;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_link */
int _harness_ocall_link(const char *oldpath, const char *newpath) {
    (void)oldpath; (void)newpath;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_linkat */
int _harness_ocall_linkat(int olddirfd, const char *oldpath, int newdirfd,
                          const char *newpath, int flags) {
    (void)olddirfd; (void)oldpath; (void)newdirfd; (void)newpath; (void)flags;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_unlinkat */
int _harness_ocall_unlinkat(int dirfd, const char *pathname, int flags) {
    (void)dirfd; (void)pathname; (void)flags;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_readlink */
ssize_t _harness_ocall_readlink(const char *pathname, char *buf, size_t bufsiz) {
    (void)pathname;
    if (!buf || bufsiz == 0) return 0;
    size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, bufsiz);
    if (n > 0 && g_fdp->remaining_bytes() >= n)
        g_fdp->ConsumeData(buf, n);
    return (ssize_t)n;
}

/* ocall_readlinkat */
ssize_t _harness_ocall_readlinkat(int dirfd, const char *pathname, char *buf,
                                  size_t bufsiz) {
    (void)dirfd; (void)pathname;
    if (!buf || bufsiz == 0) return 0;
    size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, bufsiz);
    if (n > 0 && g_fdp->remaining_bytes() >= n)
        g_fdp->ConsumeData(buf, n);
    return (ssize_t)n;
}

/* ocall_renameat */
int _harness_ocall_renameat(int olddirfd, const char *oldpath, int newdirfd,
                            const char *newpath) {
    (void)olddirfd; (void)oldpath; (void)newdirfd; (void)newpath;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_symlinkat */
int _harness_ocall_symlinkat(const char *target, int newdirfd,
                             const char *linkpath) {
    (void)target; (void)newdirfd; (void)linkpath;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_realpath */
int _harness_ocall_realpath(const char *path, char *buf, unsigned int buf_len) {
    (void)path;
    if (buf && buf_len > 0) {
        size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, buf_len - 1);
        if (n > 0 && g_fdp->remaining_bytes() >= n)
            g_fdp->ConsumeData(buf, n);
        buf[n < buf_len ? n : buf_len - 1] = '\0';
    }
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ---- Other file OCalls ---- */

/* ocall_ioctl */
int _harness_ocall_ioctl(int fd, unsigned long request, void *arg,
                         unsigned int arg_len) {
    (void)fd; (void)request;
    if (arg && arg_len > 0 && g_fdp->remaining_bytes() >= arg_len)
        g_fdp->ConsumeData(arg, arg_len);
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_fcntl */
int _harness_ocall_fcntl(int fd, int cmd) {
    (void)fd; (void)cmd;
    return g_fdp->ConsumeIntegralInRange<int>(-1, 1024);
}

/* ocall_fcntl_long */
int _harness_ocall_fcntl_long(int fd, int cmd, long arg) {
    (void)fd; (void)cmd; (void)arg;
    return g_fdp->ConsumeIntegralInRange<int>(-1, 1024);
}

/* ocall_posix_fallocate */
int _harness_ocall_posix_fallocate(int fd, off_t offset, off_t len) {
    (void)fd; (void)offset; (void)len;
    return g_fdp->ConsumeProbability<double>() < 0.8 ? 0 : -1;
}

/* ocall_poll */
int _harness_ocall_poll(void *fds, unsigned nfds, int timeout,
                        unsigned int fds_len) {
    (void)fds; (void)nfds; (void)timeout; (void)fds_len;
    return g_fdp->ConsumeIntegralInRange<int>(-1, (int)nfds);
}

/* ocall_getopt */
int _harness_ocall_getopt(int argc, char *argv_buf, unsigned int argv_buf_len,
                          const char *optstring) {
    (void)argc; (void)argv_buf; (void)argv_buf_len; (void)optstring;
    return -1; /* no more options */
}

/* ocall_readv */
ssize_t _harness_ocall_readv(int fd, char *iov_buf, unsigned int buf_size,
                             int iovcnt, bool has_offset, off_t offset) {
    (void)fd; (void)iovcnt; (void)has_offset; (void)offset;
    if (!iov_buf || buf_size == 0) return 0;
    if (g_fdp->ConsumeProbability<double>() < 0.1) return -1;
    size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, buf_size);
    if (n > 0 && g_fdp->remaining_bytes() >= n)
        g_fdp->ConsumeData(iov_buf, n);
    return (ssize_t)n;
}

/* ocall_writev */
ssize_t _harness_ocall_writev(int fd, char *iov_buf, unsigned int buf_size,
                              int iovcnt, bool has_offset, off_t offset) {
    (void)fd; (void)iov_buf; (void)buf_size; (void)iovcnt;
    (void)has_offset; (void)offset;
    return g_fdp->ConsumeIntegralInRange<ssize_t>(-1, 4096);
}

/* ---- Time OCalls ---- */

/* ocall_clock_gettime */
int _harness_ocall_clock_gettime(unsigned clock_id, void *tp_buf,
                                 unsigned tp_buf_size) {
    (void)clock_id;
    if (tp_buf && tp_buf_size > 0 && g_fdp->remaining_bytes() >= tp_buf_size)
        g_fdp->ConsumeData(tp_buf, tp_buf_size);
    return 0;
}

/* ocall_clock_getres */
int _harness_ocall_clock_getres(int clock_id, void *res_buf,
                                unsigned res_buf_size) {
    (void)clock_id;
    if (res_buf && res_buf_size > 0 && g_fdp->remaining_bytes() >= res_buf_size)
        g_fdp->ConsumeData(res_buf, res_buf_size);
    return 0;
}

/* ocall_utimensat */
int _harness_ocall_utimensat(int dirfd, const char *pathname,
                             const void *times_buf, unsigned times_buf_size,
                             int flags) {
    (void)dirfd; (void)pathname; (void)times_buf; (void)times_buf_size;
    (void)flags;
    return g_fdp->ConsumeProbability<double>() < 0.8 ? 0 : -1;
}

/* ocall_futimens */
int _harness_ocall_futimens(int fd, const void *times_buf,
                            unsigned times_buf_size) {
    (void)fd; (void)times_buf; (void)times_buf_size;
    return g_fdp->ConsumeProbability<double>() < 0.8 ? 0 : -1;
}

/* ocall_clock_nanosleep */
int _harness_ocall_clock_nanosleep(unsigned clock_id, int flags,
                                   const void *req_buf, unsigned req_buf_size,
                                   void *rem_buf, unsigned rem_buf_size) {
    (void)clock_id; (void)flags; (void)req_buf; (void)req_buf_size;
    (void)rem_buf; (void)rem_buf_size;
    return 0;
}

/* ---- Signal/Thread OCalls ---- */

/* ocall_raise */
int _harness_ocall_raise(int sig) {
    (void)sig;
    return 0;
}

/* ocall_sched_yield */
int _harness_ocall_sched_yield(void) {
    return 0;
}

/* ocall_pthread_rwlock_init */
int _harness_ocall_pthread_rwlock_init(void **rwlock, void *attr) {
    (void)attr;
    if (rwlock) {
        if (g_fdp->ConsumeProbability<double>() < 0.1)
            *rwlock = NULL;
        else
            *rwlock = (void *)(uintptr_t)g_fdp->ConsumeIntegral<uintptr_t>();
    }
    return 0;
}

/* ocall_pthread_rwlock_destroy */
int _harness_ocall_pthread_rwlock_destroy(void *rwlock) {
    (void)rwlock;
    return 0;
}

/* ocall_pthread_rwlock_rdlock */
int _harness_ocall_pthread_rwlock_rdlock(void *rwlock) {
    (void)rwlock;
    return 0;
}

/* ocall_pthread_rwlock_wrlock */
int _harness_ocall_pthread_rwlock_wrlock(void *rwlock) {
    (void)rwlock;
    return 0;
}

/* ocall_pthread_rwlock_unlock */
int _harness_ocall_pthread_rwlock_unlock(void *rwlock) {
    (void)rwlock;
    return 0;
}

/* ocall_get_errno */
int _harness_ocall_get_errno(void) {
    return g_fdp->ConsumeIntegralInRange<int>(0, 40);
}

/* ---- Socket OCalls ---- */

/* ocall_socket */
int _harness_ocall_socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol;
    if (g_fdp->ConsumeProbability<double>() < 0.2)
        return -1;
    return g_fdp->ConsumeIntegralInRange<int>(3, 1024);
}

/* ocall_accept */
int _harness_ocall_accept(int sockfd, void *addr, uint32_t *addrlen,
                          uint32_t addr_size) {
    (void)sockfd; (void)addr; (void)addrlen; (void)addr_size;
    if (g_fdp->ConsumeProbability<double>() < 0.3)
        return -1;
    return g_fdp->ConsumeIntegralInRange<int>(3, 1024);
}

/* ocall_bind */
int _harness_ocall_bind(int sockfd, const void *addr, uint32_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_connect */
int _harness_ocall_connect(int sockfd, void *addr, uint32_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_getsockname */
int _harness_ocall_getsockname(int sockfd, void *addr, uint32_t *addrlen,
                               uint32_t addr_size) {
    (void)sockfd;
    if (addr && addr_size > 0 && g_fdp->remaining_bytes() >= addr_size)
        g_fdp->ConsumeData(addr, addr_size);
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_getpeername */
int _harness_ocall_getpeername(int sockfd, void *addr, uint32_t *addrlen,
                               uint32_t addr_size) {
    (void)sockfd;
    if (addr && addr_size > 0 && g_fdp->remaining_bytes() >= addr_size)
        g_fdp->ConsumeData(addr, addr_size);
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_getsockopt */
int _harness_ocall_getsockopt(int sockfd, int level, int optname,
                              void *val_buf, unsigned val_buf_size,
                              void *len_buf) {
    (void)sockfd; (void)level; (void)optname; (void)len_buf;
    if (val_buf && val_buf_size > 0 && g_fdp->remaining_bytes() >= val_buf_size)
        g_fdp->ConsumeData(val_buf, val_buf_size);
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_listen */
int _harness_ocall_listen(int sockfd, int backlog) {
    (void)sockfd; (void)backlog;
    return g_fdp->ConsumeProbability<double>() < 0.7 ? 0 : -1;
}

/* ocall_recv */
int _harness_ocall_recv(int sockfd, void *buf, size_t len, int flags) {
    (void)sockfd; (void)flags;
    if (!buf || len == 0) return 0;
    if (g_fdp->ConsumeProbability<double>() < 0.1) return -1;
    size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, len);
    if (n > 0 && g_fdp->remaining_bytes() >= n)
        g_fdp->ConsumeData(buf, n);
    return (int)n;
}

/* ocall_recvfrom */
ssize_t _harness_ocall_recvfrom(int sockfd, void *buf, size_t len, int flags,
                                void *src_addr, uint32_t *addrlen,
                                uint32_t addr_size) {
    (void)sockfd; (void)flags; (void)src_addr; (void)addrlen; (void)addr_size;
    if (!buf || len == 0) return 0;
    if (g_fdp->ConsumeProbability<double>() < 0.1) return -1;
    size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, len);
    if (n > 0 && g_fdp->remaining_bytes() >= n)
        g_fdp->ConsumeData(buf, n);
    return (ssize_t)n;
}

/* ocall_recvmsg */
ssize_t _harness_ocall_recvmsg(int sockfd, void *msg_buf,
                               unsigned msg_buf_size, int flags) {
    (void)sockfd; (void)flags;
    if (!msg_buf || msg_buf_size == 0) return 0;
    if (g_fdp->ConsumeProbability<double>() < 0.1) return -1;
    size_t n = g_fdp->ConsumeIntegralInRange<size_t>(0, msg_buf_size);
    if (n > 0 && g_fdp->remaining_bytes() >= n)
        g_fdp->ConsumeData(msg_buf, n);
    return (ssize_t)n;
}

/* ocall_send */
int _harness_ocall_send(int sockfd, const void *buf, size_t len, int flags) {
    (void)sockfd; (void)buf; (void)flags;
    return g_fdp->ConsumeProbability<double>() < 0.1
        ? -1
        : g_fdp->ConsumeIntegralInRange<int>(0, (int)len);
}

/* ocall_sendto */
ssize_t _harness_ocall_sendto(int sockfd, const void *buf, size_t len,
                              int flags, void *dest_addr, uint32_t addrlen) {
    (void)sockfd; (void)buf; (void)flags; (void)dest_addr; (void)addrlen;
    return g_fdp->ConsumeProbability<double>() < 0.1
        ? -1
        : g_fdp->ConsumeIntegralInRange<ssize_t>(0, (ssize_t)len);
}

/* ocall_sendmsg */
ssize_t _harness_ocall_sendmsg(int sockfd, void *msg_buf,
                               unsigned msg_buf_size, int flags) {
    (void)sockfd; (void)msg_buf; (void)msg_buf_size; (void)flags;
    return g_fdp->ConsumeIntegralInRange<ssize_t>(-1, 4096);
}

/* ocall_setsockopt */
int _harness_ocall_setsockopt(int sockfd, int level, int optname,
                              void *optval, unsigned optlen) {
    (void)sockfd; (void)level; (void)optname; (void)optval; (void)optlen;
    return g_fdp->ConsumeProbability<double>() < 0.8 ? 0 : -1;
}

/* ocall_shutdown */
int _harness_ocall_shutdown(int sockfd, int how) {
    (void)sockfd; (void)how;
    return 0;
}

} /* extern "C" */
