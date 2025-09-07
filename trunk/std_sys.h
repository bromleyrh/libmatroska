/*
 * std_sys.h
 */

#ifndef _STD_SYS_H
#define _STD_SYS_H

#define FILE_OFFSET_BITS 64

#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>

enum {
#define X(nm, ...) \
    SYS_E##nm = E_##nm,
    LIST_ERRNO(X)
#undef X
};

#define SYS_AT_FDCWD -128

#define SYS_STDIN_FILENO sys_stdin_fileno()
#define SYS_STDOUT_FILENO sys_stdout_fileno()
#define SYS_STDERR_FILENO sys_stderr_fileno()

#define SYS_O_RDONLY 1
#define SYS_O_WRONLY 2

#define SYS_O_CLOEXEC 4

extern _Thread_local int sys_errno;

int sys_openat(int dirfd, const char *pathname, int flags);

int sys_dup(int oldfd);
int sys_dup2_nocancel(int oldfd, int newfd);

int sys_close(int fd);
int sys_close_nocancel(int fd);

int64_t sys_lseek(int fd, int64_t offset, int whence);

int sys_fseek64(FILE *stream, off_t offset, int whence);
off_t sys_ftell64(FILE *stream);

ssize_t sys_read_nocancel(int fd, void *buf, size_t count);

ssize_t sys_write_nocancel(int fd, const void *buf, size_t count);

int sys_fsync_nocancel(int fd);

int sys_stdin_fileno(void);
int sys_stdout_fileno(void);
int sys_stderr_fileno(void);

int sys_maperrn(void);

int sys_maperror(int errnum);

int sys_rmaperror(int errnum);

char *sys_strerror(int errnum);

int sys_strerror_r(int errnum, char *strerrbuf, size_t buflen);

#endif

/* vi: set expandtab sw=4 ts=4: */
