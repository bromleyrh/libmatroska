/*
 * std_sys.h
 */

#ifndef _STD_SYS_H
#define _STD_SYS_H

#include "config.h"

#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

enum {
#define X(nm, ...) \
    SYS_E##nm = E_##nm,
    LIST_ERRNO(X)
#undef X
};

typedef intmax_t procid_t;

typedef void *loc_t;

#define SYS_AT_FDCWD -128

#define SYS_STDIN_FILENO sys_stdin_fileno()
#define SYS_STDOUT_FILENO sys_stdout_fileno()
#define SYS_STDERR_FILENO sys_stderr_fileno()

#define SYS_O_RDONLY 1
#define SYS_O_WRONLY 2

#define SYS_O_CLOEXEC 4

#define SYS_PATH_MAX _SYS_PATH_MAX

#define SYS_LC_GLOBAL_LOCALE _sys_lc_global_locale

extern _Thread_local int sys_errno;

extern const loc_t _sys_lc_global_locale;

procid_t sys_fork(void);

procid_t sys_waitprocid_nocancel(procid_t pid, int *wstatus, int options);

int sys_wifexited(int wstatus);
int sys_wifsignaled(int wstatus);
int sys_wifstopped(int wstatus);
int sys_wifcontinued(int wstatus);

int sys_wexitstatus(int wstatus);
int sys_wtermsig(int wstatus);
int sys_wstopsig(int wstatus);

int sys_execvp(const char *file, char *const argv[]);

int sys_exit_direct(int status);

int sys_pause(void);

procid_t sys_getpid(void);

int sys_setenv(const char *name, const char *value, int overwrite);
int sys_unsetenv(const char *name);

loc_t sys_uselocale(loc_t newloc);
loc_t sys_duplocale(loc_t locobj);
void sys_freelocale(loc_t locobj);

struct tm *sys_localtime_r(const time_t *timep, struct tm *result);

int sys_openat(int dirfd, const char *pathname, int flags);

FILE *sys_fdopen(int fd, const char *mode);

int sys_dup(int oldfd);
int sys_dup2_nocancel(int oldfd, int newfd);

int sys_close(int fd);
int sys_close_nocancel(int fd);

int64_t sys_lseek(int fd, int64_t offset, int whence);

int sys_fseek64(FILE *stream, int64_t offset, int whence);
int64_t sys_ftell64(FILE *stream);

int64_t sys_read_nocancel(int fd, void *buf, size_t count);

int64_t sys_write_nocancel(int fd, const void *buf, size_t count);

int sys_fsync_nocancel(int fd);

int sys_pipe(int pipefd[2]);

int sys_isatty(int fd);

int sys_stdin_fileno(void);
int sys_stdout_fileno(void);
int sys_stderr_fileno(void);

int sys_fileno(FILE *stream);

int sys_maperrn(void);

int sys_maperror(int errnum);

int sys_rmaperror(int errnum);

char *sys_strerror(int errnum);

int sys_strerror_r(int errnum, char *strerrbuf, size_t buflen);

char *sys_strerror_l(int errnum, loc_t locale);

#endif

/* vi: set expandtab sw=4 ts=4: */
