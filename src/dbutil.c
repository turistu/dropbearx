/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#ifdef __linux__
#define _GNU_SOURCE
/* To call clock_gettime() directly */
#include <sys/syscall.h>
#endif /* __linux */

#ifdef HAVE_MACH_MACH_TIME_H
#include <mach/mach_time.h>
#include <mach/mach.h>
#endif

#include "includes.h"
#include "dbutil.h"
#include "buffer.h"
#include "session.h"
#include "atomicio.h"

#define MAX_FMT 100

#if DEBUG_TRACE
int debug_trace = 0;
#endif

static void generic_dropbear_exit(int exitcode, const char *msg) ATTRIB_NORETURN;
static void generic_dropbear_log(int priority, const char *msg);

void (*_dropbear_exit)(int exitcode, const char *buf) ATTRIB_NORETURN
	= generic_dropbear_exit;
										void (*_dropbear_log)(int priority, const char *buf) = generic_dropbear_log;

#ifndef DISABLE_SYSLOG
void startsyslog(const char *ident) {

	openlog(ident, LOG_PID, LOG_AUTHPRIV);

}
#endif /* DISABLE_SYSLOG */

void msg_format(char *buf, int size, const char *fmt, va_list va) {
	int l = vsnprintf(buf, size, fmt, va);
	if (l > 0 && l < size - 10 && buf[l - 1] == ':') {
		snprintf(buf + l, size - l, " %s", strerror(errno));
	}
}

void dropbear_close(const char* fmt, ...) {
	char buf[512];
	va_list va;

	va_start(va, fmt);
	msg_format(buf, sizeof buf, fmt, va);
	va_end(va);
	_dropbear_exit(EXIT_SUCCESS, buf);
}

void dropbear_exit(const char* fmt, ...) {
	char buf[512];
	va_list va;

	va_start(va, fmt);
	msg_format(buf, sizeof buf, fmt, va);
	va_end(va);
	_dropbear_exit(EXIT_FAILURE, buf);
}

/* this is what can be called to write arbitrary log messages */
void dropbear_log(int priority, const char* fmt, ...) {
	char buf[512];
	va_list va;

	va_start(va, fmt);
	msg_format(buf, sizeof buf, fmt, va);
	va_end(va);
	_dropbear_log(priority, buf);
}

void dropbear_exit_if(int cond, const char *fmt, ...) {
	char buf[512];
	va_list va;

	va_start(va, fmt);
	msg_format(buf, sizeof buf, fmt, va);
	va_end(va);
	if(cond) _dropbear_exit(EXIT_FAILURE, buf);
	else _dropbear_log(LOG_ERR, buf);
}

static void generic_dropbear_exit(int exitcode, const char *msg) {

	_dropbear_log(exitcode ? LOG_ERR : LOG_INFO, msg);

#if DROPBEAR_FUZZ
    if (fuzz.do_jmp) {
        longjmp(fuzz.jmp, 1);
    }
#endif

	exit(exitcode);
}

void fail_assert(const char* expr, const char* file, int line) {
	dropbear_exit("Failed assertion (%s:%d): `%s'", file, line, expr);
}

static void generic_dropbear_log(int priority, const char *msg) {

	fprintf(stderr, "<%d> %s\n", priority, msg);
}



#if DEBUG_TRACE 

static double debug_start_time = -1;

void debug_start_net()
{
	if (getenv("DROPBEAR_DEBUG_NET_TIMESTAMP"))
	{
		/* Timestamps start from first network activity */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		debug_start_time = tv.tv_sec + (tv.tv_usec / 1000000.0);
		TRACE(("Resetting Dropbear TRACE timestamps"))
	}
}

static double time_since_start()
{
	double nowf;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	nowf = tv.tv_sec + (tv.tv_usec / 1000000.0);
	if (debug_start_time < 0)
	{
		debug_start_time = nowf;
		return 0;
	}
	return nowf - debug_start_time;
}

static void dropbear_tracelevel(int level, const char *format, va_list param)
{
	if (debug_trace == 0 || debug_trace < level) {
		return;
	}

	fprintf(stderr, "TRACE%d (%d) %f: ", level, getpid(), time_since_start());
	vfprintf(stderr, format, param);
	fprintf(stderr, "\n");
}
#if (DEBUG_TRACE>=1)
void dropbear_trace1(const char* format, ...) {
	va_list param;

	va_start(param, format);
	dropbear_tracelevel(1, format, param);
	va_end(param);
}
#endif
#if (DEBUG_TRACE>=2)
void dropbear_trace2(const char* format, ...) {
	va_list param;

	va_start(param, format);
	dropbear_tracelevel(2, format, param);
	va_end(param);
}
#endif
#if (DEBUG_TRACE>=3)
void dropbear_trace3(const char* format, ...) {
	va_list param;

	va_start(param, format);
	dropbear_tracelevel(3, format, param);
	va_end(param);
}
#endif
#if (DEBUG_TRACE>=4)
void dropbear_trace4(const char* format, ...) {
	va_list param;

	va_start(param, format);
	dropbear_tracelevel(4, format, param);
	va_end(param);
}
#endif
#if (DEBUG_TRACE>=5)
void dropbear_trace5(const char* format, ...) {
	va_list param;

	va_start(param, format);
	dropbear_tracelevel(5, format, param);
	va_end(param);
}
#endif
#endif


/* Connect to a given unix socket. The socket is blocking */
#if ENABLE_CONNECT_UNIX
int connect_unix(const char* path, int len) {
	struct sockaddr_un addr = {0};
	int fd = -1;

	addr.sun_family = AF_UNIX;
	if(len < 0) len = strlen(path);
	if(len >= (int)sizeof addr.sun_path){
		TRACE(("path too long for a unix socket: %s", path))
		return -1;
	}
	memcpy(addr.sun_path, path, len);
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		TRACE(("Failed to open unix socket"))
		return -1;
	}
	if (connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) {
		/* XXX XXX should s/@/\@/ + s/\0/@/ */
		TRACE(("Failed to connect to '%s' socket", path))
		m_close(fd);
		return -1;
	}
	return fd;
}
#endif

/* Sets up a pipe for a, returning three non-blocking file descriptors
 * and the pid. exec_fn is the function that will actually execute the child process,
 * it will be run after the child has fork()ed, and is passed exec_data.
 * If ret_errfd == NULL then stderr will not be captured.
 * ret_pid can be passed as  NULL to discard the pid. */
int spawn_command(void(*exec_fn)(const void *user_data), const void *exec_data,
		int *ret_writefd, int *ret_readfd, int *ret_errfd, pid_t *ret_pid) {
#if HAVE_SOCKETPAIR
	int sock[2];
#else
	int infds[2];
	int outfds[2];
#endif
	int errfds[2];
	pid_t pid;
	const int FDIN = 0;
	const int FDOUT = 1;


#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		return fuzz_spawn_command(ret_writefd, ret_readfd, ret_errfd, ret_pid);
	}
#endif

	/* redirect stdin/stdout/stderr */
#if HAVE_SOCKETPAIR
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock)) {
		return DROPBEAR_FAILURE;
	}
#else
	if (pipe(infds) != 0) {
		return DROPBEAR_FAILURE;
	}
	if (pipe(outfds) != 0) {
		return DROPBEAR_FAILURE;
	}
#endif
	if (ret_errfd && pipe(errfds) != 0) {
		return DROPBEAR_FAILURE;
	}

#if DROPBEAR_VFORK
	pid = vfork();
#else
	pid = fork();
#endif

	if (pid < 0) {
		return DROPBEAR_FAILURE;
	}

	if (!pid) {
		/* child */

		TRACE(("back to normal sigchld"))
		/* Revert to normal sigchld handling */
		if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
			dropbear_exit("signal() error");
		}

		/* redirect stdin/stdout */
#if HAVE_SOCKETPAIR
		if ((dup2(sock[1], STDIN_FILENO) < 0) ||
			(dup2(sock[1], STDOUT_FILENO) < 0) ||
			(ret_errfd && dup2(errfds[FDOUT], STDERR_FILENO) < 0)) {
			TRACE(("leave noptycommand: error redirecting FDs"))
			dropbear_exit("Child dup2() failure");
		}
		close(sock[0]);
		close(sock[1]);
#else
		if ((dup2(infds[FDIN], STDIN_FILENO) < 0) ||
			(dup2(outfds[FDOUT], STDOUT_FILENO) < 0) ||
			(ret_errfd && dup2(errfds[FDOUT], STDERR_FILENO) < 0)) {
			TRACE(("leave noptycommand: error redirecting FDs"))
			dropbear_exit("Child dup2() failure");
		}
		close(infds[FDOUT]);
		close(infds[FDIN]);
		close(outfds[FDIN]);
		close(outfds[FDOUT]);
#endif
		if (ret_errfd)
		{
			close(errfds[FDIN]);
			close(errfds[FDOUT]);
		}

		exec_fn(exec_data);
		/* not reached */
		return DROPBEAR_FAILURE;
	} else {
		/* parent */
#if HAVE_SOCKETPAIR
		close(sock[1]);
		setnonblocking(sock[0]);
		*ret_writefd = *ret_readfd = sock[0];
#else
		close(infds[FDIN]);
		close(outfds[FDOUT]);
		setnonblocking(outfds[FDIN]);
		setnonblocking(infds[FDOUT]);
		*ret_writefd = infds[FDOUT];
		*ret_readfd = outfds[FDIN];
#endif

		if (ret_errfd) {
			close(errfds[FDOUT]);
			setnonblocking(errfds[FDIN]);
			*ret_errfd = errfds[FDIN];
		}

		if (ret_pid) {
			*ret_pid = pid;
		}

		return DROPBEAR_SUCCESS;
	}
}

/* Runs a command with "sh -c". Will close FDs (except stdin/stdout/stderr) and
 * re-enabled SIGPIPE. If cmd is NULL, will run a login shell.
 */
void run_shell_command(const char* cmd, unsigned int maxfd, char* usershell) {
	char * argv[4];
	char * baseshell = NULL;
	unsigned int i;

	baseshell = basename(usershell);

	if (cmd != NULL) {
		argv[0] = baseshell;
	} else {
		/* a login shell should be "-bash" for "/bin/bash" etc */
		argv[0] = m_asprintf("-%s", baseshell);
	}

	if (cmd != NULL) {
		argv[1] = "-c";
		argv[2] = (char*)cmd;
		argv[3] = NULL;
	} else {
		/* construct a shell of the form "-bash" etc */
		argv[1] = NULL;
	}

	/* Re-enable SIGPIPE for the executed process */
	if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
		dropbear_exit("signal() error");
	}

	/* close file descriptors except stdin/stdout/stderr
	 * Need to be sure FDs are closed here to avoid reading files as root */
	for (i = 3; i <= maxfd; i++) {
		m_close(i);
	}

	execv(usershell, argv);
}

#if DEBUG_TRACE
void printhex(const char * label, const unsigned char * buf, int len) {
	int i, j;

	fprintf(stderr, "%s\n", label);
	/* for each 16 byte line */
	for (j = 0; j < len; j += 16) {
		const int linelen = MIN(16, len - j);

		/* print hex digits */
		for (i = 0; i < 16; i++) {
			if (i < linelen) {
				fprintf(stderr, "%02x", buf[j+i]);
			} else {
				fprintf(stderr, "  ");
			}
			// separator between pairs
			if (i % 2 ==1) {
				fprintf(stderr, " ");
			}
		}

		/* print characters */
		fprintf(stderr, "  ");
		for (i = 0; i < linelen; i++) {
			char c = buf[j+i];
			if (!isprint(c)) {
				c = '.';
			}
			fputc(c, stderr);
		}
		fprintf(stderr, "\n");
	}
}

void printmpint(const char *label, const mp_int *mp) {
	buffer *buf = buf_new(1000);
	buf_putmpint(buf, mp);
	fprintf(stderr, "%d bits ", mp_count_bits(mp));
	printhex(label, buf->data, buf->len);
	buf_free(buf);

}
#endif

/* Strip all control characters from text (a null-terminated string), except
 * for '\n', '\r' and '\t'.
 * The result returned is a newly allocated string, this must be free()d after
 * use */
char * stripcontrol(const char * text) {

	char * ret;
	int len, pos;
	int i;
	
	len = strlen(text);
	ret = m_malloc(len+1);

	pos = 0;
	for (i = 0; i < len; i++) {
		if ((text[i] <= '~' && text[i] >= ' ') /* normal printable range */
				|| text[i] == '\n' || text[i] == '\r' || text[i] == '\t') {
			ret[pos] = text[i];
			pos++;
		}
	}
	ret[pos] = 0x0;
	return ret;
}
			

/* reads the contents of filename into the buffer buf, from the current
 * position, either to the end of the file, or the buffer being full.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_readfile(buffer* buf, const char* filename) {

	int fd = -1;
	int len;
	int maxlen;
	int ret = DROPBEAR_FAILURE;

	fd = open(filename, O_RDONLY);

	if (fd < 0) {
		goto out;
	}
	
	do {
		maxlen = buf->size - buf->pos;
		len = read(fd, buf_getwriteptr(buf, maxlen), maxlen);
		if (len < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			goto out;
		}
		buf_incrwritepos(buf, len);
	} while (len < maxlen && len > 0);

	ret = DROPBEAR_SUCCESS;

out:
	if (fd >= 0) {
		m_close(fd);
	}
	return ret;
}

/* get a line from the file into buffer in the style expected for an
 * authkeys file.
 * Will return DROPBEAR_SUCCESS if data is read, or DROPBEAR_FAILURE on EOF.*/
/* Only used for ~/.ssh/known_hosts and ~/.ssh/authorized_keys */
#if DROPBEAR_CLIENT || DROPBEAR_SVR_PUBKEY_AUTH
int buf_getline(buffer * line, FILE * authfile) {

	int c = EOF;

	buf_setpos(line, 0);
	buf_setlen(line, 0);

	while (line->pos < line->size) {

		c = fgetc(authfile); /*getc() is weird with some uClibc systems*/
		if (c == EOF || c == '\n' || c == '\r') {
			goto out;
		}

		buf_putbyte(line, (unsigned char)c);
	}

	TRACE(("leave getauthline: line too long"))
	/* We return success, but the line length will be zeroed - ie we just
	 * ignore that line */
	buf_setlen(line, 0);

out:


	/* if we didn't read anything before EOF or error, exit */
	if (c == EOF && line->pos == 0) {
		return DROPBEAR_FAILURE;
	} else {
		buf_setpos(line, 0);
		return DROPBEAR_SUCCESS;
	}

}	
#endif

/* make sure that the socket closes */
void m_close(int fd) {
	int val;

	if (fd < 0) {
		return;
	}

	do {
		val = close(fd);
	} while (val < 0 && errno == EINTR);

	if (val < 0 && errno != EBADF) {
		/* Linux says EIO can happen */
		dropbear_exit("Error closing fd %d:", fd);
	}
}
	
void setnonblocking(int fd) {

	TRACE(("setnonblocking: %d", fd))

#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		return;
	}
#endif

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		if (errno == ENODEV) {
			/* Some devices (like /dev/null redirected in)
			 * can't be set to non-blocking */
			TRACE(("ignoring ENODEV for setnonblocking"))
		} else {
			dropbear_exit("Couldn't set nonblocking");
		}
	}
	TRACE(("leave setnonblocking"))
}

/* Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE, with the result in *val */
int m_str_to_uint(const char* str, unsigned int *val) {
	unsigned long l;
	char *endp;

	errno = 0;
	l = strtoul(str, &endp, 10);
	if (endp == str || *endp || errno || l > UINT_MAX) {
		return DROPBEAR_FAILURE;
	} else {
		*val = l;
		return DROPBEAR_SUCCESS;
	}
}

/* Returns malloced path. inpath beginning with '~/' expanded,
   otherwise returned as-is */
char * expand_homedir_path(const char *inpath) {
	if (strncmp(inpath, "~/", 2) == 0) {
		return m_asprintf("%s/%s", get_homedir(), inpath + 2);
	} else {
		return m_strdup(inpath);
	}
}

int constant_time_memcmp(const void* a, const void *b, size_t n)
{
	const char *xa = a, *xb = b;
	uint8_t c = 0;
	size_t i;
	for (i = 0; i < n; i++)
	{
		c |= (xa[i] ^ xb[i]);
	}
	return c;
}

/* higher-resolution monotonic timestamp, falls back to gettimeofday */
void gettime_wrapper(struct timespec *now) {
	struct timeval tv;
#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		/* time stands still when fuzzing */
		now->tv_sec = 5;
		now->tv_nsec = 0;
	}
#endif

#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
	/* POSIX monotonic clock. Newer Linux, BSD, MacOSX >10.12 */
	if (clock_gettime(CLOCK_MONOTONIC, now) == 0) {
		return;
	}
#endif

#if defined(__linux__) && defined(SYS_clock_gettime)
	{
	/* Old linux toolchain - kernel might support it but not the build headers */
	/* Also glibc <2.17 requires -lrt which we neglect to add */
	static int linux_monotonic_failed = 0;
	if (!linux_monotonic_failed) {
		/* CLOCK_MONOTONIC isn't in some headers */
		int clock_source_monotonic = 1; 
		if (syscall(SYS_clock_gettime, clock_source_monotonic, now) == 0) {
			return;
		} else {
			/* Don't try again */
			linux_monotonic_failed = 1;
		}
	}
	}
#endif /* linux fallback clock_gettime */

#if defined(HAVE_MACH_ABSOLUTE_TIME)
	{
	/* OS X pre 10.12, see https://developer.apple.com/library/mac/qa/qa1398/_index.html */
	static mach_timebase_info_data_t timebase_info;
	uint64_t scaled_time;
	if (timebase_info.denom == 0) {
		mach_timebase_info(&timebase_info);
	}
	scaled_time = mach_absolute_time() * timebase_info.numer / timebase_info.denom;
	now->tv_sec = scaled_time / 1000000000;
	now->tv_nsec = scaled_time % 1000000000;
	}
#endif /* osx mach_absolute_time */

	/* Fallback for everything else - this will sometimes go backwards */
	gettimeofday(&tv, NULL);
	now->tv_sec = tv.tv_sec;
	now->tv_nsec = 1000*(long)tv.tv_usec;
}

/* second-resolution monotonic timestamp */
time_t monotonic_now() {
	struct timespec ts;
	gettime_wrapper(&ts);
	return ts.tv_sec;
}

void fsync_parent_dir(const char* fn) {
#ifdef HAVE_LIBGEN_H
	char *fn_dir = m_strdup(fn);
	char *dir = dirname(fn_dir);
	int dirfd = open(dir, O_RDONLY);

	if (dirfd != -1) {
		if (fsync(dirfd) != 0) {
			TRACE(("fsync of directory %s failed:", dir))
		}
		m_close(dirfd);
	} else {
		TRACE(("error opening directory %s for fsync:", dir))
	}

	m_free(fn_dir);
#endif
}

int fd_read_pending(int fd) {
	fd_set fds;
	struct timeval timeout;

	DROPBEAR_FD_ZERO(&fds);
	FD_SET(fd, &fds);
	while (1) {
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
		if (select(fd+1, &fds, NULL, NULL, &timeout) < 0) {
			if (errno == EINTR) {
				continue;
			}
			return 0;
		}
		return FD_ISSET(fd, &fds);
	}
}

int m_snprintf(char *str, size_t size, const char *format, ...) {
	va_list param;
	int ret;

	va_start(param, format);
	ret = vsnprintf(str, size, format, param);
	va_end(param);
	if (ret < 0) {
		dropbear_exit("snprintf failed");
	}
	return ret;
}
const char *get_homedir(void) {
	char *h;
	struct passwd *pw;
	if ((h = getenv("HOME")))
		return h;
	if ((pw = getpwuid(getuid())) && (h = pw->pw_dir) && *h)
		return h;
	return "/";
}
const char *get_username(void) {
	char *u;
	struct passwd *pw;
	if ((u = getenv("USER")))
		return u;
	if ((pw = getpwuid(getuid())) && (u = pw->pw_name) && *u)
		return u;
	return "";
}
