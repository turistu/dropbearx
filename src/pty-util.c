#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>

#include "dbutil.h"

#define FAIL(msg)	{ e = (msg); goto fail; }

#ifdef __sun
#include <stropts.h>

/* On Solaris, ioctl(st, I_PUSH, "ptem") is causing the terminal to
   become the controlling tty (if the process had called setsid() before),
   despite any O_NOCTTY flag when it was opened.
   And trying to get rid of it with ioctl(TIOCNOTTY) will generate a SIGHUP */

static void (*old_sigh)(int s);
static void sigh(int s){ signal(SIGHUP, old_sigh); }

char *pty_peer(int *mtp, int *stp, char **snp){
	int mt = -1, st = -1; char *sn, *e;
	if((mt = posix_openpt(O_RDWR|O_NOCTTY)) == -1) FAIL("open master");
	if(grantpt(mt)) FAIL("grantpt");
	if(unlockpt(mt)) FAIL("unlockpt");
	if(!(sn = ptsname(mt))) FAIL("ptsname");
	if((st = open(sn, O_RDWR|O_NOCTTY)) == -1) FAIL("open slave");
	if(ioctl(st, I_PUSH, "ptem")) FAIL("push ptem");
	if(ioctl(st, I_PUSH, "ldterm")) FAIL("push ldterm");
	old_sigh = signal(SIGHUP, sigh);
	ioctl(st, TIOCNOTTY);
	if(snp) *snp = sn;
	*mtp = mt; *stp = st; return 0;
fail:
	close(st); close(mt); return e;
}

#else

#ifdef __ANDROID__
#define posix_openpt(flags)	open("/dev/ptmx", flags)
#endif

char *pty_peer(int *mtp, int *stp, char **snp){
	int mt = -1, st = -1; char *sn, *e;
	if((mt = posix_openpt(O_RDWR|O_NOCTTY)) == -1) return "open master";
	if(grantpt(mt)) FAIL("grantpt");
	if(unlockpt(mt)) FAIL("unlockpt");
#ifdef TIOCGPTPEER
	if((st = ioctl(mt, TIOCGPTPEER, O_RDWR|O_NOCTTY)) != -1){
		if(snp) *snp = ptsname(mt);
		*mtp = mt; *stp = st; return 0;
	}
#endif
	if(!(sn = ptsname(mt))) FAIL("ptsname");
	if((st = open(sn, O_RDWR|O_NOCTTY)) == -1) FAIL("open slave");
	if(snp) *snp = sn;
	*mtp = mt; *stp = st; return 0;
fail:
	close(st); close(mt); return e;
}

#endif

char *pty_login(int st){
	if(setsid() == -1) return "setsid";
	if(ioctl(st, TIOCSCTTY, 0)) return "tiocsctty";
	if(dup2(st, 0) == -1 || dup2(st, 1) == -1) return "dup2";
	close(st);
	return 0;
}

/*
 * When opening the master pty, Linux is using the *effective* user id
 * of the calling process to determine the permissions of the slave.
 *
 * BSD and Solaris are using the *real* user id for that.
 *
 * Set both the ruid and the euid with setresuid(2) --if available--,
 * or with setreuid(2) --assuming a standard-compliant setreuid()
 * which clobbers the saved uid with the current euid, not with the
 * new ruid
 */
static uid_t euid, ruid;
#if __linux__ || __FreeBSD__ || __OpenBSD__ || HAVE_SETRESUID
void setxuid_to(int uid){
	euid = geteuid(), ruid = getuid();
	if(setresuid(uid, uid, -1))
		dropbear_exit("setresuid(%d, %d, -1) to:", uid, uid);
}
void setxuid_back(void){
	if(setresuid(ruid, euid, -1))
		dropbear_exit("setresuid(%d, %d, -1) back:", ruid, euid);
}
#else
void setxuid_to(int uid){
	euid = geteuid(), ruid = getuid();
	if(setreuid(uid, euid))
		dropbear_exit("setreuid(%d, %d) to:", uid, euid);
	if(seteuid(uid)) dropbear_exit("seteuid(%d)", uid);
}
void setxuid_back(void){
	if(seteuid(euid)) dropbear_exit("seteuid(%d)", euid);
	if(setreuid(ruid, euid))
		dropbear_exit("setreuid(%d, %d) back:", ruid, euid);
}
#endif
