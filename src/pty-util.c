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
