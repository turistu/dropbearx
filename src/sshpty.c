/*
 * Dropbear - a SSH2 server
 *
 * Copied from OpenSSH-3.5p1 source, modified by Matt Johnston 2003
 * 
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Allocating a pseudo-terminal, and making it the controlling tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/*RCSID("OpenBSD: sshpty.c,v 1.7 2002/06/24 17:57:20 deraadt Exp ");*/

#include "includes.h"
#include "dbutil.h"
#include "errno.h"
#include "sshpty.h"
#include "session.h"

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

int
pty_allocate(int *ptyfd, int *ttyfd, char **nameptr)
{
	int ret = 0;
	uid_t uid = geteuid();
	char *name;
	if(seteuid(ses.authstate.pw_uid))
		dropbear_exit("seteuid(%d):", ses.authstate.pw_uid);
#ifdef HAVE_POSIX_OPENPT
	*ptyfd = posix_openpt(O_RDWR|O_NOCTTY);
	if(*ptyfd == -1){
		dropbear_log(LOG_ERR, "posix_openpt:");
		goto done;
	}
#else
	*ptyfd = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	if(*ptyfd == -1){
		dropbear_log(LOG_ERR, "open /dev/ptmx:");
		goto done;
	}
#endif
	grantpt(*ptyfd);
	unlockpt(*ptyfd);
#ifdef TIOCGPTPEER
	*ttyfd = ioctl(*ptyfd, TIOCGPTPEER, O_RDWR|O_NOCTTY);
	if(*ttyfd != -1){
		*nameptr = m_strdup(ttyname(*ttyfd));
		ret = 1;
		goto done;
	}
#endif
	if(!(name = ptsname(*ptyfd))) {
		dropbear_log(LOG_ERR, "ptsname:");
		goto done;
	}
	*ttyfd = open(name, O_RDWR|O_NOCTTY);
	if(*ttyfd != -1) {
		*nameptr = m_strdup(name);
		ret = 1;
		goto done;
	}
	close(*ptyfd);
	dropbear_log(LOG_ERR, "open %s:", *nameptr);
done:
	if(seteuid(uid))
		dropbear_exit("seteuid(%d):", uid);
	return ret;
}

void
pty_make_controlling_tty(int ttyfd)
{
	setsid();
	ioctl(ttyfd, TIOCSCTTY, 0);
}

/* Changes the window size associated with the pty. */

void
pty_change_window_size(int ptyfd, int row, int col,
	int xpixel, int ypixel)
{
	struct winsize w;

	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(void) ioctl(ptyfd, TIOCSWINSZ, &w);
}
