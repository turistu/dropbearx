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
#ifdef HAVE_POSIX_OPENPT
	*ptyfd = posix_openpt(O_RDWR|O_NOCTTY);
	if(*ptyfd == -1){
		dropbear_log(LOG_WARNING, "posix_openpt: %s", strerror(errno));
		return 0;
	}
#else
	*ptyfd = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	if(*ptyfd == -1){
		dropbear_log(LOG_WARNING, "open /dev/ptmx: %s", strerror(errno));
		return 0;
	}
#endif
	if(unlockpt(*ptyfd)){
		dropbear_log(LOG_WARNING, "unlockpt: %s", strerror(errno));
		return 0;
	}
#ifdef TIOCGPTPEER
	*ttyfd = ioctl(*ptyfd, TIOCGPTPEER, O_RDWR|O_NOCTTY);
	if(*ttyfd != -1){
		*nameptr = m_strdup(ttyname(*ttyfd));
		return 1;
	}
#endif
	*nameptr = m_strdup(ptsname(*ptyfd));
	*ttyfd = open(*nameptr, O_RDWR|O_NOCTTY);
	if(*ttyfd != -1)
		return 1;
	dropbear_log(LOG_WARNING, "open %s: %s", *nameptr, strerror(errno));
	return 0;
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

void
pty_release(const char *tty_name)
{
	(void)tty_name;
}

/* Makes the tty the processes controlling tty and sets it to sane modes. */

void
pty_make_controlling_tty(int *ttyfd, const char *tty_name)
{
	(void)tty_name;
	setsid();
	ioctl(*ttyfd, TIOCSCTTY, 0);
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

void
pty_setowner(struct passwd *pw, int ttyfd)
{
	struct group *grp;
	gid_t gid;
	mode_t mode;
	struct stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	if (grp) {
		gid = grp->gr_gid;
		mode = S_IRUSR | S_IWUSR | S_IWGRP;
	} else {
		gid = pw->pw_gid;
		mode = S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH;
	}

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	if (fstat(ttyfd, &st)) {
		dropbear_exit("pty_setowner: stat(%.101s) failed: %.100s",
				ttyname(ttyfd), strerror(errno));
	}

	/* Allow either "tty" gid or user's own gid. On Linux with openpty()
	 * this varies depending on the devpts mount options */
	if (st.st_uid != pw->pw_uid || !(st.st_gid == gid || st.st_gid == pw->pw_gid)) {
		if (fchown(ttyfd, pw->pw_uid, gid) < 0) {
			if (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0)) {
				dropbear_log(LOG_ERR,
					"chown(%.100s, %u, %u) failed: %.100s",
						ttyname(ttyfd),
						(unsigned int)pw->pw_uid, (unsigned int)gid,
						strerror(errno));
			} else {
				dropbear_exit("chown(%.100s, %u, %u) failed: %.100s",
				    ttyname(ttyfd), (unsigned int)pw->pw_uid, (unsigned int)gid,
				    strerror(errno));
			}
		}
	}

	if ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		if (fchmod(ttyfd, mode) < 0) {
			if (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0) {
				dropbear_log(LOG_ERR,
					"chmod(%.100s, 0%o) failed: %.100s",
					ttyname(ttyfd), mode, strerror(errno));
			} else {
				dropbear_exit("chmod(%.100s, 0%o) failed: %.100s",
				    ttyname(ttyfd), mode, strerror(errno));
			}
		}
	}
}
