#include <unistd.h>
#include <stdio.h>
#include "includes.h"
#include "sys-self_exe.h"

/* of all these, only the linux version is really safe */

#if __linux__ || __DragonFly__
const char *self_exe(const char *UNUSED(fallback)){
	static char b[32];
	snprintf(b, sizeof b, "/proc/%u/exe", getpid());
	return b;
}

#else
static char path[PATH_MAX];

#if __NetBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
const char *self_exe(const char *fallback){
        int mib[4] = { CTL_KERN, KERN_PROC_ARGS, -1, KERN_PROC_PATHNAME };
        size_t size = sizeof path;
        if(sysctl(mib, 4, &path, &size, 0, 0)) return fallback;
        return path;
}
#elif __FreeBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
const char *self_exe(const char *fallback){
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
        size_t size = sizeof path;
        if(sysctl(mib, 4, &path, &size, 0, 0)) return fallback;
        return path;
}
#elif __APPLE__
#include <sys/types.h>
#include <mach-o/dyld.h>
const char *self_exe(const char *fallback){
	uint32_t size = sizeof path;
	if(_NSGetExecutablePath(path, &size)) return fallback;
	return path;
}
#elif __OpenBSD__
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
const char *self_exe(const char *fallback){
        struct kinfo_file kf; struct stat st;
        size_t size = sizeof kf;
        int mib[6] = { CTL_KERN, KERN_FILE, KERN_FILE_BYPID,
                getpid(), sizeof kf, 1 };
	const char *p = getprogname();
	if(stat(p, &st)) goto fail;
        if(sysctl(mib, 6, &kf, &size, 0, 0) && errno != ENOMEM) goto fail;
        if(size < sizeof kf || kf.fd_fd != KERN_FILE_TEXT) goto fail;
	if(st.st_dev != kf->va_fsid || st.st_ino != kf->va_fileid) goto fail;
fail:
	return fallback;
}
#elif __sun
const char *self_exe(const char *fallback){
	char b[48]; ssize_t l;
	snprintf(b, sizeof b, "/proc/%u/path/a.out", getpid());
	l = readlink(b, path, sizeof b);
	if(l < 0 || l >= sizeof path) return fallback;
	path[l] = '\0';
	return p;
}
#else
const char *self_exe(const char *fallback){
	return fallback;
}
#endif

#endif	/* not (__linux__ || __DragonFly__) */
