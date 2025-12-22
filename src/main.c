#include "includes.h"
#include "main.h"

static char *av0;

#ifdef MAIN

int main(int ac, char **av){
	av0 = av[0];
	return MAIN(ac, av);
}
const struct prog *find_multi(const char *UNUSED(name)){
	return NULL;
}

#else

static struct prog {
	int (*func)(int, char**);
	const char *desc;
} progs[] = {
#ifdef DB_dropbear
	{ dropbear_main, "'dropbear' or 'sshd' - the Dropbear server" },
#endif
#ifdef DB_dbclient
	{ dbclient_main, "'dbclient' or 'ssh' - the Dropbear client" },
#endif
#ifdef DB_dropbearkey
	{ dropbearkey_main, "'dropbearkey' or 'ssh-keygen' -- the key generator" },
#endif
#ifdef DB_dropbearconvert
	{ dropbearconvert_main, "'dropbearconvert' -- the key converter" },
#endif
#ifdef DB_scp
	{ scp_main, "'scp' -- secure copy" },
#endif
	{ 0 }
};

const struct prog *find_multi(const char *name){
	const char *s; struct prog *p;
	if((s = strrchr(name, '/'))) name = s + 1;
	for(p = progs; (s = p->desc); p++)
		if(*s && (s = strstr(s + 1, name)) && s[-1] == '\''
				&& s[strlen(name)] == '\'')
			return p;
	return NULL;
}
static void run(const char *name, int ac, char **av){
	const struct prog *p = find_multi(name);
	if(p) exit(p->func(ac, av));
}
int main(int ac, char **av){
	av0 = av[0];
	struct prog *p;
	run(av[0], ac, av);
	if(ac > 1) run(av[1], ac - 1, av + 1);
	fprintf(stderr, "Dropbear SSH multi-purpose v%s\n"
		"Make a symlink pointing at this binary with one of the\n",
		DROPBEAR_VERSION);
	for(p = progs; p->desc; p++)
		fprintf(stderr,  "\t%s\n", p->desc);
	return 1;
}

#endif

#if __linux__ || __DragonFly__
const char *curpid_exe(void){
	static char b[32];
	snprintf(b, sizeof b, "/proc/%u/exe", getpid());
	return b;
}
#elif __NetBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
const char *curpid_exe(void){
        int mib[4] = { CTL_KERN, KERN_PROC_ARGS, -1, KERN_PROC_PATHNAME };
        static char path[PATH_MAX];
        size_t size = sizeof path;
        if(sysctl(mib, 4, &path, &size, 0, 0)) return av0;
        return path;
}
#elif __APPLE__
#include <sys/types.h>
#include <mach-o/dyld.h>
const char *curpid_exe(void){
        static char path[PATH_MAX]; uint32_t z = sizeof path;
	if(_NSGetExecutablePath(path, &z)) return av0;
	return path;
}
#else
const char *curpid_exe(void){
	return av0;
}
#endif
