int dropbear_main(int ac, char **av);
int dbclient_main(int ac, char **av);
int dropbearkey_main(int ac, char **av);
int dropbearconvert_main(int ac, char **av);
int scp_main(int ac, char **av);

const struct prog *find_multi(const char *name);
const char *curpid_exe(void);

#if __DragonFly__	/* || __NetBSD__ does not work with execve */
#define PROC_SELF_EXE	"/proc/curproc/exe"
#elif __linux__
#define PROC_SELF_EXE	"/proc/self/exe"
#else
#define PROC_SELF_EXE	(curpid_exe())
#endif
