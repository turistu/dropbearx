const char *self_exe(const char *fallback);

/* /proc/curproc/exe does not work with execve() on netbsd.
  and even on dragonflybsd it's just a regular UNSAFE symlink: it also
  does not work if the executable was removed, as it does in linux */
#if __linux__ || __DragonFly__
#define SELF_EXE(fall_back)	"/proc/self/exe"
#else
#define SELF_EXE	self_exe
#endif
