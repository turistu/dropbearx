#define _GNU_SOURCE
#include <unistd.h>
#include "includes.h"
#include "svr-util.h"

#ifdef HAVE_SETRESUID
int setxuid(uid_t uid, uid_t suid){
	return setresuid(uid, uid, suid);
}
int setxgid(gid_t gid, gid_t sgid){
	return setresgid(gid, gid, sgid);
}
int drop_saved_uid(uid_t UNUSED(suid)){
	return setresuid(-1, -1, geteuid());
}
#elif HAVE_SETREUID
int setxuid(uid_t uid, uid_t suid){
	if(setreuid(uid, suid)) return -1;
	return seteuid(uid);
}
int setxgid(gid_t gid, gid_t sgid){
	if(setregid(gid, sgid)) return -1;
	return setegid(gid);
}
int drop_saved_uid(uid_t suid){
	uid_t euid = geteuid();
	if(setreuid(euid, suid)) return -1;
	return setreuid(euid, euid);
}
#else
#error this needs either setresuid or setreuid
#endif
