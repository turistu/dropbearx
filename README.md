#### see the [original README below](#original-readmemd)

This is a fork of [Matt Johnston's dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) ssh client/server with some new features like:
- support for `-o BatchMode=yes` for the client.
- support for `-o ConnectTimeout=<secs>` for the client.
- allow the user to prevent the server from creating pidfiles with `-P none`;
        also allow that misfeature to be configured away at compile time
	with `--disable-pidfile`.
- a new `-A <path>` option to let the server use some other file than the
        remote user's `~/.ssh/authorized_keys`.
- use of a unix domain socket instead of a pair of pipes for the stdin/out
        of the spawned command in non-interactive mode.
- a better password-reading function which doesn't depend on the deprecated
	`getpass()`.
	
some incompatible changes:
- allow `-t` (force pty) to work even when the stdin of the client is not
  a tty ([57f9cc9][57f9]); this simplifies implementing simple command line
  emulators. Unlike in openssh, a single `-t` should suffice.
- when in non-interactive mode, wait for an eof on the pipe reading from the
  child ([e48d1b0][e48d]); this brings it in line with openssh, simplifies
  scripts using background processes, and allows for passing the stdin/out fd
  to kernel modules (like nbd or usbib) or to other processes via `SCM_RIGHTS`.
- allow `-i` (inetd mode) of the server to be combined with `-E`.

and some fixes for:
- cross-compiling for and using it on android
- cross-compiling for openwrt
- building in another (sub-)directory

Build for Android with the NDK with:
```
autoreconf
./ndk-configure aarch64 /path-to/android-ndk-r25c
make -j
```
[e48d]: https://github.com/turistu/dropbearx/commit/e48d1b0fb55a939e623124f3edd257ebdc688b8b
[57f9]: https://github.com/turistu/dropbearx/commit/57f9cc95140c71dfb835a84327e3b65c0e4b0f8c

## Original README.md
## Dropbear SSH
A smallish SSH server and client
https://matt.ucc.asn.au/dropbear/dropbear.html

[INSTALL.md](INSTALL.md) has compilation instructions.

[MULTI.md](MULTI.md) has instructions on making a multi-purpose binary (ie a single binary which performs multiple tasks, to save disk space).

[SMALL.md](SMALL.md) has some tips on creating small binaries.

A mirror of the Dropbear website and tarballs is available at https://dropbear.nl/mirror/.

Please contact me if you have any questions/bugs found/features/ideas/comments etc
There is also a mailing list https://lists.ucc.asn.au/mailman/listinfo/dropbear

Matt Johnston
matt@ucc.asn.au


### In the absence of detailed documentation, some notes follow

----
#### Server public key auth

You can use *~/.ssh/authorized_keys* in the same way as with OpenSSH, just put the key entries in that file. They should be of the form:

```
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAwVa6M6cGVmUcLl2cFzkxEoJd06Ub4bVDsYrWvXhvUV+ZAM9uGuewZBDoAqNKJxoIn0Hyd0NkyU99UVv6NWV/5YSHtnf35LKds56j7cuzoQpFIdjNwdxAN0PCET/MG8qyskG/2IE2DPNIaJ3Wy+Ws4IZEgdJgPlTYUBWWtCWOGc= someone@hostname
```

You must make sure that *~/.ssh*, and the key file, are only writable by the user. Beware of editors that split the key into multiple lines.

Dropbear supports some options for authorized_keys entries, see the manpage.

----
#### Client public key auth

Dropbear can do public key auth as a client, but you will have to convert OpenSSH style keys to Dropbear format, or use dropbearkey to create them.

If you have an OpenSSH-style private key *~/.ssh/id_rsa*, you need to do:

```
dropbearconvert openssh dropbear ~/.ssh/id_rsa  ~/.ssh/id_rsa.db
dbclient -i ~/.ssh/id_rsa.db <hostname>
```

Dropbear does not support encrypted hostkeys though can connect to ssh-agent.

----
If you want to get the public-key portion of a Dropbear private key, look at dropbearkey's `-y` option.

----
To run the server, you need to generate server keys, this is one-off:

```
./dropbearkey -t rsa -f dropbear_rsa_host_key
./dropbearkey -t dss -f dropbear_dss_host_key
./dropbearkey -t ecdsa -f dropbear_ecdsa_host_key
./dropbearkey -t ed25519 -f dropbear_ed25519_host_key
```

Or alternatively convert OpenSSH keys to Dropbear:

```
./dropbearconvert openssh dropbear /etc/ssh/ssh_host_dsa_key dropbear_dss_host_key
```

You can also get Dropbear to create keys when the first connection is made - this is preferable to generating keys when the system boots. Make sure */etc/dropbear/* exists and then pass `-R` to the dropbear server.

----
If the server is run as non-root, you most likely won't be able to allocate a pty, and you cannot login as any user other than that running the daemon (obviously). Shadow passwords will also be unusable as non-root.

----
The Dropbear distribution includes a standalone version of OpenSSH's `scp` program. You can compile it with `make scp`. You may want to change the path of the ssh binary, specified by `_PATH_SSH_PROGRAM` in *options.h*. By default
the progress meter isn't compiled in to save space, you can enable it by adding `SCPPROGRESS=1` to the `make` commandline.
