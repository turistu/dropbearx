## Tips for a small system

If you only want server functionality (for example), compile with

```
make PROGRAMS=dropbear
```

rather than just

```
make dropbear
```

so that client functionality in shared portions of Dropbear won't be included. The same applies if you are compiling just a client.

---
The following are set in *localoptions.h*:

* If you're compiling statically, you can turn off host lookups.

* You can disable either password or public-key authentication, though note that the IETF draft states that pubkey authentication is required.

* Similarly with DSS and RSA, you can disable one of these if you know that all clients will be able to support a particular one. The IETF draft states that DSS is required, however you may prefer to use RSA. **DON'T** disable either of these on systems where you aren't 100% sure about who will be connecting and what clients they will be using.

* Disabling the `MOTD` code and `SFTP-SERVER` may save a small amount of codesize.

* You can disable x11, tcp and agent forwarding as desired. None of these are essential, although agent-forwarding is often useful even on firewall boxes.

---
If you are compiling statically, you may want to disable zlib, as it will use a few tens of kB of binary-size
```
./configure --disable-zlib
```

You can create a combined binary, see the file [MULTI.md](MULTI.md), which will put all the functions into one binary, avoiding repeated code.

If you're compiling with gcc, you might want to look at gcc's options for stripping unused code. The relevant vars to set before configure are:

```
LDFLAGS=-Wl,--gc-sections
CFLAGS="-ffunction-sections -fdata-sections"
```

You can also experiment with optimisation flags such as `-Os`. Note that in some cases these flags actually seem to increase size, so experiment before
deciding.

Of course using small C libraries such as uClibc and dietlibc can also help.

---
Libtommath has its own default `CFLAGS` to improve speed. You can use

```
./configure LTM_CFLAGS=-Os
```

to reduce size at the expense of speed.

If you have any queries, mail me and I'll see if I can help.
