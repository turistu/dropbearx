## Multi-Binary Compilation

To compile for systems without much space (floppy distributions etc), you can create a single binary. This will save disk space by avoiding repeated code between the various parts. If you are familiar with "busybox", it's the same principle.

Both the multi-binary (`dropbearmulti`) and the separate executables
(`dropbear`, `dbclient`) are built by `make` by default; to build just the
multi-binary, run `make multi`.

To use the binary, symlink it from the desired executable:

```
ln -s dropbearmulti dropbear
ln -s dropbearmulti dbclient
```
etc.

Then execute as normal:

```
./dropbear <options here>
```
