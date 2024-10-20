Run with QEMU:

```
qemu-system-x86_64 -drive file=disk.img,format=raw -bios bios.bin
```

Connect QEMU to GDB:

```
gdb
target remote localhost:1234
```
```
qemu-system-x86_64 -drive file=disk.img,format=raw -bios bios.bin -gdb tcp:localhost:1234
```

From C4tShell, enter the disk:

```
fs0:
```

It contains encrypted files.
Each of them starts with a magic `C4TB`.
According to "help" they can be decrypted with a command:

```
decrypt_file  - Decrypts a user chosen .c4tb file from a mounted storage, given a decryption key.
```

The bios.bin contains the implementation of the command.

Strings inside the bios binary reference the project:
https://github.com/tianocore/edk2/

