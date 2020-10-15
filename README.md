![IMAGE](image01.png)

# evil-mhyprot-cli
An PoC for vulnerable driver "mhyprot" that allows us to read/write memory in kernel/user from usermode.

A brand new rootkit!

# Overview

What we can do with this CLI is as follows:

- Read/Write any kernel memory with privilege of kernel
- Read/Write any user memory with privilege of kernel
- All operations are executed as kernel level privileage by the vulnerable driver

Also:

- Administrator privileage only needed if the service is not yet running
- Therefore we can execute commands above as the normal user (w/o administrator privileage)

---

The `mhyprot` is an anti-cheat kernel mode driver used in [`Genshin Impact`](https://genshin.mihoyo.com/ja).  
The driver has a vulnerable `IOCTL` commands that allows us to execute `MmCopyVirtualMemory` and `memcpy(in the kernel!)` from ring-3 (usermode).

# Impact

allows SMEP? not yet sure but since it allows us to controll kernel memory i dont think it's not possible.

# Requirements

- Any version of Windows x64 that the driver works on
- Administrator privileage does not required if the service already running

# Usage

```
bin.exe [TargetProcess] -options
```

following options are available as of now:

- `t`
  - Perform Tests
- `d`
  - Print debug infos
- `s`
  - Print seedmap
