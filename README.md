![IMAGE](image01.png)

# evil-mhyprot-cli
An PoC for vulnerable driver "mhyprot" that allows us to read/write memory in kernel/user from usermode.

A brand new rootkit!

# Overview

What we can do with this driver is as follows:

- Read/Write any memory from kernel
- Read/Write any memory from usermode
- All operations are executed as kernel level privileage by the vulnerable driver

Also:

- Administrator privileage only needed if the service is not yet running
- Therefore we can execute commands above as the normal user (w/o administrator privileage)

---

The `mhyprot` is an anti-cheat kernel mode driver used in [`Genshin Impact`](https://genshin.mihoyo.com/ja).  
The driver has a vulnerable `IOCTL` commands that allows us to execute `MmCopyVirtualMemory` and `memcpy(in the kernel!)` from ring-3 (usermode).
