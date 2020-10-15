![IMAGE](image01.png)

# evil-mhyprot-cli
An PoC for vulnerable driver "mhyprot" that allows us to read/write memory in kernel/user from usermode.

# Overview

What we can do with this driver is as follows:

- Read/Write any memory from kernel
- Read/Write any memory from usermode
- All operations are executed as kernel level privileage by the vulnerable driver

Also:

- Administrator privileage only needed if the service is not yet running
- Therefore we can execute commands above as the normal user (w/o administrator privileage)
