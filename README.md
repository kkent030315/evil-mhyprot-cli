<p align="center"><img src="images/logo_min.png"></p>
<p align="center">
  <img src="https://img.shields.io/github/license/kkent030315/evil-mhyprot-cli?style=for-the-badge">
  <img src="https://img.shields.io/github/last-commit/kkent030315/evil-mhyprot-cli?style=for-the-badge">
  <img src="https://img.shields.io/codefactor/grade/github/kkent030315/evil-mhyprot-cli?style=for-the-badge">
</p>

![IMAGE](images/image01.png)
![IMAGE](images/image04.png)
![IMAGE](images/image05.png)

# evil-mhyprot-cli

A PoC for Mhyprot2.sys vulnerable driver that allowing read/write memory in kernel/user via unprivileged user process.

- [libmhyprot](https://github.com/kkent030315/libmhyprot)
- [Wiki](https://github.com/kkent030315/evil-mhyprot-cli/wiki)

# Overview

What we can do with this CLI is as follows:

- Read/Write any kernel memory with privilege of kernel from usermode
- Read/Write any user memory with privilege of kernel from usermode
- Enumerate a number of modules by specific process id
- Get system uptime
- Enumerate threads in specific process, result in allows us to reading `PETHREAD` structure in the kernel directly from CLI as well.
- Terminate specific process by process id with `ZwTerminateProcess` which called in the vulnerable driver context (ring-0).
- All operations are executed as kernel level privilege (ring-0) by the vulnerable driver

Also:

- Administrator privilege only needed if the service is not yet running
- Therefore we can execute commands above as the normal user (w/o administrator privilege)

# Requirements

- Any version of Windows x64 that the driver works on
- Administrator privilege **does not required** if the service already running

Tested on:

- Windows10 x64 1903
- Windows7 x64 6.1
- Windows8.1 x64 6.3

# Usage

```
*.exe <target_process_name> -<options>
```

following options are available as of now:

- `t`
  - Perform Tests
- `d`
  - Print debug infos
- `s`
  - Print seedmap

# Latest

![IMAGE](images/image10.png)
