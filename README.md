![LOGO](logo.png)
<p align="center">
  <img src="https://img.shields.io/github/license/kkent030315/evil-mhyprot-cli?style=for-the-badge">
  <img src="https://img.shields.io/github/last-commit/kkent030315/evil-mhyprot-cli?style=for-the-badge">
  <img src="https://img.shields.io/codefactor/grade/github/kkent030315/evil-mhyprot-cli?style=for-the-badge">
</p>

![IMAGE](images/image01.png)
![IMAGE](images/image04.png)
![IMAGE](images/image05.png)

# evil-mhyprot-cli

![IMAGE](images/image10.png)

A PoC for vulnerable driver "mhyprot" that allows us to read/write memory in kernel/user from usermode.

### ✅ Static Library is here: [libmhyprot](https://github.com/kkent030315/libmhyprot)
### ✅ Documents are moved to the [Wiki](https://github.com/kkent030315/evil-mhyprot-cli/wiki)

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

# Impact

Investigating

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
