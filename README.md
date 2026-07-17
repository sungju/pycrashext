# pycrashext

Crash extension commands for the Linux [crash utility](https://github.com/crash-utility/crash), built on [PyKdump](https://sourceforge.net/projects/pykdump/). It provides 30+ commands for kernel crash dump analysis covering memory, processes, networking, cgroups, modules, filesystems, scheduling, locks, and more — plus a rule-based engine that automatically detects known issues.

![Example screen of "edis -lrg"](https://github.com/sungju/pycrashext/blob/main/docs/edis_example.png)

## Prerequisites

- The [crash utility](https://github.com/crash-utility/crash)
- [PyKdump](https://sourceforge.net/projects/pykdump/) (`mpykdump` extension loaded in crash)

## Quick Start

```
$ git clone https://github.com/sungju/pycrashext
$ cd pycrashext
$ sh ./install.sh
$ logout
< login again >
```

The installer configures `~/.crashrc` to load the mpykdump extension and register all commands, and sets `PYKDUMPPATH` in `~/.bash_profile`. It also optionally configures `CRASHEXT_SERVER` for commands that require the remote API server (`edis`, `git`, `ai`).

## Project Structure

```
pycrashext/
├── source/               # Command modules and detection rules
│   ├── *.py              # 30+ crash commands (one per file)
│   ├── rules/            # 14 autocheck detection rules
│   ├── config.json       # Command registration config
│   ├── regext.py         # Registration logic
│   ├── crashhelper.py    # Shared helper utilities
│   └── crashcolor.py     # Color output support
├── remoteapi/            # Backend server for edis, git, ai commands
│   └── web/              # Flask app with plugin architecture
├── docs/                 # Screenshots and images
└── install.sh            # Installer script
```

## Commands

Every command accepts `-h` to show its available options. See [`source/README.md`](source/README.md) for detailed usage and examples.

| Command | Description |
|---|---|
| **ai** | Analyse command output using an AI model (needs remoteapi) |
| **auditinfo** | Audit subsystem information |
| **autocheck** | Diagnose known issues using the built-in detection rules |
| **bh** | Bottom half (softirq/tasklet) information |
| **caseinfo** | Show case number when running on a retrace server |
| **cginfo** | cgroup information (v1/v2/hybrid) |
| **cpuinfo** | CPU information, core topology, effective frequency analysis |
| **devinfo** | Device information |
| **edis** | Enhanced disassembly with source lines and callgraph (needs remoteapi) |
| **fsinfo** | Filesystem information (mount details, freeze status, dumpe2fs-style) |
| **git** | Run `git log`/`git show` on remote kernel source repos (needs remoteapi) |
| **hangcheck** | Show hung (D-state) tasks with details |
| **insights** | Run insights rules (needs remoteapi; currently deprecated) |
| **ipcinfo** | IPC information |
| **ipmi** | IPMI information |
| **lockinfo** | Lock related information (spinlock/MCS lock) |
| **lockup** | Detect long running tasks on CPUs |
| **meminfo** | Memory information (usage, NUMA, slab, OOM, buddyinfo, swap) |
| **modinfo** | Module information, disassembly, unloaded module recovery |
| **netinfo** | Network information |
| **psinfo** | `ps`-like process information (`--aux`, `--ef`, stack search) |
| **pstree** | Process list in tree format |
| **revs** | Reverse engineering helper (registers, instruction reference) |
| **schedinfo** | Scheduling information |
| **screen** | Screen handling (reset) |
| **seinfo** | SELinux sidtab information |
| **selinuxinfo** | SELinux status |
| **syscallinfo** | System call table listing and modification check |
| **timeinfo** | Time related information (clock sources) |
| **traceinfo** | ftrace/BPF tracing information |
| **vminfo** | Virtual machine information (balloon, hypervisor overcommit) |

## Autocheck (Automated Issue Detection)

The `autocheck` command runs all rules under `source/rules/` against the current crash dump and reports any known issues it finds, along with KCS article links and resolution steps.

Rules implement a standard interface (`add_rule()`, `run_rule()`, `is_major()`, `description()`) and can be added by dropping a new `.py` file into the `source/rules/` directory.

## Remote API Server

Some commands (`edis`, `git`, `ai`) require a backend server that has access to kernel source trees and/or AI engines. The server can run standalone or in Docker.

```
$ export RHEL_SOURCE_DIR="/path/to/kernel/sources"
$ cd remoteapi
$ ./run_standalone.sh     # or ./start_docker.sh
```

Then point crash at the server:

```
$ export CRASHEXT_SERVER=http://myserver:5000
$ crash
```

See [`remoteapi/README.md`](remoteapi/README.md) for full setup instructions.

## Environment Variables

| Variable | Description |
|---|---|
| `PYKDUMPPATH` | Path list containing the `source` directory (set by `install.sh`) |
| `CRASHEXT_SERVER` | Remote API server address (e.g., `http://myserver:5000`) |
| `AI_ENGINE` | Default AI engine (`ollama` or `podman`) |
| `AI_MODEL` | Default AI model name (e.g., `llama3.2`) |
| `AI_REQUEST_TIMEOUT` | AI request timeout in seconds (default: 30) |
| `CODE_THEME` | Color theme for AI markdown output |
| `PYTHON_LIB` | Additional Python library paths for `sys.path` |

## License

GPLv3 — see [LICENSE](LICENSE) for details.
