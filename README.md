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
| **fsinfo** | Filesystem information (mount details, freeze status, dumpe2fs-style, page cache breakdown) |
| **git** | Run `git log`/`git show` on remote kernel source repos, and `git find` to check whether an upstream patch is backported into this kernel — falling back to git.kernel.org and GitHub when the local mirrors miss, with every match labelled `local` or `web` (needs remoteapi) |
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
| **rcuinfo** | RCU information (stalls, grace periods, node tree, per-CPU callbacks) |
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

## Investigating Page Cache Usage

`fsinfo -r` lists how many cached pages each mounted filesystem holds:

```
crash> fsinfo -r
```

When one filesystem stands out, pass its `struct super_block` address back to
the same option to see *what inside it* is holding the cache:

```
crash> fsinfo -r ffff888100aabbcc
crash> fsinfo -r ffff888100aabbcc --top 50
```

This walks the superblock's inode list once and reports:

- **Cache by file type** — regular files vs directories vs devices, so a cache
  held by metadata rather than data is obvious at a glance
- **Cached pages per inode** — a bucketed histogram answering whether the cache
  is a handful of huge files or a swarm of small ones
- **Cache density** — how much of those files is actually resident, plus how
  many are cached almost fully (read whole) versus barely at all (sampled, so
  evicting them buys little)
- **Dirty and writeback** — inodes that cannot be dropped without writeback
- **Top N inodes** — the largest consumers with filename, size, resident share,
  and `[dirty]` / `[writeback]` markers (`--top`, default 20)

Inodes that are being freed (`I_FREEING`/`I_WILL_FREE`) and inodes with no
cached pages are skipped. The dirty page count is the whole cache of the dirty
inodes, so treat it as an upper bound.

### Finding out *who* is holding it

When the cache is one big pile of regular files — a tmpfs with thousands of
generated filenames, say — the type breakdown says nothing useful. `--breakdown`
resolves a path for every cached inode and groups them:

```
crash> fsinfo -r ffff995380013800 --breakdown
crash> fsinfo -r ffff995380013800 --breakdown --depth 0    # full paths
```

| Section | Answers |
|---|---|
| Cache by directory | which tree it lives under (`--depth N` sets the grouping level, default 3) |
| Cache by filename pattern | which *producer* made it — varying ids collapse to `<ID>`/`<N>`, so 2000 `sess_a1b2c3d4` files become one row |
| Cache by owner | which uid |
| Held without a name | unlinked files still held open, and inodes with no reachable dentry |

That last one matters most on tmpfs: cache behind an unlinked file is not
reachable by path and is not freed until the last fd referencing it is closed,
so it will not show up in anything that walks the directory tree.

When *every* cached inode turns out to be unlinked, no path resolves for any of
them and the directory and pattern tables have nothing to say. That is not a
failure of the tool — it is the answer. `--holders` then names the processes
keeping those deleted files open, which is the only remaining route to a
culprit:

```
crash> fsinfo -r ffff995380013800 --breakdown --holders
```

It runs `foreach files` once for the whole system, so the cost does not grow
with the size of the filesystem. A file open in several processes is counted
under each of them, so those shares can exceed 100%.

An open fd is not the only thing that pins an inode, and on tmpfs it is usually
not the one that matters. `--holders` therefore also walks each inode's VMA
interval tree and reports the processes that have it **mapped** — a file that
was mapped and then had its fd closed, which is the normal life of a
`memfd_create()` or POSIX shm segment, is invisible to `foreach files` but
holds every one of its pages.

Anything left with no fd *and* no mapping is called out separately, along with
what can still be holding it: an unattached SysV segment held by the IPC
namespace alone, a descriptor in flight over a unix socket (`SCM_RIGHTS`), a
loop device's backing file, a swapfile, or a GEM/DRM buffer. An *attached* SysV
segment is not in that list — `shmat()` creates a VMA, so it shows up in the
mmap table instead.

Inodes whose `i_mmap` layout the build does not recognise are reported as
unclassified rather than counted as unmapped, and an inode with more mappings
than the walk limit is flagged so a short mapper list is not mistaken for a
complete one.

Finally, a tmpfs superblock that is `kern_mount()`ed is recognised and labelled
`<kernel-internal shmem>`. That is where `shmem_file_setup()` allocates from —
anonymous shared mappings, `memfd_create()`, SysV shm and DRM/GEM buffers — so
its inodes have no name and no path by construction. On that superblock
"unlinked" and "no path" are the normal state rather than a finding, and the
total is better read as shared-memory usage than as page cache.

Paths come from walking `d_parent` and reading `d_name` directly, with
ancestors memoised, so this costs no crash command per inode. Paths are
relative to the filesystem root and carry no mount point — every inode being
grouped belongs to the same superblock anyway.

## Finding Backported Patches

`git find` answers the question that comes up on nearly every kernel case: *is
this upstream fix in the kernel that crashed?* It looks the patch up in the
upstream tree by commit ID or subject text, then cross-checks the RHEL tree
matching the dump.

```
crash> git find <commit-id>
crash> git find net/mlx5e: Fix crash moving to switchdev mode
crash> git find <commit-id> --stat              # with a diffstat
crash> git find <commit-id> --repos=rhel8,rhel9 # check other RHEL trees too
```

The query type is detected automatically — 7-40 hex characters are treated as a
commit ID, anything else as subject text, which does not need quoting.

When the local mirrors miss, the server also asks the public kernel sources
(git.kernel.org cgit and the GitHub API). Every match is labelled **`local`** or
**`web`** so there is no ambiguity about where it came from — a local mirror and
a public tree often share a name such as `linux` or `torvalds`. Web matches are
still cross-checked for backports against the local RHEL trees.

```
crash> git find <commit-id> --web      # ask the public sources too
crash> git find <commit-id> --no-web   # local mirrors only
```

A commit reported as NOT FOUND exists neither in the local trees nor on the
public sources — useful for checking a fix someone has quoted at you.

The same command is available in [isos](https://github.com/sungju/isos) for
sosreport analysis, against the same remoteapi server.

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

### When the server name will not resolve

A remoteapi command failing with `Name or service not known` (errno -2) while
`curl` reaches the very same URL from the same shell is almost never a network
problem. crash runs PyKdump's bundled Python, which is statically linked, and
glibc resolves names by `dlopen()`ing the NSS modules — something a static
binary cannot do. Sockets work; only name lookup is broken. The other common
cause is crash running in a chroot or container, such as a retrace server, with
no `/etc/resolv.conf`.

The commands handle this themselves. On a name-lookup failure they resolve the
name without `getaddrinfo()`, cheapest first:

1. `/etc/hosts`, read directly
2. a resolver binary — `getent`, `dig`, `host`, `nslookup`, or the system
   `python3`. These are dynamically linked, so NSS still works for them; this
   is the step that rescues the static-interpreter case
3. a DNS query straight to the nameservers in `/etc/resolv.conf`, over UDP,
   for a host too stripped down to have any of those binaries

The request is then retried against the resolved address with the original
`Host:` header intact, so name-based virtual hosts still work. Connection
refused, timeouts and HTTP errors are left alone — those are real failures and
are reported exactly as before.

When none of the three steps works, the error lists what each one tried, which
usually identifies the cause on the spot.

If even that cannot resolve the name, set `CRASHEXT_SERVER` to the address.
Resolve it **on the host running crash**, not elsewhere, since split-horizon
DNS or a VPN may hand out a different answer there:

```
$ getent hosts myserver     # or: dig +short myserver
$ export CRASHEXT_SERVER=http://<address>:5000
```

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
