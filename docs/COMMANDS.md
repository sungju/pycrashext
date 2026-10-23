# Pycrashext Command Reference

Pycrashext is a PyKdump-based extension suite for the Linux crash utility. It provides 37 commands for kernel crash dump analysis covering memory, CPU, storage, networking, filesystem, processes, locking, tracing, and more.

All commands are invoked inside the crash utility as `epython <command>.py [options]` or directly by name if registered via `install.sh`.

---

## Table of Contents

- [Memory Analysis](#memory-analysis)
  - [meminfo](#meminfo)
- [CPU & Scheduling](#cpu--scheduling)
  - [cpuinfo](#cpuinfo)
  - [schedinfo](#schedinfo)
  - [lockup](#lockup)
- [Process Analysis](#process-analysis)
  - [psinfo](#psinfo)
  - [pstree](#pstree)
  - [hangcheck](#hangcheck)
- [Filesystem](#filesystem)
  - [fsinfo](#fsinfo)
- [Networking](#networking)
  - [netinfo](#netinfo)
- [Cgroup Analysis](#cgroup-analysis)
  - [cginfo](#cginfo)
- [Device & Module Information](#device--module-information)
  - [devinfo](#devinfo)
  - [modinfo](#modinfo)
- [Locking & Synchronization](#locking--synchronization)
  - [lockinfo](#lockinfo)
  - [rcuinfo](#rcuinfo)
- [Tracing & Debugging](#tracing--debugging)
  - [traceinfo](#traceinfo)
  - [edis](#edis)
  - [syscallinfo](#syscallinfo)
- [Security & Audit](#security--audit)
  - [seinfo](#seinfo)
  - [selinuxinfo](#selinuxinfo)
  - [auditinfo](#auditinfo)
- [Virtualization](#virtualization)
  - [vminfo](#vminfo)
- [IPC & Communication](#ipc--communication)
  - [ipcinfo](#ipcinfo)
  - [ipmi](#ipmi)
- [Bottom Half & Interrupts](#bottom-half--interrupts)
  - [bh](#bh)
- [Time](#time)
  - [timeinfo](#timeinfo)
- [Automated Diagnostics](#automated-diagnostics)
  - [autocheck](#autocheck)
  - [insights](#insights)
  - [evidence](#evidence)
- [AI-Assisted Analysis](#ai-assisted-analysis)
  - [ai](#ai)
- [Reverse Engineering](#reverse-engineering)
  - [revs](#revs)
- [Utility Commands](#utility-commands)
  - [screen](#screen)
  - [caseinfo](#caseinfo)
  - [git](#git)
  - [kvercmp](#kvercmp)
  - [logscan](#logscan)
  - [preempt](#preempt)
  - [sysinfo](#sysinfo)

---

## Memory Analysis

### meminfo

Memory information and analysis. Provides comprehensive memory subsystem inspection including buddy allocator, NUMA, slab, swap, OOM analysis, page ownership, and per-task memory accounting.

**Usage:** `meminfo [options]`

#### General Display Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-a` | `--all` | Show all the output |
| `-c` | `--compact` | Show compact data for other options |
| `-d` | `--details` | Show detailed output |
| `-g` | `--graph` | Show bar chart for memory usage visualization |
| `-l` | `--longer` | Show more data than normal |
| `--debug` | | Show debug output |
| `--progress` | | Show progress results while handling operation |
| `--reverse` | | Show results in reverse order |
| `--pager N` | | Show progress per specified term (default: 2000) |

#### Memory Overview

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-b` | `--buddyinfo` | Show /proc/buddyinfo-like output (the old spelling `--budyinfo` still works) |
| `-i` | `--meminfo` | Show /proc/meminfo-like output |
| `-m` | `--numa` | Show NUMA info |
| `--overall` | | Show overall memory usage breakdown with bar graphs |

#### Slab Analysis

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-s` | `--slabtop` | | Show slabtop-like output |
| `-S` | `--slabdetail` | `<name>` | Show details of a specific slab |
| `--corrupt` | | `<addr\|name>[:<cpu>]` | Check SLAB corruption |

#### Per-Task Memory

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-u` | `--memusage` | Show memory usage by tasks |
| `-P` | `--pss` | Show memory usage (PSS) by tasks |
| `-n` | `--nogroup` | Show data in individual tasks (not grouped) |

#### OOM Analysis

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-O` | `--OOM` | | Analyse OOM messages in log |
| `--oom-summary` | | | Show OOM summary dashboard with pattern analysis |
| `--oom-count` | | `N` | Limit number of OOM events to display |
| `--oom-top` | | `N` | Show top N memory consumers (default: 10) |
| `--oom-tree` | | | Show the OOM task dump as a process tree |
| `--oom-ascii` | | | Use ASCII instead of Unicode glyphs in `--oom-tree` |
| `--process-filter` | | `<name>` | Filter OOM events by process name (comma-separated or regex) |
| `--shared` | | | Account for shared memory in OOM analysis to prevent double-counting |

#### Page & TLB Analysis

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-e` | `--error` | `<code>` | Interpret page_fault error code |
| `-f` | `--tlb` | `<addr>` | Show TLB list (CSD). Example: `meminfo -f 0xffffade6b68037e0 -d` |
| `-F` | `--pte_flags` | `<flags>` | Show the meaning of PTE flags |
| `-G` | `--gfp_mask` | `<mask>` | Interpret GFP mask value |
| `-o` | `--page_owner` | | Show page_owner details |
| `--po-slab` | | | Show slab-only allocations in page_owner mode (use with -o) |

#### VM & Swap

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-v` | `--vm` | Show 'vm' output with more details |
| `-w` | `--swap` | Show swap usage |
| `-W` | `--swap_full` | Show swap usage in detail |

#### Percpu

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-p` | `--percpu` | `<addr>` | Convert percpu address into virtual address |
| `-t` | `--type` | `<type>` | Specify percpu type: u8, u16, u32, u64, s8, s16, s32, s64, int |

#### Advanced Options

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-U` | `--user_alloc` | `<name>` | Show slub_debug=U usage |
| `--maxcount` | | `N` | Check only maxcount entries |
| `--memory_limit` | | `N` | Limit call trace storage to reduce memory usage (default: 0, no limit) |

#### Examples

```
meminfo -i                    # Show /proc/meminfo-like output
meminfo -b                    # Show buddy allocator state
meminfo -s                    # Show slab usage (slabtop)
meminfo -S kmalloc-256        # Show details of kmalloc-256 slab
meminfo -u                    # Show per-task memory usage
meminfo -P                    # Show per-task PSS memory usage
meminfo -O                    # Analyze OOM killer events
meminfo --oom-summary         # OOM dashboard with pattern analysis
meminfo -O --process-filter java  # OOM events filtered by process name
meminfo -m                    # Show NUMA memory info
meminfo -G 0x14200ca          # Decode GFP mask
meminfo -e 0x7                # Decode page fault error code
meminfo -o                    # Show page owner info
meminfo --overall             # Overall memory breakdown with graphs
meminfo -w                    # Show swap usage summary
meminfo -W                    # Show detailed swap usage
meminfo -p 0xffff --type u64  # Convert percpu address (u64 type)
meminfo --corrupt dentry      # Check dentry slab for corruption
```

---

## CPU & Scheduling

### cpuinfo

CPU information including capabilities, frequency, idle states, and topology.

**Usage:** `cpuinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-c` | `--capability` | Show CPU capability flags |
| `-d` | `--driver` | Show CPU idle driver |
| `-f` | `--cpufreq` | Show CPU frequency details |
| `-i` | `--cpuid` | Show CPU physical and core ID |
| `-o` | `--online` | Show online/offline CPU status |
| `-s` | `--cstate` | Show CPU C-state information |
| `--speed` | | Show effective CPU speed (APERF/MPERF) |
| `-t` | `--tlb` | Show CPU TLB state |
| `-v` | `--verbose` | Show more information |

#### Examples

```
cpuinfo                # Show default CPU info
cpuinfo -o             # Show online/offline CPUs
cpuinfo -f             # Show CPU frequency details
cpuinfo -c             # Show CPU capability flags
cpuinfo -s             # Show C-state info
cpuinfo --speed        # Show effective CPU speed
cpuinfo -i             # Show physical/core ID mapping
```

### schedinfo

Scheduling subsystem information including classes, features, RT details, and worker pools.

**Usage:** `schedinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-c` | `--classes` | Show scheduling classes |
| `-d` | `--details` | Show details |
| `-f` | `--sched_features` | Show /sys/kernel/debug/sched_features |
| `-r` | `--rt` | Show RT-related values |
| `-w` | `--worker_pool` | Show worker pool information |

#### Examples

```
schedinfo -c           # List scheduling classes
schedinfo -f           # Show sched_features
schedinfo -r           # Show RT scheduling info
schedinfo -w all       # Show worker pool info
```

### lockup

CPU lockup detection and runqueue analysis. Identifies which CPUs are locked up and shows associated task context.

**Usage:** `lockup [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-b` | `--backtrace` | | Show backtrace for locked CPUs |
| `-c` | `--compact` | | Show compact output |
| `-d` | `--details` | | Show detailed information |
| `-r` | `--reverse` | | Show longest holder at top |
| `-t` | `--tasks` | | Show tasks in each runqueue |
| `-s` | `--rt` | | Show RT scheduling information |
| `-q` | `--qspinlock` | `<addr>` | Show qspinlock details for address |
| `--smp-call` | | `<addr>` | Show SMP call function details |
| `-u` | `--user` | | Show user space information |

#### Examples

```
lockup                 # Show CPU lockup summary
lockup -r              # Show with longest holder first
lockup -d              # Show detailed lockup info
lockup -t              # Show tasks in runqueues
lockup -b              # Show backtraces for locked CPUs
lockup -q 0xffff...    # Examine qspinlock at address
```

---

## Process Analysis

### psinfo

Process information with various output formats and stack searching capabilities.

**Usage:** `psinfo [options]`

#### Display Formats

| Option | Long Form | Description |
|--------|-----------|-------------|
| `--aux` | | Show output like `ps aux` |
| `--auxcww` | | Show output like `ps auxcww` |
| `--auxww` | | Show output like `ps auxww` |
| `--ef` | | Show output like `ps -ef` |

#### Task Analysis

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-t` | `--task` | `<addr>` | Show general info about a specific task |
| `-p` | `--policy` | `<type>` | Show processes with specific scheduling policy |
| `-k` | `--taskname` | `<name>` | Limit search to matching task name |

#### Stack Searching

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-s` | `--searchstack` | `<pattern>` | Search task stacks using `bt -f` |
| `-S` | `--Searchstack` | `<pattern>` | Search task stacks using `bt -F` |
| `-n` | `--nodetails` | | Show no stack contents (summary only) |
| `-i` | `--include` | `<list>` | Comma-separated list of values to include in search |
| `-e` | `--exclude` | `<list>` | Comma-separated list of values to exclude from search |

#### Examples

```
psinfo --aux                        # ps aux equivalent
psinfo --ef                         # ps -ef equivalent
psinfo -t 0xffff88003e4d0000        # Show info for specific task
psinfo -s schedule                  # Search stacks for 'schedule'
psinfo -s mutex -k java             # Search java tasks for 'mutex' in stack
psinfo -s lock -i spin -e rcu       # Search for 'lock', include 'spin', exclude 'rcu'
psinfo -p SCHED_FIFO                # Show FIFO scheduled tasks
```

### pstree

Display the process hierarchy in a tree format with optional details.

**Usage:** `pstree [options]`

| Option | Description |
|--------|-------------|
| `-p` | Print process ID |
| `-u` | Print User ID |
| `-g` | Print number of threads as {N} |
| `-s` | Print task state |
| `-t <pid>` | Print specific task and its children |
| `-T` | Show threads as children with {name} notation |
| `-c` | Disable compact mode (compacts identical leaf processes by default) |
| `-A` | Use ASCII characters for tree (default: Unicode) |
| `-l` | Print state color legend |

#### Examples

```
pstree                   # Show full process tree
pstree -p -s             # Show tree with PIDs and states
pstree -t 1234           # Show process 1234 and its children
pstree -g                # Show thread counts
pstree -T                # Show individual threads
pstree -A                # ASCII mode for terminals without Unicode
```

### hangcheck

`hangcheck -g` groups the D-state tasks by where they wait (the first two
frames below the scheduler, e.g. `io_schedule < blk_mq_get_tag`) from one
`foreach UN bt`, with one example backtrace per top group as printed.

Detect and analyze processes in D-state (uninterruptible sleep) and zombie state.

**Usage:** `hangcheck [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-a` | `--all` | | Show all UN-state processes (default shows limited set) |
| `-n` | `--number` | `N` | Show top N longest D-state processes |
| `-d` | `--detail` | | Show task details |
| `-f` | `--files` | | Show open files for each task |
| `-b` | `--backtrace` | | Show kernel backtrace for each D-state task |
| `-t` | `--threshold` | `N` | Only show tasks in D state longer than N seconds |
| `-z` | `--zombie` | | Show zombie (ZO) processes |

#### Examples

```
hangcheck                # Show top D-state processes
hangcheck -a             # Show all D-state processes
hangcheck -b             # Show with backtraces
hangcheck -d -f          # Show details and open files
hangcheck -t 60          # Only D-state tasks stuck > 60 seconds
hangcheck -n 5           # Show top 5 longest D-state
hangcheck -z             # Show zombie processes
```

---

## Filesystem

### fsinfo

Filesystem information including dentries, inodes, page caches, swap, and open files.

**Usage:** `fsinfo [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-a` | `--all` | | Show all |
| `-d` | `--details` | | Show detailed information |
| `-c` | `--caches` | | Show dentry/inode caches |
| `-C` | `--CACHED` | | Show CACHED details |
| `-f` | `--file` | `<addr>` | Show detailed file info for `struct file` address |
| `--findpidbyfile` | | `<addr>` | Find PID from /proc file address |
| `--findpidbydentry` | | `<addr>` | Find PID from /proc dentry address |
| `-i` | `--inode` | `<addr>` | Show detailed inode info |
| `-I` | `--icache` | `[<super_block>]` | What is holding the dentry and inode caches: cache sizes and per-superblock reclaimable counts; with a superblock, its pinned vs reclaimable inodes and the directories holding its dentries |
| `--max` | | `N` | With `-I <super_block>`, stop each walk after N objects (default: 2000000) |
| `-n` | `--fsnotify` | `<addr>` | Show fsnotify details for an `fsnotify_group` |
| `--negdents` | | | Show negative dentries |
| `-r` | `--page_caches` | `[<super_block>]` | Page cache per superblock; with a superblock, what is consuming its cache |
| `--top` | | `N` | With `-r` or `-I <super_block>`, rows in each table (default: 20) |
| `--breakdown` | | | With `-r <super_block>`, group the cache by directory, filename pattern and owner, and report cache held by unlinked files |
| `--holders` | | | With `-r <super_block>`, the processes holding the cache by open fd and by mapping; with `-I <super_block>`, the processes holding pinned inodes open |
| `--depth` | | `N` | With `--breakdown`, group directories at N path components (default: 3; 0 for full paths) |
| `-s` | `--slab` | | Show dentry details in slab |
| `--show_open_files` | | | Show open files per process |
| `--show_open_file_size` | | | Show file size of open files |
| `-S` | `--swap` | | Show swap usage |
| `-t` | `--task` | `<task_struct>` | Show the task and its executable's file details |
| `-p` | `--dumpe2fs` | `<regex>` | Show dumpe2fs-like information for the superblocks whose root name matches (`*` for all) |
| `-z` | `--frozen` | | Is a filesystem freeze blocking the system (`-d` adds backtraces) |

#### Examples

```
fsinfo -z                       # Freeze verdict: frozen fs, blocked tasks, agents
fsinfo -c                       # Show dentry/inode caches
fsinfo -r                       # Page cache per filesystem
fsinfo -r 0xffff888100aabbcc --breakdown --holders   # What holds one filesystem's cache, and who
fsinfo -I                       # What holds the dentry and inode caches
fsinfo -I 0xffff888100aabbcc    # Pinned vs reclaimable inodes of one filesystem
fsinfo -S                       # Show swap usage
fsinfo --show_open_files        # Show open files per process
fsinfo --show_open_file_size    # Show file sizes of open files
fsinfo -f 0xffff88003e500000    # Inspect struct file
fsinfo -i 0xffff88003a100000    # Inspect inode
fsinfo --findpidbyfile 0xffff...  # Find PID from file address
fsinfo -n 0xffff88003b200000    # Show fsnotify_group details
fsinfo --negdents               # Show negative dentries
fsinfo -p '*'                   # dumpe2fs-like output for every superblock
```

---

## Networking

### netinfo

Network subsystem information including interfaces, protocols, sockets, and nftables.

**Usage:** `netinfo [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-d` | `--details` | | Show network details |
| `-i` | `--interface` | | Show network interfaces |
| `-n` | `--nft` | | Show nftables information |
| `-p` | `--proto` | | Show network protocols |
| `-s` | `--socket` | `<addr>` | Show socket details for `struct socket` address |
| `-S` | `--sock` | `<addr>` | Show `struct sock` details |

#### Examples

```
netinfo                       # Show network interfaces (default)
netinfo -i                    # Show network interfaces with driver info
netinfo -i -d                 # Show interfaces with detailed info (MTU, IRQ, etc.)
netinfo -p                    # Show network protocols with buffer sizes
netinfo -n                    # Show nftables tables and sets
netinfo -n -d                 # Show nftables with chain/rule details
netinfo -s 0xffff88003e...    # Inspect socket structure
netinfo -S 0xffff88003e...    # Inspect sock structure
```

---

## Cgroup Analysis

### cginfo

Cgroup information supporting cgroup v1, v2, and hybrid configurations. Provides memory analysis, process mapping, tree views, and advanced task group inspection.

**Usage:** `cginfo [options]`

#### Basic Analysis

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-m` | `--memory` | | Memory usage summary sorted by consumption (top 20 by default) |
| `-p` | `--process` | | Process-to-cgroup mapping |
| `-s` | `--subsys` | `<name>` | Show overview for a specific subsystem/controller (e.g., memory, cpu, io) |

#### Tree Views

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-t` | `--tree` | | Compact cgroup tree (name + task count); add -d for resource details |
| `-a` | `--all` | | Include cgroups with 0 tasks (hidden by default) |
| `-d` | `--detail` | | Detail mode: resource usage/limits per cgroup |
| `-l` | `--tasklist` | | Show task list per cgroup (use with -t) |
| `-n` | `--name` | `<name>` | Filter cgroup tree to entries whose name contains `<name>` |
| `-c` | `--cgroup` | `<addr>` | Show sub-tree rooted at specific cgroup address (hex) |

#### Advanced

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-g` | `--tglist` | | task_group list with CPU scheduling details |
| `-G` | `--tgtree` | `<addr>` | task_group tree from a given address (hex) |
| `-i` | `--idr` | | mem_cgroup IDR allocated entries |
| `-I` | `--IDR` | | mem_cgroup IDR all entries including free slots |

#### Examples

```
cginfo                        # Show version, hierarchy, and counts
cginfo -m                     # Memory usage summary (top consumers)
cginfo -m -d                  # Memory usage with detailed limits
cginfo -p                     # Process-to-cgroup mapping
cginfo -s memory              # Memory controller overview
cginfo -t                     # Compact cgroup tree
cginfo -t -d                  # Tree with resource details
cginfo -t -l                  # Tree with task lists
cginfo -t -n docker           # Filter tree to docker cgroups
cginfo -a -t                  # Include empty cgroups in tree
cginfo -c 0xffff88003e...     # Inspect specific cgroup subtree
cginfo -g                     # task_group scheduling details
```

---

## Device & Module Information

### devinfo

Storage status, block and character devices, block requests, swiotlb and
paravirtual I/O rings.

**Usage:** `devinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-s` | `--status` | Storage status: SCSI hosts and devices, FC remote ports, other disks, and the I/O each holds, with an answer on top (`-d` lists idle devices too) |
| `-b` | `--block` | Block majors and every disk: size, driver, queue type, hardware queues, scheduler (`-d` adds queue limits, stopped hardware queues, bio-based in-flight counts) |
| `-c` | `--char` | Character device regions and their `file_operations` |
| `-q` | `--requests` | Block requests queued or in flight, oldest first, and per device (`-d` adds hardware queue and tag) |
| `-i` | `--iotlb` | swiotlb bounce buffers: size and use (`-d` lists the slots in use) |
| `-p` | `--pvio` | Paravirtual I/O rings: what the host has not completed (`-d` adds structure addresses) |
| `-d` | `--details` | More detail for the options above |

#### Examples

```
devinfo -s               # is a host in error handling, a device or path down, I/O stuck?
devinfo -s -d            # ... and list every device and FC remote port
devinfo -q               # the requests behind it, oldest first
devinfo -b               # disks: size, driver, queue type, scheduler
devinfo -c               # character devices
devinfo -i               # swiotlb use
devinfo -p               # virtio / pvscsi / VMBus rings: host or guest side?
```

`--status` is `scsishow -p`/`-s` for every RHEL release: `scsishow -p` needs
`Scsi_Host->host_busy`, which is gone from RHEL8. It reads:
- SCSI hosts: state, BUSY (commands at the HBA: the `host_busy` counter on
  RHEL7, the in-flight commands of the tag set later), FAILED
  (`host_failed`: waiting for the error handler, which starts once it equals
  BUSY), BLOCKED, `host_eh_scheduled`, and the error handler thread.
- SCSI devices: state, BUSY (`device_busy`, or `budget_map` from RHEL9),
  BLOCKED, IOREQ/IODONE/IOERR/IOTMO counters, and the requests the device
  holds. Devices that are running, idle and error-free are left out unless
  `-d` is given.
- FC remote ports that are not online (all of them with `-d`).
- Other disks (NVMe with its controller state, virtio, dm, md, loop):
  requests held, or the in-flight count of a bio-based disk.

The answer is the worst finding:
- `ERROR RECOVERY`: host in recovery or with failed commands; NVMe
  controller resetting or connecting.
- `DEVICE OFFLINE`, `PATH DOWN` (FC remote port not online).
- `I/O STALLED` or `I/O SLOW`: the oldest request at the device is 30s/5s
  old from dispatch, or past the device timeout, or timed out; requests
  allocated 30s ago whose timer the driver keeps restarting; requests the
  device completed that the kernel has not finished; requests not sent to
  the driver for 30s.
- `QUEUE STOPPED` (quiesced, or stopped hardware queues with requests
  waiting), `DEVICE BLOCKED`.
- `BUSY` or `IDLE`. Errors and timeouts since boot are listed under the
  answer but are not a verdict.

Request ages are from allocation (`start_time` in jiffies on RHEL7,
`start_time_ns` against CLOCK_MONOTONIC from `tk_core` later) and from
dispatch (`jiffies - deadline + timeout`). The verdicts are in
`source/storstat.py`, with checks in `storstat_test.py`.

`--pvio` reads the rings a paravirtual device shares with the host: virtio
split virtqueues, VMware pvscsi `rings_state`, and Hyper-V VMBus channels
(storvsc, netvsc). It counts three things:
- HOST: what the guest posted and the host has not completed. For storvsc
  this is the device's `num_outstanding_req`, because the host reads a
  request off the ring at once and keeps it until it completes.
- GUEST: what the host completed and the guest has not processed.
- KICK: what the guest added without notifying the host.

It combines these with the age of the oldest block request the device holds.
The age is measured from dispatch (`jiffies - deadline + timeout`), per queue
for virtio-blk and per device otherwise. The answer is the worst state:
- `BROKEN`
- `HOST STALLED` (≥ 30s) or `HOST SLOW` (≥ 5s): the host stopped completing
  I/O, for example a datastore or backend stall.
- `GUEST NOT PROCESSING`: a lost interrupt or a stuck completion handler.
  It is named only when the host holds nothing.
- `GUEST NOT NOTIFIED`: only when every entry the host holds is unkicked.
- `IN FLIGHT` or `IDLE`

Receive and event queues hold buffers for the host to fill and are not
judged. Devices are found through pykdump's bus and SCSI-host walks, so RHEL
9.5 and later work too. Structures that live in modules
(`struct vring_virtqueue` from virtio_ring, `pvscsi_adapter`,
`storvsc_device`, VMBus from hv_vmbus, and virtio itself on RHEL7) need that
module's debuginfo. Without it the row says what to load with `mod -s`, and
the answer never reports an all-clear for a ring it could not read. The
ring arithmetic is in `source/pvring.py`, with checks in `pvring_test.py`.

### modinfo

Kernel module information including taint status, symbols, disassembly, and gap analysis.

**Usage:** `modinfo [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `--disasm` | | `<module>` | Disassemble functions in a module |
| `--details` | | `<module>` | Show module details |
| `-c` | `--contents` | | Show contents of each symbol |
| `-t` | | | Show tainted modules only |
| `-g` | | | Show gaps between modules and physically allocated sizes |
| `-a` | | | Show address range for the module |
| `-u` | | | Show unloaded module data if possible |
| `-f` | | | Show meanings of tainted flags |
| `-s` | | | Show strings from each data section |
| `-l` | | `N` | Set minimum string size to show for -s (default: 5) |
| `--batch_run` | | `<module>` | Run major options together for detailed info |
| `--target_dir` | | `<dir>` | Save results to this directory |
| `--nodate` | | | Do not use date in target filename |
| `-m` | `--module` | `<addr>` | Retrieve module structure from address |
| `-y` | `--symtab` | | Retrieve the module's symbol table (with `-m`) |
| `-r` | `--reverse` | | Disassemble from an unloaded module |

#### Examples

```
modinfo                           # List all loaded modules
modinfo -t                        # Show tainted modules only
modinfo -f                        # Show tainted flag meanings
modinfo -g                        # Show module gaps and sizes
modinfo -a                        # Show module address ranges
modinfo --details mymodule        # Detailed info for a module
modinfo --disasm mymodule         # Disassemble module functions
modinfo -y mymodule               # Show module symbol table
modinfo --batch_run mymod --target_dir /tmp  # Full analysis to /tmp
modinfo -u                        # Show unloaded module info
```

---

## Locking & Synchronization

### lockinfo

Lock owners and waiters: spinlocks, mutexes and rw_semaphores, and which locks hold up the hung (UN) tasks.

**Usage:** `lockinfo [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-s` | `--spinlock` | `<addr>` | Decode the spinlock at `<addr>`, list the CPUs queued on it and its likely holder |
| `-m` | `--mcslock` | | List every MCS queue, its lock and likely holders, and possible deadlocks |
| `-x` | `--excluded` | | With `-m`, also list the CPUs not in any queue |
| `-M` | `--mutex` | `<addr>` | Show a mutex's owner and its waiters in queue order |
| `-R` | `--rwsem` | `<addr>` | Show an rw_semaphore's writer or readers and its waiters |
| `-b` | `--blocked` | | Group every UN task by the mutex or rwsem it waits for, with owners, wait chains and deadlocks |

#### Examples

```
lockinfo -s 0xffff88003e...   # Inspect spinlock
lockinfo -m                   # Show MCS queues and their locks
lockinfo -b                   # Who blocks the hung (UN) tasks
lockinfo -M 0xffff9e2a...     # Inspect a mutex
```

A spinlock does not record which CPU holds it. lockinfo reports the
waiters it can read from the dump, then infers the likely holders from
every CPU's backtrace.

- **qspinlock (RHEL8 and later).** `-s` decodes the locked byte, the pending
  bit and the tail. The layout comes from `CONFIG_NR_CPUS` (`help -k`), not
  from the number of CPUs online. The tail names the last CPU queued.
  lockinfo walks back from that CPU's MCS node to the queue head. Only
  nodes that are in use count: on each CPU, the first `qnodes[0].count`
  slots, one per nesting level. When the locked byte is `_Q_SLOW_VAL`
  (paravirt), the halted head is looked up in `pv_lock_hash`.
- **`-m`** rebuilds every queue from the in-use nodes, then finds each
  queue's lock on its waiters' `bt -f` output. A stack or register word
  counts as the lock only if the 32-bit value there has a tail naming that
  queue's tail CPU and slot. Each match shows how many waiters' stacks it
  was found on.
- **Ticket locks (RHEL7).** `-s` shows head and tail and the number of
  waiters, not counting the holder. With `CONFIG_PARAVIRT_SPINLOCKS` the
  ticket step is 2 and the slowpath flag is masked out. It also lists the
  waiters that halted, from `klock_waiting` (KVM) or `lock_waiting` (Xen).
- **Holder.** On debug kernels (`CONFIG_DEBUG_SPINLOCK`), lockinfo prints
  the owner recorded in `raw_spinlock`. Otherwise it lists the CPUs outside
  the lock's queue that have the lock address, or a pointer up to 512 bytes
  below it (the containing object), in their `bt -f` words or registers.
  - An exact address ranks above a nearby pointer.
  - A CPU spinning on a lock that could not be identified ranks lower.
  - Where the kernel keeps a preempt count (RHEL9 and later, read from
    `pcpu_hot`; `CONFIG_DEBUG_ATOMIC_SLEEP` kernels), a CPU with preempt
    depth 0 is ruled out, because a spinlock holder runs with preemption
    disabled. If that would rule out every CPU, they are all shown anyway:
    `arch_spin_lock()` users such as the ring buffer don't raise the count.
    On RHEL8 (`__preempt_count`) the depth is only shown, because a 0
    proves nothing there.
  - A CPU waiting for the lock from interrupt or softirq context stays on
    the list as a possible AA deadlock: the code it interrupted may hold
    the lock.
  - If no CPU references the lock, the likely causes are a missed unlock,
    a holder that slept with the lock held, or a corrupted lock word.
- **Pending spinners.** The first CPU to find a qspinlock held spins as the
  pending waiter and takes no queue node. lockinfo finds that CPU's lock
  among its own words: a word whose locked byte is 1 or 3 and whose
  pending byte is 1. `-m` lists such locks too, so a two-CPU deadlock
  shows up even when no queue exists.
- **Deadlocks (`-m`).** A likely holder that is itself queued or pending on
  another lock links the two locks. A cycle of such links is reported as a
  possible deadlock (ABBA).
- **PREEMPT_RT (kernel-rt).** `spinlock_t` is a sleeping rt_mutex. `-s`
  prints its recorded owner task first, then decodes the first word as a
  raw spinlock: that is either the lock itself, if it is a
  `raw_spinlock_t`, or the rt_mutex's `wait_lock`.

**Mutexes and rw_semaphores** record their owner, so there is no
guessing for writers:

- **Mutex.** RHEL8 and later read the owner word (task | `WAITERS`,
  `HANDOFF`, `PICKUP`). RHEL7 reads the count (1 free, 0 locked, negative
  with waiters) and the owner pointer.
- **rw_semaphore.** The writer is in `owner`. Readers are not tracked:
  `owner` holds only the last reader to take the lock, and it may have
  released it since. The reader count comes from `count`: bits 8-62 on
  RHEL8 and later, or the active count of the RHEL7 bias layout, where the
  wait list tells "one reader with waiters" apart from "a lone writer".
  For a read-held rwsem, lockinfo also lists the blocked tasks and
  running CPUs that have the lock's address on their stack but are not
  waiting for it, as possible readers.
- **Waiters** are listed in queue order from `wait_list`, with each task's
  state, how long ago it last ran (`ps -m`), and read or write for an
  rwsem. RHEL7's rwsem `slist_head` is handled.
- **`-b`** runs `foreach UN bt -f`. For each task sleeping in
  `__mutex_lock*` or `rwsem_down_{read,write}*`, it finds the task's own
  waiter struct on its stack (the word that equals its `task_struct`, with
  sane list links). The lock's `wait_list` head is the one entry on that
  waiter's ring that is not a waiter on some task's stack. For RHEL7's
  rwsem `slist`, whose head is not on the ring, the lock is instead a
  stack word, not on the task's own stack, whose `wait_list` points into
  the ring and whose count shows waiters. The tasks are grouped by lock,
  busiest lock first.
  - Each owner that is itself waiting is shown with the lock it waits for,
    including owners sleeping interruptibly, which the UN scan misses. An
    owner waiting for its own lock is reported as recursive locking.
  - A mutex with `PICKUP` set has been handed off to its next waiter,
    which hasn't run yet. lockinfo shows that, with no holder.
  - Cycles are reported as deadlocks.
  - The ends of the chains are listed with how many tasks each blocks.
    A chain ends at an owner that isn't waiting for a lock, or at a lock
    whose owner isn't recorded: typically a read-held rwsem such as
    `mmap_lock` or `i_rwsem`, whose readers are the real blockers.
  - Tasks in `TASK_INTERRUPTIBLE` (`mutex_lock_interruptible`) are not
    scanned.
- **PREEMPT_RT:** a mutex's rt_mutex owner is shown, but rw_semaphores
  (`rwbase_rt`) are not decoded.

The decoding is in `source/lockdecode.py`, with checks in
`lockdecode_test.py`. Also `python3 source/lockdecode.py <value>...`
decodes qspinlock words (`CONFIG_NR_CPUS` 8192 layout).

### rcuinfo

RCU (Read-Copy-Update) subsystem information including stall analysis, grace periods, node tree, callbacks, and blocked tasks.

**Usage:** `rcuinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-s` | `--stall` | Show detailed RCU stall analysis from dmesg |
| `-g` | `--gp` | Show grace period details |
| `-n` | `--node` | Show RCU node tree with quiescent state masks |
| `-c` | `--callbacks` | Show per-CPU RCU callback info |
| `-t` | `--tasks` | Show tasks blocked in RCU critical sections |
| `-a` | `--all` | Show all RCU information |
| `-v` | `--verbose` | Show additional details (backtraces for blocked tasks) |

#### Examples

```
rcuinfo                # Show RCU overview
rcuinfo -s             # Analyze RCU stalls from dmesg
rcuinfo -g             # Show grace period details
rcuinfo -n             # Show RCU node tree
rcuinfo -c             # Show per-CPU callback info
rcuinfo -t             # Show tasks in RCU critical sections
rcuinfo -t -v          # Show blocked tasks with backtraces
rcuinfo -a             # Show all RCU info
```

---

## Tracing & Debugging

### traceinfo

Tracing subsystem information including ftrace, BPF programs, and kprobes.

**Usage:** `traceinfo [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-b` | `--bpf_tree` | | Show BPF tree list |
| `-d` | `--details` | | Show details |
| `-m` | `--trace_modules` | | Show modules involved in ftrace |
| `-t` | `--trace_types` | | Show ftrace types |
| `-D` | `--debug` | | Show structure names and field sources in detailed output |
| `--disasm` | `--asm` | | Show disassembled BPF program code (use with -d) |
| `-i` | `--ip` | `<addr>` | Look up kprobe for a specific IP address (hex) |
| `-A` | `--addr` | `<addr>` | Identify BPF code at a given address (hex) |

#### Examples

```
traceinfo                       # Show tracing overview
traceinfo -t                    # Show ftrace types
traceinfo -m                    # Show modules using ftrace
traceinfo -b                    # Show BPF programs
traceinfo -b -d                 # Show BPF details
traceinfo -b -d --disasm        # Show BPF with disassembly
traceinfo -i 0xffffffff81...    # Look up kprobe at address
traceinfo -A 0xffffffff81...    # Identify BPF code at address
```

### edis

Enhanced disassembly with color highlighting, jump graphs, source line integration, and call graph analysis.

**Usage:** `edis [options] <function|address>`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-r` | `--reverse` | | Display all instructions from the start of the function |
| `-l` | `--list` | | Compatibility flag for `dis -l` |
| `-S` | `--stack` | `<addr>` | Set stack address for disasm operation |
| `-g` | `--graph` | | Display jump graph on the left |
| `-f` | `--full` | | Display full function code |
| `-b` | `--symbol` | | Translate symbols if possible |
| `-j` | `--jump` | `<ops>` | Show graph for specified jump operations only |
| `-D` | `--debug` | | Show stack calculation debug lines |
| `-n` | `--noaction` | | Only colorize output, do not connect to server |
| `-s` | `--sourceonly` | | Display source lines only |
| `-c` | `--callgraph` | | Show call graph for a function |
| `-m` | `--max_depth` | `N` | Maximum depth of graph for callgraph |

#### Examples

```
edis schedule                  # Disassemble schedule()
edis -g schedule               # Disassemble with jump graph
edis -f schedule               # Full function disassembly
edis -r 0xffffffff81234567     # From function start to address
edis -b schedule               # Disassemble with symbol translation
edis -c do_page_fault          # Show call graph
edis -c do_page_fault -m 3     # Call graph with max depth 3
edis -s schedule               # Source lines only
```

### syscallinfo

System call table inspection and integrity checking.

**Usage:** `syscallinfo [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-c` | `--check` | | Check for any modifications in syscall table |
| `-n` | `--no` | `<num>` | Show detailed information for a specific syscall number |

#### Examples

```
syscallinfo              # Show syscall table
syscallinfo -c           # Check for syscall table modifications
syscallinfo -n 1         # Show details for syscall #1 (write)
```

---

## Security & Audit

### seinfo

SELinux internal information including SID table details.

**Usage:** `seinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-s` | `--sidtab` | Show SID table information |
| `-t` | `--total` | Show total count |
| `-d` | `--detail` | Show details |

#### Examples

```
seinfo -s              # Show SID table
seinfo -s -d           # Show detailed SID info
seinfo -t              # Show total SID count
```

### selinuxinfo

SELinux status and policy information. Without options it prints the status (enabled or disabled, and enforcing or permissive) and any `selinux=`/`enforcing=` boot parameter.

Older kernels keep the state in the `selinux_enabled`, `selinux_enforcing` and `selinux_disabled` ints. RHEL8.10, RHEL9 and RHEL10 keep it in `struct selinux_state` (`initialized` stands for enabled, since `selinux_enabled_boot` is freed after boot; `disabled` is gone from RHEL10). `-d` shows which symbol each value came from.

**Usage:** `selinuxinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-d` | `--detail` | Show the status and the kernel symbols it was read from |
| `-i` | `--info` | Show what enforcing, permissive and disabled mean |
| `-f` | `--fsmount` | Show the selinuxfs superblock (`selinuxfs_mount`, or `selinux_null.mnt` on RHEL9 and later) and where it is mounted |

#### Examples

```
selinuxinfo            # Status
selinuxinfo -d         # Status and the kernel symbols behind it
selinuxinfo -i         # What the modes mean
selinuxinfo -f         # selinuxfs mounts
```

### auditinfo

Linux audit subsystem information including status, rules, and backlog.

**Usage:** `auditinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-b` | `--backlog` | Show tasks waiting for backlog space and how long, plus kauditd state (`-d` adds kauditd backtrace) |
| `-d` | `--details` | Show details if possible |
| `-m` | `--match` | Show which rule generated the queued audit records, counted per rule (`-d` lists each event) |
| `-r` | `--rules` | Show audit rules in `auditctl -l` format (`-d` adds entry addresses and syscall numbers) |
| `-s` | `--status` | Show audit status: auditd/kauditd state, all queues, and warnings for a full backlog, lost records or audit_panic (default) |

#### Examples

```
auditinfo -s           # Show audit status
auditinfo -r           # Show audit rules
auditinfo -b           # Show audit backlog processes
auditinfo -s -d        # Show audit status and dump the queued records
auditinfo -r -d        # Show rules with audit_entry addresses and syscall numbers
auditinfo -m           # Count queued audit events per rule that generated them
```

---

## Virtualization

### vminfo

Virtual machine and hypervisor information including overcommit assessment.

**Usage:** `vminfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-d` | `--details` | Show details (with --overcommit, append related raw values) |
| `-a` | `--all` | Show full details for all runqueues and how to extract their timing fields (implies -d) |
| `-c` | `--context` | Show VM context |
| `-o` | `--overcommit` | Assess hypervisor CPU/memory overcommit, signal by signal |

#### Examples

```
vminfo                 # Show VM overview
vminfo -o              # Overcommit verdict, signals, blind spots
vminfo -o -d           # Overcommit with raw values
vminfo -c              # Show VM context
vminfo -a              # Show all runqueue details
```

`--overcommit` prints every check as a signal (`HIT`, `miss`, `n/a`) with its
value and threshold. Host-only signals decide (steal, a vCPU tick stalled in
user mode, a user task far past its CFS slice, a soft lockup while idle/user,
a balloon). Load, runqueues and stall bursts only make CPU `POSSIBLE`, and
guest swap, OOM and storage never change the answer. Log evidence is timed
against the end of the log. The verdict logic is in `source/overcommit.py`,
which isos's `vmware` command shares. Its log part also runs on a saved log:
`python3 source/overcommit.py <file>`.

---

## IPC & Communication

### ipcinfo

Inter-process communication information including shared memory and SYSV IPC.

**Usage:** `ipcinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-a` | `--all` | Show all data (default shows limited) |
| `-m` | `--memory` | Show shared memory information |
| `-d` | `--details` | Show details |
| `-s` | `--sysv` | Show SYSV allocations in each task |

#### Examples

```
ipcinfo -m             # Show shared memory info
ipcinfo -s             # Show SYSV IPC allocations
ipcinfo -m -d          # Detailed shared memory
ipcinfo -a             # Show all IPC data
```

### ipmi

IPMI (Intelligent Platform Management Interface) information.

**Usage:** `ipmi [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-l` | `--smi_list` | Show SMI info list |
| `-d` | `--details` | Show detailed information |

#### Examples

```
ipmi -l                # Show SMI info list
ipmi -l -d             # Show detailed SMI info
```

---

## Bottom Half & Interrupts

### bh

Bottom half information including softirqs and tasklets.

**Usage:** `bh [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-s` | `--softirq` | Show softirq list |
| `-t` | `--tasklet` | Show tasklet list |
| `-i` | `--hitasklet` | Show tasklet_hi list |

#### Examples

```
bh -s                  # Show softirq list
bh -t                  # Show tasklet list
bh -i                  # Show high-priority tasklet list
```

---

## Time

### timeinfo

Time subsystem information including clock sources.

**Usage:** `timeinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-s` | `--source` | Show time sources |
| `-d` | `--details` | Show details |

#### Examples

```
timeinfo -s            # Show time sources
timeinfo -s -d         # Show detailed time source info
```

---

## Automated Diagnostics

### autocheck

Automated detection of known issues using a rules engine. Runs detection rules against the crash dump to identify common problems.

**Usage:** `autocheck [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-a` | `--all` | Run all rules (default runs major rules only) |
| `-l` | `--list` | Show currently available rules |
| `-r` | `--reload` | Reload rules |

#### Examples

```
autocheck              # Run major detection rules
autocheck -a           # Run all detection rules
autocheck -l           # List available rules
autocheck -r           # Reload rules after modification
```

### insights

Run Red Hat Insights checks against the crash dump data. Needs a remoteapi server with the insights plugin re-enabled; it ships disabled (`remoteapi/web/plugins/insights.py.deprecated`). `autocheck` runs the local rules instead.

**Usage:** `insights [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-t` | `--test` | Run with test data |

#### Examples

```
insights               # Run insights checks
insights -t            # Run with test data
```

### evidence

Collects, in one crash session, the raw output a vmcore analysis rests on, into one Markdown file an AI (or an engineer) writes the report from, instead of an AI driving crash one command at a time. It runs a base set (`sys`, `caseinfo`, `sysinfo`, `bt`, `logscan`, the last 150 log lines, `mod -t`, `kmem -i`, `ps -S`, `autocheck`), picks the analysis branch from `sys` and the log signatures (`logsig.py`): panic/oops, OOM, hang/lockup/stall, sysrq, death of init. It then runs that branch's commands, with follow-ups from what it already saw (`edis -r <RIP>`, `sym`, `modinfo --details <module>`, `kmem <address>`, `hangcheck -g`, `lockup`, `rcuinfo`, `vminfo --overcommit -d` on a hung VM, ...).

Each output goes into the file under a `**Source:** \`/cores/tasks/<task>\` → \`<command>\`` line, exactly as printed, without colour codes. A long output keeps its first and last lines with a `<<< SKIPPED N lines >>>` line carrying the true count, so excerpts copied from it can be checked by `excerpt-markers --revive` and `/datacheck`. A short summary at the top (branches, fault, log signatures, commands that failed) is labelled as derived.

The file goes to `~/cases/<case>/vmcore-<task>-evidence.md` when the case is known (the task's `caseno`, as `caseinfo` reads it), else `~/cases/vmcores/<task>/`, else the current directory, else `$HOME`. The last line printed, `EVIDENCE file=... task=... case=... branches=... blocks=... bytes=...`, is for scripts. Pycrashext commands run in-process (their file as `__main__`, output captured) rather than through a nested epython, and `| grep`, `| head`, `| tail` and `| wc -l` after a command are applied by `evidence` itself.

**Usage:** `evidence [-o FILE] [-x "cmd; cmd"] [-f FILE] [-a] [--stdout] [-q]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-o` | `--output` | Write the evidence file here |
| `-x` | `--extra` | More commands to run, separated by `;` |
| `-f` | `--file` | More commands, one per line |
| `-a` | `--append` | Only run the `-x`/`-f` commands, appended to the existing file |
| `-t` | `--task` | Task ID, when the DUMPFILE path does not hold it |
| `--stdout` | | Print the evidence instead of writing a file |
| `-q` | `--quiet` | Do not print each command as it runs |

#### Examples

```
evidence                                   # Collect into ~/cases/<case>/vmcore-<task>-evidence.md
evidence -a -x "bt 1234; kmem ffff9c0012345678"   # Follow-ups, appended to the file
evidence -a -x "log | grep -i nfs; kvercmp kernel-4.18.0-553.22.1.el8_10"
echo -e "evidence -q\nquit" | allspark revive <task>   # From a script: one session, no prompt
```

The plan and the layout are in `evidplan.py`; `python3 evidplan_test.py` and `python3 evidence_test.py` (a stand-in pykdump) check them without crash. The agent-skills `/vmreport` skill writes the vmcore report from this file.

---

## AI-Assisted Analysis

### ai

Submit crash command output (or a file), with an optional question, to an AI model. The engine is a local `claude` or `gemini` CLI when `-e` names one or, without `-e`, when one is on the PATH; otherwise the remoteapi server (`CRASHEXT_SERVER`), which forwards to ollama or podman (`-e`/`AI_ENGINE`, `-m`/`AI_MODEL`). It needs something to analyse: at least one `-c`, an `-i` file, or a question.

**Usage:** `ai [options] [prompt]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-c` | `--cmd` | `<command>` | The output of this command will be analysed (repeatable) |
| `-e` | `--engine` | `<engine>` | `claude` or `gemini` (local CLI), or an engine of the remoteapi server (`ollama`, `podman`) |
| `-i` | `--input` | `<file>` | Use file for input data |
| `-m` | `--model` | `<model>` | Choose AI model to use |
| `-r` | `--reset` | | Reset AI prompt history |
| `-t` | `--taskid` | `<id>` | Set vmcore task ID |

#### Examples

```
ai What caused this crash?              # Ask about the crash
ai -c "bt" -c "log" Analyze this       # Analyze bt and log output
ai -e gemini -c "bt" What happened?    # Use the local Gemini CLI
ai -e ollama -m llama3.2 -c "log"      # Use the remoteapi server's ollama model
ai -i /tmp/data.txt Analyze this       # Use file as input
ai -r -c "bt"                          # Start a fresh conversation (server history)
```

---

## Reverse Engineering

### revs

Reverse engineering helper for assembly language and register conventions.

**Usage:** `revs [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-r` | `--regs` | | Show registers used for argument passing |
| `-a` | `--asm` | `<instruction>` | Show manual for a GNU assembly instruction |
| `-l` | `--list` | | Show list of instructions you can check details for |

#### Examples

```
revs -r                # Show argument passing registers
revs -a mov            # Show details about 'mov' instruction
revs -a call           # Show details about 'call' instruction
revs -l                # List available instructions
```

---

## Utility Commands

### screen

Terminal screen handling.

**Usage:** `screen [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-r` | `--reset` | Reset screen (clear colors and formatting) |

#### Examples

```
screen -r              # Reset terminal screen
```

### caseinfo

Show case number when running on a retrace server.

**Usage:** `caseinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-s` | `--sys` | Show sys output |

#### Examples

```
caseinfo               # Show case number
caseinfo -s            # Show sys output
```

### git

Execute `git log` and `git show` against remote kernel source repositories, and `git find` to check whether an upstream patch is backported into this kernel. Needs the remoteapi server (`CRASHEXT_SERVER`).

**Usage:** `git <log|show|find> [options]` (`git -h` is not accepted; use `git log --help`, `git show --help` or `git find --help`)

#### Subcommands

| Subcommand | Description |
|------------|-------------|
| `log` | Search git log (supports all standard git log options, default: --max-count=1) |
| `show` | Show commit details (supports all standard git show options) |
| `find` | Find an upstream patch by subject or commit ID and report whether it is backported into this kernel |

#### Options

| Option | Argument | Description |
|--------|----------|-------------|
| `--repos` | `<repos>` | Comma-separated list of repos (e.g., rhel9,linux,upstream) |
| `--timeout` | `N` | Request timeout in seconds (default: 3600) |
| `--verbose` | | Show verbose output |

#### `git find` options

| Option | Argument | Description |
|--------|----------|-------------|
| `--commit` | `<id>` | Force commit ID lookup |
| `--subject` | `<text>` | Force subject text search |
| `--max-count` | `N` | Maximum matches to report (default: 10) |
| `--upstream` | `<dir>` | Upstream repo directory name (default: auto-detect) |
| `--web` / `--no-web` | | Always / never query the public kernel sources (default: only when the local repos miss) |
| `--web-timeout` | `N` | Per-request web timeout in seconds (default: 20) |
| `--message-lines` | `N` | Lines of commit message to show (default: 20) |
| `--no-message` | | Show only the subject, not the message body |
| `--no-backport` | | Skip the backport cross-check |
| `--no-tags` | | Skip the release-tag lookup (much faster) |
| `--patch`, `--stat` | | Show the diff / diffstat of each match |
| `--update` | | Fetch the latest branch and tags into every repo first |

The query type is detected automatically: 7-40 hex characters are a commit ID, anything else is subject text, which does not need quoting.

#### Examples

```
git find <commit-id> --stat                  # Is this upstream fix in this kernel?
git find net/mlx5e: Fix crash moving to switchdev mode
git log -Sclip_push --max-count=5           # Search for commits touching 'clip_push'
git show abc123def --stat                    # Show commit with diffstat
git log -Sinit_new_ldt --repos=rhel9,upstream  # Search specific repos
git log --author="Linus" --max-count=3      # Search by author
```

---

### logscan

Which known kernel-log signatures this dump holds: panic, sysrq/NMI, oops,
corruption (`list_del corruption`, `refcount_t`, bad page state), stack
overflow, atomic context, OOM (cgroup, no killable process), soft/hard
lockup, hung tasks, RCU stalls, NETDEV watchdog, conntrack full, storage
transport errors, MCE/EDAC, hypervisor. For each: count, first and last
`log` line number, what it points to, then the first and last lines exactly
as `log` prints them. A panic made by a detection sysctl
(`softlockup_panic`, `hung_task_panic`, `panic_on_oom`) gets a reroute note.

**Usage:** `logscan [-a]` (`-a` prints every matching line). The catalogue is
`source/logsig.py`, which also runs on a saved log: `python3 source/logsig.py <file>`.

---

### preempt

Decodes `preempt_count`: preempt-disable depth, serving a softirq, bottom
halves disabled, hardirq nesting, NMI, and whether that is atomic context.

**Usage:** `preempt <value>...` or `preempt -l` (every preempt_count the kernel
log prints, each after its line). Also `python3 source/preemptcount.py <value>...`.

---

### sysinfo

What this machine was, before starting on the vmcore. One screen with what
`sys` does not give:

- **Platform**: bare metal and whose (Dell, HPE, Lenovo, Cisco UCS,
  Supermicro, ...), a VM and on what (VMware, Hyper-V, KVM/QEMU, RHV/oVirt,
  OpenStack, OpenShift Virtualization, Nutanix AHV, Xen, ...), or a cloud
  instance (Azure, EC2, GCE, OCI, ...), POWER LPAR or IBM Z. Decided from
  DMI and checked against the kernel's own hypervisor type and the
  `Hypervisor detected` log line; a disagreement is shown (KVM with Hyper-V
  enlightenments, SMBIOS passed through to a VM). BIOS date and its age at
  the crash, serial, and where that platform keeps its own record of the
  event (iDRAC TSR, iLO AHS, ESXi vmware.log, Azure boot diagnostics, ...).
- **Kernel**: RHEL major.minor from the release (`_N` suffix, else the GA
  release table), EUS/ELS notes, CentOS Stream/pre-release, UEK, debug and
  RT kernels.
- CPU model, microcode, NUMA nodes, memory, kdump reservation, dump file.
- **Taint** decoded; boot parameters that change how a crash reads
  (`mitigations=off`, `nohz_full`, `nowatchdog`, `hugepages`, ...); panic
  sysctls that were set (`panic_on_oops`, `hung_task_panic`, ...),
  `kernel.panic`, hung-task timeout, watchdog threshold, FIPS, SELinux.
- **Third-party products** by module (CrowdStrike, Trend Micro, McAfee,
  Veeam, PowerPath, HDLM, Veritas, Oracle ASM, GPFS, ZFS, NVIDIA, live
  patches, ...) and any other tainting module; driver stacks (VM, storage,
  network, cluster, containers, KVM host).
- Filesystems, network addresses, **workloads** from process names (Oracle
  instances, SAP HANA, Pacemaker, Kubernetes/OpenShift, KVM host, ...) and
  guest/cloud/security agents.
- Counts of the known log signatures (as `logscan`), the reroute note, and
  **Start with**: the commands to run first, from all of the above.

The output is grouped as Machine, Kernel and Software; everything that
deserves attention (load far above the CPU count, why an NMI became a panic,
the logscan reroute, platform disagreements, support state, boot parameters
that change the analysis) is gathered under **Worth noting**. Panic sysctls
are split into those set on this system and the RHEL defaults
(`panic_on_oops`, `hardlockup_panic`). Firmware and serial are shown for
bare metal only (`-v` for all).

Every section fails on its own, so it is safe in a crash startup script. The
last line, `SYSINFO platform=... kind=... rhel=... arch=... cpus=... mem=...
taint=... thirdparty=...`, is for scripts.

**Usage:** `sysinfo [-v]` (`-v` adds every DMI field, the whole boot command
line, every interface and tainted module). The rules are `source/sysenv.py`,
checked by `python3 source/sysenv_test.py`.

---

### kvercmp

Is a fix already in this dump's kernel? Compares the dump's kernel release
with the fixed kernels an errata or KCS article lists, under one set of rules:
only the same RHEL major counts; a fix in the kernel's own minor release (the
same release number, e.g. 553 for every `4.18.0-553.*.el8_10` build) is
compared in full, so `553.5.1` is older than `553.77.1`; a fix from an earlier
minor release only gives `LIKELY_FIXED`, to confirm with `git log`.

**Usage:** `kvercmp [-k <kernel>] <fixed kernel>...`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-k` | `--kernel` | Check this kernel instead of the dump's own release |

Prints each version as parsed, the verdict, and a last line
`KVERCMP verdict=<FIXED|LIKELY_FIXED|NOT_FIXED|NO_MATCH|UNKNOWN> current=... fix=...`.
The same report runs without crash: `python3 source/kernel_version.py <kernel> <fixed kernel>...`.

#### Examples

```
kvercmp kernel-4.18.0-425.3.1.el8 kernel-4.18.0-372.32.1.el8_6 kernel-5.14.0-162.6.1.el9_1
kvercmp -k 4.18.0-553.5.1.el8_10 kernel-4.18.0-553.77.1.el8_10
```

---

## Quick Reference

### Common Troubleshooting Workflows

**System hang investigation:**
```
autocheck              # Run automated checks first
lockup -r -d           # Check for CPU lockups
hangcheck -b           # Check D-state processes with backtraces
psinfo --aux           # Process overview
rcuinfo -s             # Check for RCU stalls
```

**Memory issue investigation:**
```
meminfo -i             # /proc/meminfo overview
meminfo --overall      # Memory breakdown with graphs
meminfo -s             # Slab usage
meminfo -u             # Per-task memory usage
meminfo -O             # OOM analysis
meminfo -b             # Buddy allocator state
```

**Network issue investigation:**
```
netinfo -i -d          # Interface details
netinfo -p             # Protocol buffer sizes
netinfo -n             # nftables state
```

**Process debugging:**
```
psinfo --aux           # Process list
pstree -p -s           # Process tree with PIDs and states
hangcheck -b           # D-state processes
psinfo -s <func>       # Search stacks for function
```

**Module investigation:**
```
modinfo -t             # List tainted modules
modinfo -f             # Show taint flag meanings
modinfo --details <mod>  # Detailed module info
modinfo --disasm <mod>   # Disassemble module
```

**Cgroup analysis:**
```
cginfo                 # Overview
cginfo -m              # Memory consumers
cginfo -t -d           # Tree with resource details
cginfo -p              # Process-to-cgroup mapping
```
