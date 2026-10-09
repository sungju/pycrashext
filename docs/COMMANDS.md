# Pycrashext Command Reference

Pycrashext is a PyKdump-based extension suite for the Linux crash utility. It provides 30+ commands for kernel crash dump analysis covering memory, CPU, networking, filesystem, processes, locking, tracing, and more.

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
- [AI-Assisted Analysis](#ai-assisted-analysis)
  - [ai](#ai)
- [Reverse Engineering](#reverse-engineering)
  - [revs](#revs)
- [Utility Commands](#utility-commands)
  - [screen](#screen)
  - [caseinfo](#caseinfo)
  - [git](#git)
  - [kvercmp](#kvercmp)

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
| `-b` | `--buddyinfo` | Show /proc/buddyinfo-like output |
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
| `-n` | `--fsnotify` | | Show fsnotify details |
| `--negdents` | | | Show negative dentries |
| `-r` | `--page_caches` | | Show page caches |
| `-s` | `--slab` | | Show dentry details in slab |
| `--show_open_files` | | | Show open files per process |
| `--show_open_file_size` | | | Show file size of open files |
| `-S` | `--swap` | | Show swap usage |
| `-t` | `--task` | | Show task-related information |
| `-p` | `--dumpe2fs` | | Show dumpe2fs-like information |

#### Examples

```
fsinfo -c                       # Show dentry/inode caches
fsinfo -r                       # Show page caches
fsinfo -S                       # Show swap usage
fsinfo --show_open_files        # Show open files per process
fsinfo --show_open_file_size    # Show file sizes of open files
fsinfo -f 0xffff88003e500000    # Inspect struct file
fsinfo -i 0xffff88003a100000    # Inspect inode
fsinfo --findpidbyfile 0xffff...  # Find PID from file address
fsinfo -n                       # Show fsnotify details
fsinfo --negdents               # Show negative dentries
fsinfo -p                       # Show dumpe2fs-like output
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

Device information for block devices, character devices, and IOMMU/IOTLB.

**Usage:** `devinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-b` | `--block` | Show block device details |
| `-c` | `--char` | Show character device details |
| `-d` | `--details` | Show detailed information |
| `-i` | `--iotlb` | Show IOTLB information |
| `-q` | `--requests` | Show request details |

#### Examples

```
devinfo -b               # Show block devices
devinfo -c               # Show character devices
devinfo -b -d            # Detailed block device info
devinfo -i               # Show IOTLB info
```

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
| `-y` | `--symtab` | `<module>` | Retrieve module's symbol table |

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

Lock analysis for spinlocks and MCS locks.

**Usage:** `lockinfo [options]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-s` | `--spinlock` | `<addr>` | Show spinlock details for the given address |
| `-m` | `--mcslock` | | Show MCS lock information |
| `-x` | `--excluded` | | Show excluded details |

#### Examples

```
lockinfo -s 0xffff88003e...   # Inspect spinlock
lockinfo -m                   # Show MCS lock info
```

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

SELinux status and policy information.

**Usage:** `selinuxinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-d` | `--detail` | Show SELinux status |
| `-i` | `--info` | Show SELinux basic policy |
| `-f` | `--fsmount` | Show SELinux filesystem mount information |

#### Examples

```
selinuxinfo -d         # Show SELinux status
selinuxinfo -i         # Show basic policy info
selinuxinfo -f         # Show SELinux fs mounts
```

### auditinfo

Linux audit subsystem information including status, rules, and backlog.

**Usage:** `auditinfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-b` | `--backlog` | Show backlog process list |
| `-d` | `--details` | Show details if possible |
| `-r` | `--rules` | Show audit rules |
| `-s` | `--status` | Show audit status |

#### Examples

```
auditinfo -s           # Show audit status
auditinfo -r           # Show audit rules
auditinfo -b           # Show audit backlog processes
auditinfo -s -d        # Show detailed audit status
```

---

## Virtualization

### vminfo

Virtual machine and hypervisor information including overcommit assessment.

**Usage:** `vminfo [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-d` | `--details` | Show details (with --overcommit, append related raw values) |
| `-a` | `--all` | Show full details for all runqueues (implies -d) |
| `-c` | `--context` | Show VM context |
| `-o` | `--overcommit` | Assess hypervisor CPU/memory/storage overcommit |

#### Examples

```
vminfo                 # Show VM overview
vminfo -o              # Assess overcommit ratios
vminfo -o -d           # Overcommit with raw values
vminfo -c              # Show VM context
vminfo -a              # Show all runqueue details
```

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

Run Red Hat Insights checks against the crash dump data.

**Usage:** `insights [options]`

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-t` | `--test` | Run with test data |

#### Examples

```
insights               # Run insights checks
insights -t            # Run with test data
```

---

## AI-Assisted Analysis

### ai

Submit crash data to an AI engine for analysis. Supports multiple engines and models.

**Usage:** `ai [options] [prompt]`

| Option | Long Form | Argument | Description |
|--------|-----------|----------|-------------|
| `-c` | `--cmd` | `<command>` | The output of this command will be analysed (repeatable) |
| `-e` | `--engine` | `<engine>` | Choose AI engine to use |
| `-i` | `--input` | `<file>` | Use file for input data |
| `-m` | `--model` | `<model>` | Choose AI model to use |
| `-r` | `--reset` | | Reset AI prompt history |
| `-t` | `--taskid` | `<id>` | Set vmcore task ID |

#### Examples

```
ai What caused this crash?              # Ask about the crash
ai -c "bt" -c "log" Analyze this       # Analyze bt and log output
ai -e gemini What happened?            # Use Gemini engine
ai -m gpt-4 Explain the panic          # Use specific model
ai -i /tmp/data.txt Analyze this       # Use file as input
ai -r                                  # Reset conversation history
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

Execute `git log` and `git show` commands against remote kernel source repositories. Useful for looking up commit details and searching kernel source history.

**Usage:** `git <log|show> [git-options]`

#### Subcommands

| Subcommand | Description |
|------------|-------------|
| `log` | Search git log (supports all standard git log options, default: --max-count=1) |
| `show` | Show commit details (supports all standard git show options) |

#### Options

| Option | Argument | Description |
|--------|----------|-------------|
| `--repos` | `<repos>` | Comma-separated list of repos (e.g., rhel9,linux,upstream) |
| `--timeout` | `N` | Request timeout in seconds (default: 3600) |
| `--verbose` | | Show verbose output |

#### Examples

```
git log -Sclip_push --max-count=5           # Search for commits touching 'clip_push'
git show abc123def --stat                    # Show commit with diffstat
git log -Sinit_new_ldt --repos=rhel9,upstream  # Search specific repos
git log --author="Linus" --max-count=3      # Search by author
```

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
