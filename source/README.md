# pycrashext commands #

These crash commands are implemented as [PyKdump](https://sourceforge.net/projects/pykdump/) epython scripts. The 'mpykdump' extension must be loaded in 'crash' before the commands can be used.

## Setup ##

The simplest way is to run the installer at the top of this repository:

```
$ git clone https://github.com/sungju/pycrashext
$ cd pycrashext
$ sh ./install.sh
$ logout
< login again >
```

'install.sh' does the following:

- Adds the 'mpykdump' extension loading and the command registration (`epython .../source/regext.py`) into '~/.crashrc'
- Sets 'PYKDUMPPATH' in '~/.bash_profile' so the command scripts under this directory can be found
- Optionally sets 'CRASHEXT_SERVER' in '~/.bash_profile' which is needed for the commands that talk to the 'remoteapi' server ('edis', 'git', 'ai' and 'insights'). See README.md under the ./remoteapi directory for the server setup.

### Environment variables ###

| Variable | Description |
|---|---|
| PYKDUMPPATH | Path list that contains this 'source' directory. Used to locate the command scripts |
| CRASHEXT_SERVER | remoteapi server address (example: `http://myserver:5000`). Used by 'edis', 'git', 'ai' and 'insights' |
| AI_ENGINE | Default AI engine for the 'ai' command ('ollama' or 'podman') |
| AI_MODEL | Default AI model name for the 'ai' command (example: llama3.2) |
| AI_REQUEST_TIMEOUT | Request timeout in seconds for the 'ai' command (default: 30) |
| CODE_THEME | Color theme used when rendering the markdown output of the 'ai' command |
| PYTHON_LIB | Additional python library paths to be added into sys.path |

### Command registration ###

Commands are registered by 'regext.py' which reads 'config.json' in this directory. Each entry looks like below and can be turned off by adding `"enabled": false`.

```
{
    "command" : "meminfo",
    "desc"    : "Memory information",
    "options" : "-h   - list available options",
    "help"    : "memory related information"
}
```

## Provided commands ##

Every command accepts '-h' to show the available options.

| Command | Description |
|---|---|
| ai | Analyse command output using an AI model (needs remoteapi) |
| auditinfo | Audit subsystem information |
| autocheck | Diagnose known issues using the rules under ./rules |
| bh | Bottom half (softirq/tasklet) information |
| caseinfo | Show case number when running on a retrace server |
| cginfo | cgroup information (v1/v2/hybrid) |
| cpuinfo | CPU information |
| devinfo | Device information |
| edis | Enhanced disassembly with source lines (needs remoteapi) |
| fsinfo | Filesystem information |
| git | Run 'git log/show' on remote kernel source repositories (needs remoteapi) |
| hangcheck | Show hung (D-state) tasks with details |
| insights | Run insights rules (needs remoteapi; server plugin currently deprecated) |
| ipcinfo | IPC information |
| ipmi | IPMI information |
| lockinfo | Lock related information (spinlock/mcs lock) |
| lockup | Detect long running tasks on CPUs |
| meminfo | Memory information |
| modinfo | Module related information |
| netinfo | Network information |
| psinfo | 'ps'-like process information |
| pstree | Process list in tree format |
| revs | Reverse engineering helper |
| schedinfo | Scheduling information |
| screen | Screen handling (reset) |
| seinfo | SELinux sidtab information |
| selinuxinfo | SELinux status |
| syscallinfo | System call table listing and modification check |
| timeinfo | Time related information (clock sources) |
| traceinfo | ftrace/BPF tracing information |
| vminfo | Virtual machine related information |

## Commands ##

### insights ###

- Insights is a rule based engine to detect known issues. [https://github.com/RedHatInsights/insights-core](https://github.com/RedHatInsights/insights-core)
- This command sends the collected data to the 'remoteapi' server located under the ./remoteapi/ directory. For details on how to set up 'remoteapi', please check README.md under the ./remoteapi directory.
- NOTE: The server side insights plugin is currently deprecated (remoteapi/web/plugins/insights.py.deprecated), so this command only works against a server that re-enables that plugin. For local rule based checking, use 'autocheck' below.

```
crash> insights
===========================================================================
RULE ID : softlockup_find_get_pages|FIND_GET_PAGES_SOFTLOCKUP
	ERROR KEY      : FIND_GET_PAGES_SOFTLOCKUP
	Kernel version : 2.6.32-696.23.1.el6.x86_64
	Message        : The system had softlockup due to find_get_pages() bug
	KCS            : https://access.redhat.com/solutions/3390081

---------------------------------------------------------------------------
1 rules matched with the issued system
===========================================================================
```

### autocheck ###
It runs rules implemented under ./rules directory which will try to detect any known issues.

```
crash> autocheck
===========================================================================
ISSUE: find_get_page() softlockup BZ detected by find_get_page.py
---------------------------------------------------------------------------
ll_after_swapgs+0x156/0x220
 [<ffffffff815576d6>] ? system_call_fastpath+0x16/0x1b
 [<ffffffff8155756a>] ? system_call_after_swapgs+0xca/0x220
Code: d0 48 3b 34 c5 20 11 c2 81 77 3c 8d 0c 52 8d 4c 09 fa eb 09 66 0f 1f 44 00 00 83 e9 06 48 89 f0 48 d3 e8 83 e0 3f 48 8d 44 c7 18 <48> 8b 38 48 85 ff 74 14 83 ea 01 75 e2 c9 c3 0f 1f 84 00 00 00 
Call Trace:
 [<ffffffff8112ed5e>] ? find_get_page+0x1e/0xa0
 [<ffffffff8113097c>] ? generic_file_aio_read+0x24c/0x700
 [<ffffffff8119a6ba>] ? do_sync_read+0xfa/0x140
 [<ffffffff810a7280>] ? autoremove_wake_function+0x0/0x40
 [<ffffffff81248d1b>] ? selinux_file_permission+0xfb/0x150
 [<ffffffff8123b9c6>] ? security_file_permission+0x16/0x20
 [<ffffffff8119afb5>] ? vfs_read+0xb5/0x1a0
 [<ffffffff8119bd76>] ? fget_light_pos+0x16/0x50
 [<ffffffff81557627>] ? system_call_after_swapgs+0x187/0x220
 [<ffffffff8119b301>] ? sys_read+0x51/0xb0
 [<ffffffff815575fd>] ? system_call_after_swapgs+0x15d/0x220
 [<ffffffff815575f6>] ? system_call_after_swapgs+0x156/0x220
 [<ffffffff815576d6>] ? system_call_fastpath+0x16/0x1b
 [<ffffffff8155756a>] ? system_call_after_swapgs+0xca/0x220
BUG: soft lockup - CPU#1 stuck for 67s! [bpbkar:1837]
Module
---------------------------------------------------------------------------
KCS:
	softlockup in find_get_pages after installing kernel-2.6.32-696.23.1
	https://access.redhat.com/solutions/3390081
Resolution:
	Upgrade kernel to kernel-2.6.32-754.el6 or later version
---------------------------------------------------------------------------
***************************************************************************
	WARNING: 1 issue detected
***************************************************************************
```

- The rules can be implemented by having below two functions.

```
def add_rule(sysinfo):
	# Check if the rule can be applied on this vmcore
	# sysinfo is the output of 'sys' which can be used
	# to check kernel version/architecutre and panic message
	pass
	
def run_rule(sysinfo):
	# Actual checking is happening here
	# The result will be a list of dictionary
	# Each dictionary should contains the below key/value pairs
	"TITLE" : "title message"
	"MSG" : "Usually can be a proof message"
	"KCS_TITLE" : "Related article title"
	"KCS_URL" : "Related article URL"
	"RESOLUTION" : "Resolution message"
	pass
```

### syscallinfo ###
Shows system call list and can check for any modifications.

```
Options:
  -c, --check           Check for any modifications in syscall table
  -n SYSCALL_NO, --no=SYSCALL_NO
                        Shows detailed information for a specific syscall no
```

```
crash> syscallinfo 
  0 ffffffff8119a660 (T) sys_read                  fs/read_write.c: 435
  1 ffffffff8119a710 (T) sys_write                 fs/read_write.c: 453
  2 ffffffff81196aa0 (T) sys_open                  fs/open.c: 922
  3 ffffffffa0540960 (t) efab_linux_trampoline_close [onload]
  4 ffffffff8119fa20 (T) sys_newstat               fs/stat.c: 242
  5 ffffffff8119fb20 (T) sys_newfstat              fs/stat.c: 278
...

crash> syscallinfo --check
  3 ffffffffa0540960 (t) efab_linux_trampoline_close [onload] 
 13 ffffffffa051f720 (t) efab_linux_trampoline_sigaction [onload] 
 14 ffffffff810a06c0 (T) sys_rt_sigprocmask        kernel/signal.c: 2614
	callq  0xffffffff816bda00 <ftrace_regs_caller>
231 ffffffffa051e9c0 (t) efab_linux_trampoline_exit_group [onload] 
===========================================================================
3 system calls were replaced
1 system calls were modified
```

### pstree ###
It prints out process list in tree format.

```
crash> pstree -h
Usage: pstree.py [options]

Options:
  -h, --help  show this help message and exit
  -p          Print process ID
  -u          Print User ID
  -g          Print number of threads
  -s          Print task state
  -t TASK_ID  Print specific task and its children
  -A          Use ASCII characters for tree (default: Unicode)
  -l          Print state color legend
  -T          Show threads as children with {name} notation
  -c          Disable compact mode (identical leaf processes are
              compacted by default)
```

Examples)

```
crash> pstree
swapper/0 -+- systemd -+- systemd-journal 
           |           |- lvmetad 
           |           |- systemd-udevd -+- systemd-udevd 
           |           |                 `- systemd-udevd 
           |           |- dmeventd 
           |           |- auditd 
           |           |- dbus-daemon 
           |           |- rpcbind 
           |           |- polkitd 
           |           |- systemd-logind
...

crash> pstree -p
swapper/0(0) -+- systemd(1) -+- systemd-journal(811) 
              |              |- lvmetad(835) 
              |              |- systemd-udevd(843) -+- systemd-udevd(284694) 
              |              |                      `- systemd-udevd(284791) 
              |              |- dmeventd(1301) 
              |              |- auditd(1360) 
              |              |- dbus-daemon(1384) 
              |              |- rpcbind(1390) 
              |              |- polkitd(1406) 
              |              |- systemd-logind(1407)
...

crash> pstree -p -t 843
systemd-udevd(843) -+- systemd-udevd(284694) 
                    `- systemd-udevd(284791) 

Total 3 tasks printed
```

### lockup ###
Detects any long running tasks on CPUs.

```
Options:
  -b, --backtrace       Shows backtrace of the process
  -c, --compact         Exclude swapper/* from the list
  -d, --details         Show task details
  -r, --reverse         Show longest holder at top
  -t, --tasks           Show tasks in each runqueue
  -s, --rt              Show RT statistics
  -q QSPINLOCK, --qspinlock=QSPINLOCK
                        Shows qspinlock details
  --smp-call=SMP_CALL   Analyze SMP call function data: --smp-call
                        <call_function_data_addr>[,<__call_single_data_addr>]
  -u, --user            Show user space running only
```

```
crash> lockup
CPU  13:       0.00 sec behind by 0xffff880179ac5e20, swapper/13 [N:120] (1 in queue)
CPU   9:    7092.64 sec behind by 0xffff880179ac1f60, swapper/9 [N:120] (2 in queue)
CPU  15:    7111.28 sec behind by 0xffff880eba386dd0, java [N:120] (1 in queue)
CPU  12:    7111.29 sec behind by 0xffff880e21ffde20, java [N:120] (1 in queue)
CPU   3:    7111.29 sec behind by 0xffff880fd66cde20, java [N:120] (1 in queue)
CPU   4:    7111.29 sec behind by 0xffff880ed071bec0, java [N:120] (1 in queue)
CPU   8:    7531.39 sec behind by 0xffff880179ac0fb0, swapper/8 [N:120] (1 in queue)
CPU   6:    7558.16 sec behind by 0xffff880179a5edd0, swapper/6 [N:120] (1 in queue)
CPU   7:    7603.23 sec behind by 0xffff880e936b1f60, java [N:120] (2 in queue)
CPU  14:    7611.83 sec behind by 0xffff880e6f3b8000, java [N:120] (2 in queue)
CPU  10:    7631.04 sec behind by 0xffff8800a3df2f10, java [N:120] (3 in queue)
CPU  11:    7633.36 sec behind by 0xffff880fd27c4e70, java [N:120] (3 in queue)
CPU   1:    7645.53 sec behind by 0xffff880fd27c0000, kworker/u32:0 [N:120] (2 in queue)
CPU   2:    7656.36 sec behind by 0xffff880179a5af10, swapper/2 [N:120] (1 in queue)
CPU   0:    7658.46 sec behind by 0xffff880e813fce70, kworker/0:2 [N:120] (2 in queue)
CPU   5:    7661.00 sec behind by 0xffff880179a5de20, swapper/5 [N:120] (1 in queue)


crash> lockup --tasks
CPU  13:       0.00 sec behind by 0xffff880179ac5e20, swapper/13 [N:120] (1 in queue)
  CFS tasks:
                rngd (0xffff880ffb7bce70)[N:120] :      50.51 sec delayed in queue

CPU   9:    7092.64 sec behind by 0xffff880179ac1f60, swapper/9 [N:120] (2 in queue)
  RT tasks:
          watchdog/9 (0xffff880179438fb0)[F: 99] :       0.01 sec delayed in queue
  CFS tasks:
         kworker/9:1 (0xffff880ffb7fde20)[N:120] :       2.16 sec delayed in queue

CPU  15:    7111.28 sec behind by 0xffff880eba386dd0, java [N:120] (1 in queue)

CPU  12:    7111.29 sec behind by 0xffff880e21ffde20, java [N:120] (1 in queue)
...
```

### fsinfo ###
It provides mounted filesystem details and especially useful for filesystem freezing issue

```
crash> fsinfo | grep FREEZE
SB: 0xffff880431f34000, frozen=SB_FREEZE_COMPLETE, / (dm-1) [ext3], ()
SB: 0xffff880431d43800, frozen=SB_FREEZE_COMPLETE, /boot/ (sda1) [ext3], ()
SB: 0xffff880431d3d800, frozen=SB_FREEZE_COMPLETE, /opt/ (dm-7) [ext3], ()
SB: 0xffff880431d47800, frozen=SB_FREEZE_COMPLETE, /tmp/ (dm-6) [ext3], ()
SB: 0xffff880431d49800, frozen=SB_FREEZE_COMPLETE, /var/ (dm-4) [ext3], ()
```

Below is showing dumpe2fs style of information. (Only ext4 at this stage)

```
crash> fsinfo -p var
< struct super_block 0xffff881199c7f800 >
Filesystem volume name:        <none>
Last mounted on:               /var
Filesystem UUID:               a1e69927-ca89-4367-a8dc02f5d326fe05
Filesystem magic number:       0xEF53
Filesystem revision #:         1 (dynamic)
Filesystem features:           has_journal ext_attr resize_inode dir_index filetype recover extents flex_bg sparse_super large_file huge_file uninit_bg dir_nlink extra_isize
Filesystem flags:              signed_directory_hash
Default mount options:         user_xattr acl
Filesystem state:              clean
Errors behavior:               Continue
Filesystem OS type:            Linux
Inode count:                   655360
Block count:                   2621440 (10485760 KBytes)
Reserved block count:          131056 (524224 KBytes)
Free blocks:                   1891448 (7565792 Kbytes)
Free inodes:                   645802
First block:                   0
Block size:                    4096
Fragment size:                 4096
Reserved GDT blocks:           319
```


### cginfo ###
It provides cgroup related information. It is mostly useful to find out how many cgroups were created in the system.

#### cgroup v2 ####

```
crash> cginfo
+- / (0xffffffff8b24bc90)
  +- dev-hugepages.mount (0xffff8e3cdd9c8000)
  +- dev-mqueue.mount (0xffff8e3cce925000)
  +- init.scope (0xffff8e3cc1e1e000)
  +- sys-fs-fuse-connections.mount (0xffff8e3cc5a9c000)
  +- sys-kernel-config.mount (0xffff8e3cc5a9b000)
  +- sys-kernel-debug.mount (0xffff8e3cce924000)
  +- sys-kernel-tracing.mount (0xffff8e3cce921000)
  +- system.slice (0xffff8e3cc1e1b000)
    +- ModemManager.service (0xffff8e3cc91e4000)
    +- NetworkManager.service (0xffff8e3cc91e7000)
    +- accounts-daemon.service (0xffff8e3cc7d56000)
    +- alsa-state.service (0xffff8e3cc3567000)
    +- atd.service (0xffff8e3cc92e3000)
    +- auditd.service (0xffff8e3cc3563000)
...


crash> cginfo -d
+- / (0xffffffff8b24bc90)
   * cgroup.controllers (0xffff8e3cc121b000)
   * cgroup.max.depth (0xffff8e3cc121b280)
   * cgroup.max.descendants (0xffff8e3cc121bd80)
   * cgroup.procs (0xffff8e3cc121b700) = 2(kthreadd)  3(rcu_gp)  4(rcu_par_gp)  6(kworker/0:0H)  9(mm_percpu_wq)  10(rcu_tasks_kthre)  11(rcu_tasks_rude_)  12(rcu_tasks_trace)  13(ksoftirqd/0)

   ...

          +- pipewire.service (0xffff8e3cf8388000)
             * cgroup.controllers (0xffff8e3ceda42700)
             * cgroup.events (0xffff8e3ceda43880)
             * cgroup.freeze (0xffff8e3ceda56500)
             * cgroup.kill (0xffff8e3ceda56a80)
             * cgroup.max.depth (0xffff8e3ceda43400)
             * cgroup.max.descendants (0xffff8e3ceda42980)
             * cgroup.procs (0xffff8e3ceda42380) = 1418(pipewire) 
             * cgroup.stat (0xffff8e3ceda57d00)
             * cgroup.subtree_control (0xffff8e3ceda43a00)
             * cgroup.threads (0xffff8e3ceda42300) = 1418(pipewire)  1453(pipewire) 
             * cgroup.type (0xffff8e3ceda42800)
             * cpu.pressure (0xffff8e3ceda56080)
             * cpu.stat (0xffff8e3ceda56180)
             * io.pressure (0xffff8e3ceda57800)
             * memory.current (0xffff8e3ceda57380) = 499712
...
```

#### cgroup v1 ####

```
crash> cginfo --tree
** cgroup subsystems **

** cgroup tree **
/sys/fs/cgroup/cpuset/ at 0xffffa169934f0030
  +--/sys/fs/cgroup/cpuset/system.slice at 0xffffa188bcf24a00
    +--/sys/fs/cgroup/cpuset/system.slice/docker-0a566b7e5212af346a85f614de5669b3ebfedfda5f9d1430dc1e48566f297147.scope at 0xffffa168bc749800
    +--/sys/fs/cgroup/cpuset/system.slice/docker-5b67e1f59a863b19ae16dc9f1c8208766ce8c5cd68393d2428ba752c2cb3ed10.scope at 0xffffa168bc56ac00
    +--/sys/fs/cgroup/cpuset/system.slice/docker-4ebbec3382d7ab19213904ca844d135b52468d64d4be7ef230ef71d42a47fa56.scope at 0xffffa168b9f79e00
    +--/sys/fs/cgroup/cpuset/system.slice/docker-985df33f38f253487031a4fd47a9550639ee420e4cb16251d0f02169e99ae62e.scope at 0xffffa1885f2ddc00
    +--/sys/fs/cgroup/cpuset/system.slice/docker-994cf27267cea77fbc27b558ae37dc5355f19645925c727b23cc8febd37f853c.scope at 0xffffa1683ba66c00
...
    +--/sys/fs/cgroup/net_cls,net_prio/system.slice/docker-dfe6c4a4450b325008af8843593fb54e552dd54f5b32c95aebdc58f0693e2828.scope at 0xffffa16892b6c600
    +--/sys/fs/cgroup/net_cls,net_prio/system.slice/docker-dfe6c4a4450b325008af8843593fb54e552dd54f5b32c95aebdc58f0693e2828.scope at 0xffffa16892b6c600
    +--/sys/fs/cgroup/net_cls,net_prio/system.slice/docker-c6e550101905020b91505cf30b97446924d5f28109928a22a0a58f679cd1fe3f.scope at 0xffffa1683a329600
    +--/sys/fs/cgroup/net_cls,net_prio/system.slice/docker-c6e550101905020b91505cf30b97446924d5f28109928a22a0a58f679cd1fe3f.scope at 0xffffa1683a329600


crash> cginfo --tglist
task_group = 0xffffa18893ff3400, cgroup = 0xffffa16b44e43c00
        (/sys/fs/cgroup/cpu,cpuacct/system.slice/docker-c6e550101905020b91505cf30b97446924d5f28109928a22a0a58f679cd1fe3f.scope)
task_group = 0xffffa1686cedc400, cgroup = 0xffffa167622dd400
        (/sys/fs/cgroup/cpu,cpuacct/system.slice/ntpd.service)
task_group = 0xffffa1686ced9c00, cgroup = 0xffffa188ad138a00
        (/sys/fs/cgroup/cpu,cpuacct/system.slice/docker-dfe6c4a4450b325008af8843593fb54e552dd54f5b32c95aebdc58f0693e2828.scope)
task_group = 0xffffa1682ff69c00, cgroup = 0xffffa17b53a06c00
        (/sys/fs/cgroup/cpu,cpuacct/system.slice/docker-378d9980d419b82ff95fbb1dd1cfe4331b21cb6a7fce517441a37c9f26831f2b.scope)
task_group = 0xffffa148c4b36800, cgroup = 0xffffa168bbaa3600
        (/sys/fs/cgroup/cpu,cpuacct/system.slice/docker-35ab6fcb7e543d1785ae510dc5fa1e1fb448f352c9a3305a8f74330ed5a2f418.scope)
...
task_group = 0xffffa1886e7a1000, cgroup = 0xffffa16895648800
        (/sys/fs/cgroup/cpu,cpuacct/system.slice)
task_group = 0xffffffff8dcc7040, cgroup = 0xffffa188bcaee030
        (/sys/fs/cgroup/cpu,cpuacct/)
----------------------------------------------------------------------
Total number of task_group(s) = 130
```


### modinfo ###
It provides module details as well as a way to disassemble all the functions in the module.

```
crash> modinfo -h
Options:
  -h, --help            show this help message and exit
  --disasm=DISASM_MODULE
                        Disassemble a module functions
  --details=MODULE_DETAIL
                        Show details
  -c, --contents        Show contents of each symbols
  -t                    Shows tainted modules only
  -g                    Shows gaps between modules as well as physically
                        allocated sizes
  -a                    Shows address range for the module
  -u                    Shows unloaded module data if possible
  -f                    Shows meanings of tainted flags
  -s                    Shows strings from each data section
  -l SHOW_LONGER_THAN   Set the minimum size to show for -s. default=5
  --batch_run=BATCH_RUN
                        Run major options all together to get detailed info
  --target_dir=TARGET_DIR
                        Result will be saved in this directory
  --nodate              Do not use date in target filename
  -m MODULE_ADDR, --module=MODULE_ADDR
                        Trying to retrieve module structure
  -y SYMTAB, --symtab=SYMTAB
                        Trying to retrieve module symbol table
  -r, --reverse         Trying to disasm from unloaded module
```

```
crash> modinfo
struct module *    MODULE_NAME                     SIZE
0xffffffffc036f780 dm_mod                        123941
0xffffffffc0389160 dm_log                         18411
0xffffffffc037c000 dm_region_hash                 20813
0xffffffffc03901c0 dm_mirror                      22289
0xffffffffc0382040 dca                            15130
0xffffffffc03ac3a0 pps_core                       19057
0xffffffffc03bd2a0 i2c_core                       63151
0xffffffffc03e11a0 ptp                            19231
0xffffffffc0395000 i2c_algo_bit                   13413

crash> modinfo --details oracleacfs
struct module   : 0xffffffffa085a200
name            : oracleacfs
version         : None
source ver      : 533BB7E5866E52F63B9ACCB
init            : init_module (0xffffffffa06a2370)
exit            : ofs_cleanup_module (0xffffffffa06a2320)

.text section
0xffffffffa07210a0 (t) STACK_delete
0xffffffffa0720fe0 (t) STACK_insert
0xffffffffa0720fa0 (t) Ri_LIB_CTX_get_res_meth
0xffffffffa0720f30 (t) ri_mode_filter_func
0xffffffffa0720ea0 (t) STACK_pop_free
0xffffffffa0720e30 (t) STACK_clear
0xffffffffa0720df0 (t) STACK_free
0xffffffffa0720d60 (t) STACK_move
0xffffffffa0720d50 (t) STACK_push
0xffffffffa0720d40 (t) STACK_unshift
0xffffffffa0720d10 (t) STACK_shift
0xffffffffa0720ce0 (t) STACK_pop


crash> modinfo --disasm=oracleacfs
---------- BEGIN disassemble OfsLocateExtent() ----------
0xffffffffa0500000 <OfsLocateExtent>:   push   %rbp
0xffffffffa0500001 <OfsLocateExtent+0x1>:       mov    %rsp,%rbp
0xffffffffa0500004 <OfsLocateExtent+0x4>:       push   %r14
0xffffffffa0500006 <OfsLocateExtent+0x6>:       push   %r13
0xffffffffa0500008 <OfsLocateExtent+0x8>:       push   %r12
0xffffffffa050000a <OfsLocateExtent+0xa>:       push   %rbx
0xffffffffa050000b <OfsLocateExtent+0xb>:       nopl   0x0(%rax,%rax,1)
0xffffffffa0500010 <OfsLocateExtent+0x10>:      xor    %r12d,%r12d
0xffffffffa0500013 <OfsLocateExtent+0x13>:      test   %rdx,%rdx
...
```

This command also can be very useful to track down any recently unloaded modules. It can be useful to find rootkit modules which has just disappeared.

```
crash> modinfo -u
struct module *    MODULE_NAME                     SIZE 
0xffffffffa000ed00 dm_mod                         81692 
0xffffffffa0016420 iTCO_vendor_support             3088 
...
0xffffffffa0138e60 dca                             7197 
0xffffffffa013df40 main                            9385  <-- rootkit module
0xffffffffa014bee0 ioatdma                        58482 
...


crash> modinfo -u -g
struct module *    MODULE_NAME                     SIZE ALLOC_SIZE    GAPSIZE
0xffffffffa000ed00 dm_mod                         81692      86016          0
...

0xffffffffa0138e60 dca                             7197      12288       8192
0xffffffffa013df40 main                            9385        N/A        N/A
0xffffffffa014bee0 ioatdma                        58482      65536      20480
...

crash> modinfo -u -g -a
struct module *    MODULE_NAME                     SIZE ALLOC_SIZE    GAPSIZE
0xffffffffa000ed00 dm_mod                         81692      86016          0
...
0xffffffffa0138e60 dca                             7197      12288       8192
   addr range : 0xffffffffa0138000 - 0xffffffffa013b000
0xffffffffa013df40 main                            9385        N/A        N/A
   addr range : 0xffffffffa013c000 - 0xffffffffa0140000
0xffffffffa014bee0 ioatdma                        58482      65536      20480
   addr range : 0xffffffffa0140000 - 0xffffffffa0150000
...
```

If you are suspecting an unloaded module in invalid op such as below, you can try 'modinfo -m {address}' to see if it was belong to a module.

```
crash> bt
PID: 24390  TASK: ffff9c271b16d140  CPU: 1   COMMAND: "badprocess"
 #0 [ffff9c1fb9c9fbb0] machine_kexec at ffffffff9d863674
 #1 [ffff9c1fb9c9fc10] __crash_kexec at ffffffff9d91cef2
 #2 [ffff9c1fb9c9fce0] crash_kexec at ffffffff9d91cfe0
 #3 [ffff9c1fb9c9fcf8] oops_end at ffffffff9df6c758
 #4 [ffff9c1fb9c9fd20] no_context at ffffffff9df5aafe
 #5 [ffff9c1fb9c9fd70] __bad_area_nosemaphore at ffffffff9df5ab95
 #6 [ffff9c1fb9c9fdc0] bad_area_nosemaphore at ffffffff9df5ad06
 #7 [ffff9c1fb9c9fdd0] __do_page_fault at ffffffff9df6f6b0
 #8 [ffff9c1fb9c9fe40] do_page_fault at ffffffff9df6f915
 #9 [ffff9c1fb9c9fe70] page_fault at ffffffff9df6b758
    [exception RIP: no symbolic reference]
    RIP: ffffffffc07fdfb0  RSP: ffff9c1fb9c9ff28  RFLAGS: 00010246
    RAX: ffffffffc07fdf20  RBX: 00000000f6c9f194  RCX: 0000000000000001
    RDX: 00000000f745bce8  RSI: 00000000f6c9f1d2  RDI: 00000000f6c9f194
    RBP: ffff9c1fb9c9ff48   R8: 00000000f6c9f194   R9: 00000000f6c9ee08
    R10: 0000000000000000  R11: 0000000000000000  R12: 0000000000000000
    R13: 00000000f6c9f194  R14: 0000000000000000  R15: 0000000000000000
    ORIG_RAX: ffffffffffffffff  CS: 0010  SS: 0000
#10 [ffff9c1fb9c9ff20] syscall_trace_enter at ffffffff9d83aadb
    RIP: 00000000f76838ed  RSP: 00000000f6c9edfc  RFLAGS: 00000286
    RAX: ffffffffffffffda  RBX: 00000000f6c9f194  RCX: 00000000f6c9f1d2
    RDX: 00000000f745bce8  RSI: 0000000000000001  RDI: 00000000f6c9f194
    RBP: 00000000f6c9ee08   R8: 0000000000000000   R9: 0000000000000000
    R10: 0000000000000000  R11: 0000000000000000  R12: 0000000000000000
    R13: 0000000000000000  R14: 0000000000000000  R15: 0000000000000000
    ORIG_RAX: 000000000000000a  CS: 0023  SS: 002b
```

From the above, 'RIP' is invalid. Let's check what was in there. If shows that the address was belong to the module ensilo.

```
crash> modinfo -m ffffffffc07fdfb0
Found the below module
	struct module 0xffffffffc0889de0
	name : ensilo_3_10_0_957_x86_64
	status : unloaded

crash> modinfo --details=0xffffffffc0889de0
struct module   : 0xffffffffc0889de0
name            : ensilo_3_10_0_957_x86_64
version         : None
source ver      : 1EC4D0D7D388B04E4A87252
init            : None (0xffffffffc08b0000)
exit            : None (0xffffffffc07f3160)

.text section

.bss section

.data section

.readonly_data section

```


### cpuinfo ###
It provides CPU related information include how cores are constructed.

```
crash> cpuinfo
CPU   0 (0xffffa168bd178200) min = 1200000, max = 2400000, cur = 2394574
        cpudata = 0xffffa168bd178400, current_pstate = 24, turbo_pstate = 34,
        min_pstate = 12, max_pstate = 24, policy = CPUFREQ_POLICY_PERFORMANCE
CPU   1 (0xffffa168bd178600) min = 1200000, max = 2400000, cur = 2394574
        cpudata = 0xffffa168bd178800, current_pstate = 24, turbo_pstate = 34,
        min_pstate = 12, max_pstate = 24, policy = CPUFREQ_POLICY_PERFORMANCE
CPU   2 (0xffffa168bd178a00) min = 1200000, max = 2400000, cur = 2394574
        cpudata = 0xffffa168bd178c00, current_pstate = 24, turbo_pstate = 34,
        min_pstate = 12, max_pstate = 24, policy = CPUFREQ_POLICY_PERFORMANCE
CPU   3 (0xffffa168bd178e00) min = 1200000, max = 2400000, cur = 2394574
...

crash> cpuinfo --cpuid
<<< Physical CPU   0 >>>
        CPU   0, core   0 : 0xffffa168bfc18200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   1, core   1 : 0xffffa168bfc58200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   2, core   2 : 0xffffa168bfc98200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   3, core   3 : 0xffffa168bfcd8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   4, core   4 : 0xffffa168bfd18200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   5, core   8 : 0xffffa168bfd58200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   6, core   9 : 0xffffa168bfd98200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   7, core  10 : 0xffffa168bfdd8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   8, core  11 : 0xffffa168bfe18200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU   9, core  12 : 0xffffa168bfe58200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  20, core   0 : 0xffffa168bfe98200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  21, core   1 : 0xffffa168bfed8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  22, core   2 : 0xffffa168bff18200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  23, core   3 : 0xffffa168bff58200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  24, core   4 : 0xffffa168bff98200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  25, core   8 : 0xffffa168bffd8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  26, core   9 : 0xffffa168c0018200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  27, core  10 : 0xffffa168c0058200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  28, core  11 : 0xffffa168c0098200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  29, core  12 : 0xffffa168c00d8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
<<< Physical CPU   1 >>>
        CPU  10, core   0 : 0xffffa188bf018200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  11, core   1 : 0xffffa188bf058200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  12, core   2 : 0xffffa188bf098200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  13, core   3 : 0xffffa188bf0d8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  14, core   4 : 0xffffa188bf118200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  15, core   8 : 0xffffa188bf158200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  16, core   9 : 0xffffa188bf198200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  17, core  10 : 0xffffa188bf1d8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  18, core  11 : 0xffffa188bf218200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  19, core  12 : 0xffffa188bf258200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  30, core   0 : 0xffffa188bf298200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  31, core   1 : 0xffffa188bf2d8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  32, core   2 : 0xffffa188bf318200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  33, core   3 : 0xffffa188bf358200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  34, core   4 : 0xffffa188bf398200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  35, core   8 : 0xffffa188bf3d8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  36, core   9 : 0xffffa188bf418200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  37, core  10 : 0xffffa188bf458200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  38, core  11 : 0xffffa188bf498200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz
        CPU  39, core  12 : 0xffffa188bf4d8200 Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz

        For details, run 'cpuinfo_x86  <address>'
```

`cpuinfo --speed` shows the *measured* effective frequency of each CPU using the kernel's own APERF/MPERF samples, so it works regardless of the active cpufreq driver (acpi-cpufreq, intel_pstate, HWP, etc.). It is aimed at soft-lockup analysis. On bare metal, a CPU running well below its maximum frequency while also falling behind on scheduling is flagged as a `SUSPECT`, because a sustained low frequency can stretch a normally quick operation past the soft-lockup threshold. Thermal-throttle counts (core/package) are direct evidence the hardware capped the frequency.

```
crash> cpuinfo --speed
Base frequency = 2400 MHz, kernel.watchdog_thresh = 10 (soft lockup at 20 sec)
Effective frequency is measured from APERF/MPERF (driver-agnostic, updated on each scheduler tick)

 CPU   eff.MHz   max.MHz  %max  steal%  runq   sample   behind note
-------------------------------------------------------------------
   0      2394      2400  100%    0.0%     1      0.0s     0.0s pstate 24/24
   1       412      2400   17%    0.0%     3      0.0s    21.3s SUSPECT: slow while behind, pstate 4/24, THROTTLED 14/9
   2      2390      2400  100%    0.0%     0      0.0s     0.1s pstate 24/24
...
```

**Virtualization awareness.** APERF/MPERF only advances while the vCPU is actually scheduled by the hypervisor, so effective frequency *cannot* detect CPU steal (the hypervisor descheduling the vCPU) — the signature of host CPU overcommit. When the guest is virtualized, `cpuinfo --speed` says so, reports per-CPU steal time, and — because some hypervisors (notably VMware) do not export steal to the guest (`paravirt_steal_enabled=0`, steal shown as `off`) — pivots to the signals that remain visible: per-CPU run-queue depth, load average vs online CPUs, and memory ballooning (`vminfo`). A "normal" effective frequency on a virtual machine does **not** rule out host overcommit, and the tool now flags that overcommit case instead of giving a false all-clear. When APERF/MPERF was never sampled (common on VMware guests), the frequency is shown as `unmeas.` rather than a misleading `100%`.

The values are last-sample snapshots. If the stuck CPU had interrupts disabled the sample predates the lockup and is marked `sample stale (...)`; in that case the frequency is not representative and the tool says so. Frequency is usually a contributing factor rather than the sole cause, so cross-check with `lockup` and the backtrace of the stuck task.

### edis ###
Enhanced disassembly command. It provides the source code line by line if the remote server is up and running. The server code is packed in docker image, so, it can be run on any envivronment as long as the system has docker commands.

To make it work properly, the docke image should mount source repository by setting 'RHEL_SOURCE_DIR' environment variable before start the docker. 

Here is an example to start remoteapi. Please run it in a system that has the source code.

```
$ export RHEL_SOURCE_DIR="/Users/sungju/source"
$ cd remoteapi

$ ./start_docker.sh
or
$ ./run_standalone.sh
```

Once it is running, you can use this in your crash command. But, this also needs to set 'CRASHEXT_SERVER' environment variable before start 'crash'.

```
$ export CRASHEXT_SERVER=http://myexample.com:5000
$ crash
```

If everything goes well, you now can run 'edis'.

- Below is similar to 'dis -lr', but provides actual source code for each lines

```
crash> edis -r ffffffff812461ec
/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 42
      41 static int show_sb_opts(struct seq_file *m, struct super_block *sb)
      42 {
0xffffffff81246190 <show_sb_opts>:show_sb_optsdata32 data32 data32 xchg %ax,%ax [FTRACE NOP]
...
/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
      51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
0xffffffff812461da <show_sb_opts+0x4a>:0x4amovslq (%rbx),%rax
0xffffffff812461dd <show_sb_opts+0x4d>:0x4dtest   %eax,%eax
0xffffffff812461df <show_sb_opts+0x4f>:0x4fjne    0xffffffff812461c3 <show_sb_opts+0x33>
/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 56
      56 	return security_sb_show_options(m, sb);
0xffffffff812461e1 <show_sb_opts+0x51>:0x51mov    %r12,%rsi
0xffffffff812461e4 <show_sb_opts+0x54>:0x54mov    %r13,%rdi
0xffffffff812461e7 <show_sb_opts+0x57>:0x57callq  0xffffffff812b3c70 <security_sb_show_options>
/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 57
      57 }
0xffffffff812461ec <show_sb_opts+0x5c>:0x5cpop    %rbx
```

- Sometimes, it is useful to see where this instruction came from by drawing 'jump' lines
	- If there are too many jmp instructions, the screen can be a bit messy. You can reduce the number of jump instructions you are interested in by providing '-j <jmp op>'

```
crash> edis -rg ffffffff812461ec
     /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 42
           41 static int show_sb_opts(struct seq_file *m, struct super_block *sb)
           42 {
     0xffffffff81246190 <show_sb_opts>:show_sb_optsdata32 data32 data32 xchg %ax,%ax [FTRACE NOP]
     0xffffffff81246195 <show_sb_opts+0x5>:0x5push   %rbp
     /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
           51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
     0xffffffff81246196 <show_sb_opts+0x6>:0x6mov    $0x10,%eax
     /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 42
           41 static int show_sb_opts(struct seq_file *m, struct super_block *sb)
           42 {
     0xffffffff8124619b <show_sb_opts+0xb>:0xbmov    %rsp,%rbp
     0xffffffff8124619e <show_sb_opts+0xe>:0xepush   %r13
     0xffffffff812461a0 <show_sb_opts+0x10>:0x10mov    %rdi,%r13
     0xffffffff812461a3 <show_sb_opts+0x13>:0x13push   %r12
     0xffffffff812461a5 <show_sb_opts+0x15>:0x15mov    %rsi,%r12
     0xffffffff812461a8 <show_sb_opts+0x18>:0x18push   %rbx
     /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
           51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
     0xffffffff812461a9 <show_sb_opts+0x19>:0x19mov    $0xffffffff816f5fc0,%rbx
+---*0xffffffff812461b0 <show_sb_opts+0x20>:0x20jmp    0xffffffff812461c3 <show_sb_opts+0x33>
|    0xffffffff812461b2 <show_sb_opts+0x22>:0x22nopw   0x0(%rax,%rax,1)
| +=>0xffffffff812461b8 <show_sb_opts+0x28>:0x28add    $0x10,%rbx
| |  0xffffffff812461bc <show_sb_opts+0x2c>:0x2cmovslq (%rbx),%rax
| |  0xffffffff812461bf <show_sb_opts+0x2f>:0x2ftest   %eax,%eax
|+--*0xffffffff812461c1 <show_sb_opts+0x31>:0x31je     0xffffffff812461e1 <show_sb_opts+0x51>
|||  /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 52
|||        52 		if (sb->s_flags & fs_infop->flag)
|||        53 			seq_puts(m, fs_infop->str);
+==+>0xffffffff812461c3 <show_sb_opts+0x33>:0x33test   %rax,0x50(%r12)
 |+-*0xffffffff812461c8 <show_sb_opts+0x38>:0x38je     0xffffffff812461b8 <show_sb_opts+0x28>
 | | /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 53
 | |       52 		if (sb->s_flags & fs_infop->flag)
 | |       53 			seq_puts(m, fs_infop->str);
 | | 0xffffffff812461ca <show_sb_opts+0x3a>:0x3amov    0x8(%rbx),%rsi
 | | 0xffffffff812461ce <show_sb_opts+0x3e>:0x3emov    %r13,%rdi
 | | /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
 | |       51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
 | | 0xffffffff812461d1 <show_sb_opts+0x41>:0x41add    $0x10,%rbx
 | | /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 53
 | |       52 		if (sb->s_flags & fs_infop->flag)
 | |       53 			seq_puts(m, fs_infop->str);
 | | 0xffffffff812461d5 <show_sb_opts+0x45>:0x45callq  0xffffffff812289d0 <seq_puts>
 | | /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
 | |       51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
 | | 0xffffffff812461da <show_sb_opts+0x4a>:0x4amovslq (%rbx),%rax
 | | 0xffffffff812461dd <show_sb_opts+0x4d>:0x4dtest   %eax,%eax
 | +*0xffffffff812461df <show_sb_opts+0x4f>:0x4fjne    0xffffffff812461c3 <show_sb_opts+0x33>
 |   /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 56
 |         56 	return security_sb_show_options(m, sb);
 +==>0xffffffff812461e1 <show_sb_opts+0x51>:0x51mov    %r12,%rsi
     0xffffffff812461e4 <show_sb_opts+0x54>:0x54mov    %r13,%rdi
     0xffffffff812461e7 <show_sb_opts+0x57>:0x57callq  0xffffffff812b3c70 <security_sb_show_options>


crash> edis -rgj je ffffffff812461ec
   /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 42
         41 static int show_sb_opts(struct seq_file *m, struct super_block *sb)
         42 {
   0xffffffff81246190 <show_sb_opts>:show_sb_optsdata32 data32 data32 xchg %ax,%ax [FTRACE NOP]
   0xffffffff81246195 <show_sb_opts+0x5>:0x5push   %rbp
   /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
         51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
   0xffffffff81246196 <show_sb_opts+0x6>:0x6mov    $0x10,%eax
   /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 42
         41 static int show_sb_opts(struct seq_file *m, struct super_block *sb)
         42 {
   0xffffffff8124619b <show_sb_opts+0xb>:0xbmov    %rsp,%rbp
   0xffffffff8124619e <show_sb_opts+0xe>:0xepush   %r13
   0xffffffff812461a0 <show_sb_opts+0x10>:0x10mov    %rdi,%r13
   0xffffffff812461a3 <show_sb_opts+0x13>:0x13push   %r12
   0xffffffff812461a5 <show_sb_opts+0x15>:0x15mov    %rsi,%r12
   0xffffffff812461a8 <show_sb_opts+0x18>:0x18push   %rbx
   /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
         51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
   0xffffffff812461a9 <show_sb_opts+0x19>:0x19mov    $0xffffffff816f5fc0,%rbx
   0xffffffff812461b0 <show_sb_opts+0x20>:0x20jmp    0xffffffff812461c3 <show_sb_opts+0x33>
   0xffffffff812461b2 <show_sb_opts+0x22>:0x22nopw   0x0(%rax,%rax,1)
 +>0xffffffff812461b8 <show_sb_opts+0x28>:0x28add    $0x10,%rbx
 | 0xffffffff812461bc <show_sb_opts+0x2c>:0x2cmovslq (%rbx),%rax
 | 0xffffffff812461bf <show_sb_opts+0x2f>:0x2ftest   %eax,%eax
+-*0xffffffff812461c1 <show_sb_opts+0x31>:0x31je     0xffffffff812461e1 <show_sb_opts+0x51>
|| /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 52
||       52 		if (sb->s_flags & fs_infop->flag)
||       53 			seq_puts(m, fs_infop->str);
|| 0xffffffff812461c3 <show_sb_opts+0x33>:0x33test   %rax,0x50(%r12)
|+*0xffffffff812461c8 <show_sb_opts+0x38>:0x38je     0xffffffff812461b8 <show_sb_opts+0x28>
|  /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 53
|        52 		if (sb->s_flags & fs_infop->flag)
|        53 			seq_puts(m, fs_infop->str);
|  0xffffffff812461ca <show_sb_opts+0x3a>:0x3amov    0x8(%rbx),%rsi
|  0xffffffff812461ce <show_sb_opts+0x3e>:0x3emov    %r13,%rdi
|  /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
|        51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
|  0xffffffff812461d1 <show_sb_opts+0x41>:0x41add    $0x10,%rbx
|  /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 53
|        52 		if (sb->s_flags & fs_infop->flag)
|        53 			seq_puts(m, fs_infop->str);
|  0xffffffff812461d5 <show_sb_opts+0x45>:0x45callq  0xffffffff812289d0 <seq_puts>
|  /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 51
|        51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
|  0xffffffff812461da <show_sb_opts+0x4a>:0x4amovslq (%rbx),%rax
|  0xffffffff812461dd <show_sb_opts+0x4d>:0x4dtest   %eax,%eax
|  0xffffffff812461df <show_sb_opts+0x4f>:0x4fjne    0xffffffff812461c3 <show_sb_opts+0x33>
|  /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 56
|        56 	return security_sb_show_options(m, sb);
+=>0xffffffff812461e1 <show_sb_opts+0x51>:0x51mov    %r12,%rsi
   0xffffffff812461e4 <show_sb_opts+0x54>:0x54mov    %r13,%rdi
   0xffffffff812461e7 <show_sb_opts+0x57>:0x57callq  0xffffffff812b3c70 <security_sb_show_options>
   /usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 57
         57 }
   0xffffffff812461ec <show_sb_opts+0x5c>:0x5cpop    %rbx
```

- Checking full function definition or specific portion in file can be done with '-f'

```
crash> edis -f show_sb_opts
/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c: 42

      41 static int show_sb_opts(struct seq_file *m, struct super_block *sb)
      42 {
      43 	static const struct proc_fs_info fs_info[] = {
      44 		{ MS_SYNCHRONOUS, ",sync" },
      45 		{ MS_DIRSYNC, ",dirsync" },
      46 		{ MS_MANDLOCK, ",mand" },
      47 		{ 0, NULL }
      48 	};
      49 	const struct proc_fs_info *fs_infop;
      50 
      51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
      52 		if (sb->s_flags & fs_infop->flag)
      53 			seq_puts(m, fs_infop->str);
      54 	}
      55 
      56 	return security_sb_show_options(m, sb);
      57 }

```

- Or, can see a port of af a file.

```
crash> edis -f fs/proc_namespace.c: 42
/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c:  42

      41 static int show_sb_opts(struct seq_file *m, struct super_block *sb)
      42 {
      43 	static const struct proc_fs_info fs_info[] = {
      44 		{ MS_SYNCHRONOUS, ",sync" },
      45 		{ MS_DIRSYNC, ",dirsync" },
      46 		{ MS_MANDLOCK, ",mand" },
      47 		{ 0, NULL }
      48 	};
      49 	const struct proc_fs_info *fs_infop;
      50 
      51 	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
      52 		if (sb->s_flags & fs_infop->flag)
      53 			seq_puts(m, fs_infop->str);
      54 	}
      55 
      56 	return security_sb_show_options(m, sb);
      57 }


 ** Execution took   5.19s (real)   4.23s (CPU), Child processes:   0.19s
crash> edis -f fs/proc_namespace.c: 42 49
/usr/src/debug/kernel-3.10.0-693.11.6.el7/linux-3.10.0-693.11.6.el7.x86_64/fs/proc_namespace.c:  42 49
      42 {
      43 	static const struct proc_fs_info fs_info[] = {
      44 		{ MS_SYNCHRONOUS, ",sync" },
      45 		{ MS_DIRSYNC, ",dirsync" },
      46 		{ MS_MANDLOCK, ",mand" },
      47 		{ 0, NULL }
      48 	};
      49 	const struct proc_fs_info *fs_infop;


```

- Shows callgraph by '-c'. To avoid too much tracking, the max_depth by default is 2, but you can change it by specifying '-m <depth value>'.

```
crash> edis -c nfs4_proc_renew
{nfs4_proc_renew} -+- {rpc_call_sync} -+- {rpc_run_task} ...
                   |                   |- {rpc_put_task} ...
                   |                   |- {__stack_chk_fail} ...
                   |                   |- {rpc_release_calldata} ...
                   |                   `- {warn_slowpath_null} ...
                   |- {do_renew_lease} -+- {_raw_qspin_lock} ...
                   |                    `- {_raw_spin_unlock} ...
                   `- {__stack_chk_fail} -+- {panic} ...


crash> edis -c nfs4_proc_renew -m 3
{nfs4_proc_renew} -+- {rpc_call_sync} -+- {rpc_run_task} -+- {rpc_new_task} ...
                   |                   |                  |- {_raw_qspin_lock} ...
                   |                   |                  |- {__list_add} ...
                   |                   |                  |- {_raw_spin_unlock} ...
                   |                   |                  |- {rpc_execute} ...
                   |                   |                  `- {xprt_iter_get_next} ...
                   |                   |- {rpc_put_task} -+- {rpc_do_put_task} ...
                   |                   |- {__stack_chk_fail} -+- {panic} ...
                   |                   |- {rpc_release_calldata} -+- {__x86_indirect_thunk_rax} ...
                   |                   `- {warn_slowpath_null} -+- {__warn} ...
                   |- {do_renew_lease} -+- {_raw_qspin_lock} -+- {lock_acquire} ...
                   |                    |                     |- {do_raw_spin_trylock} ...
                   |                    |                     |- {lock_contended} ...
                   |                    |                     |- {do_raw_spin_lock} ...
                   |                    |                     `- {lock_acquired} ...
                   |                    `- {_raw_spin_unlock} -+- {lock_release} ...
                   |                                           `- {do_raw_spin_unlock} ...
                   `- {__stack_chk_fail} -+- {panic} -+- {trace_hardirqs_off} ...
                                                      |- {panic_smp_self_stop} ...
...
                                                      |- {bust_spinlocks} ...
                                                      |- {printk} ...
                                                      |- {touch_nmi_watchdog} ...
                                                      |- {__x86_indirect_thunk_rax} ...
                                                      |- {__const_udelay} ...
                                                      |- {emergency_restart} ...
                                                      |- {trace_hardirqs_on} ...
                                                      |- {touch_softlockup_watchdog} ...
                                                      |- {__x86_indirect_thunk_rax} ...
                                                      `- {__const_udelay} ...
```


### vminfo ###
It provides virtual-machine related information. With no option it shows the hypervisor type and memory-ballooning usage (VMware, Hyper-V, and KVM/virtio balloon are supported).

`vminfo --overcommit` infers **hypervisor CPU/memory overcommit** from a single vmcore. This is aimed at the case where a guest suddenly shows very high load or soft lockups but per-CPU frequency (`cpuinfo --speed`) looks fine—the classic signature of the host descheduling the guest's vCPUs (CPU *steal*).

The report separates direct host-controlled evidence from nonspecific guest symptoms:

- CPU steal (when the hypervisor exports it), contended vCPU scheduler clocks that lag behind their peers, and user-mode tasks that exceed the CFS scheduling interval while work is queued.
- Load/runqueue pressure plus a runnable-versus-uninterruptible task census. This avoids treating D-state I/O load as CPU overcommit.
- VMware, Hyper-V, and KVM/virtio memory balloons, with the reclaimed share of guest RAM.
- Guest swap/reclaim/compaction/OOM counters, SCSI and block-layer queues, iowait, and historical stall messages retained in the kernel log. These corroborate pressure but are not presented as proof of host overcommit because guest-local faults can produce them too.

```
crash> vminfo --overcommit
Hypervisor overcommit assessment
===============================
Guest       : VMware; 48 vCPU(s); steal accounting disabled/unavailable to guest

Assessment
----------
  CPU      LIKELY        2 contended user-mode vCPU clock(s) lagged, max 6.7s
  Memory   HOST RECLAIM  VMware balloon 11.22 GiB (23.4% of guest RAM)
  Storage  PRESSURE      18 HBA command(s), 21 block request(s), oldest 3.4s
  ------------------------------------------------------------------------
  Overall  LIKELY        single-vmcore inference; confirm with host metrics

Evidence
--------
CPU
  Load        200.03 / 48.38 / 17.34 over 48 vCPUs (4.17x); recent pile-up
  Runqueues   809 runnable; 16.9/vCPU; deepest 67; 29 hot (>= 8)
  Task states 812 runnable, 31 uninterruptible (D), 3264 total
  Steal       unavailable: paravirt_steal_enabled=0
  Clock lag   contended vCPU clocks stopped relative to peers:
                CPU      lag    runq  mode    task(pid)
                  1    6.741s    21  user    cssdagent(1234)
                 20    3.426s    17  user    cssdmonitor(5678)
```

The normal report leads with a compact per-domain assessment. Add `-d` (`vminfo --overcommit -d`) for a bounded, evidence-focused raw appendix. It shows the worst implicated CPU/task/request rows and relevant structure fields, includes nearby CPU, backtrace, structure, and kernel-log context, and marks triggering lines with `=>` plus terminal color. Each candidate-task backtrace also includes its runqueue depth, scheduler-clock on-CPU/current-execution duration, clock lag, and the raw clock fields behind those calculations. Omission counts make the filtering explicit.

The verdict remains inferential on hypervisors that hide steal, so confirm CPU findings against the host's own metrics (for example, VMware CPU-ready/co-stop). An inflated balloon is direct evidence of hypervisor-directed memory reclaim; storage queues and guest VM-pressure counters are supporting evidence only.

### timeinfo ###
It provides time related information. For now, it is providing clock source details.

```
crash> timeinfo --source --details
Current clocksource = clocksource_tsc (0xffffffff81a9a580)

clocksource_tsc (0xffffffff81a9a580)
        name : tsc
        read : read_tsc (0xffffffff81013550)
clocksource_hpet (0xffffffff81aaa280)
        name : hpet
        read : read_hpet (0xffffffff81043e30)
clocksource_acpi_pm (0xffffffff81b27b40)
        name : acpi_pm
        read : acpi_pm_read (0xffffffff81450eb0)
clocksource_jiffies (0xffffffff81ab8e80)
        name : jiffies
        read : jiffies_read (0xffffffff810b7160)
```


### meminfo ###
It provides memory related information.

```
crash> meminfo -h
Usage: meminfo.py [options]

Options:
  -h, --help            show this help message and exit
  -a, --all             Show all the output
  -b, --budyinfo        Show /proc/buddyinfo like output
  -c, --compact         Show compact data for other options
  -d, --details         Show detailed output
  --debug               Show debug output
  -e ERROR_CODE, --error=ERROR_CODE
                        Interpret page_fault error code
  -f TLB_LIST, --tlb=TLB_LIST
                        Shows tlb list (csd). example) meminfo -f
                        0xffffade6b68037e0 -d
  -F PTE_FLAGS, --pte_flags=PTE_FLAGS
                        Shows the meaning of pte flags
  -G GFP_MASK, --gfp_mask=GFP_MASK
                        Interpret gfp_mask value
  -g, --graph           Show bar chart for memory usage visualization
  -i, --meminfo         Show /proc/meminfo-like output
  -l, --longer          Show more data than normal
  -m, --numa            Show NUMA info
  --maxcount=MAXCOUNT   Check only maxcount
  --memory_limit=MEMORY_LIMIT
                        Limit call trace storage to reduce memory usage
                        (default: 0, no limit)
  -n, --nogroup         Show data in individual tasks
  -o, --page_owner      Show page_owner details
  -O, --OOM             Analyse OOM messages in log
  --overall             Show overall memory usage breakdown with bar graphs
  --oom-summary         Show OOM summary dashboard with pattern analysis
  --process-filter=PROCESS_FILTER
                        Filter OOM events by process name (comma-separated or
                        regex)
  --oom-count=OOM_COUNT
                        Limit number of OOM events to display
  --oom-top=OOM_TOP     Show top N memory consumers (default: 10)
  -P, --pss             Show memory usages(pss) by tasks
  -p PERCPU, --percpu=PERCPU
                        Convert percpu address into virtual address
  --pager=PAGER         Show progress per specified term. default=2000
  --progress            Show progress results while handling operation
  --reverse             Show results in reverse order
  -s, --slabtop         Show slabtop-like output
  -S SLABDETAIL, --slabdetail=SLABDETAIL
                        Show details of a slab
  --shared              Account for shared memory in OOM analysis to prevent
                        double-counting
  --corrupt=CORRUPT     Check SLAB corruption. Format:
                        <kmem_cache_addr|slab_name>[:<cpu_num>]
  -t PERCPU_TYPE, --type=PERCPU_TYPE
                        Specify percpu type : u8, u16, u32, u64, s8, s16, s32,
                        s64, int
  -u, --memusage        Show memory usages by tasks
  -U USER_ALLOC, --user_alloc=USER_ALLOC
                        Show slub_debug=U usage
  -v, --vm              Show 'vm' output with more details
  -w, --swap            Show swap usage
  -W, --swap_full       Show swap usage in detail

crash> meminfo --memusage
======================================================================
 [ RSS usage ]   [ Process name ]
======================================================================
    226892 KiB   ocssd.bin
    182112 KiB   ologgerd
    121296 KiB   cssdagent
    120680 KiB   cssdmonitor
    120244 KiB   osysmond.bin
     69064 KiB   java
     49944 KiB   oraagent.bin
     39016 KiB   orarootagent.bi
     36984 KiB   tnslsnr
     27956 KiB   crsd.bin
======================================================================
Total memory usage from user-space = 8.74 GiB

crash> meminfo --slabtop
====================================================================
kmem_cache         NAME                                TOTAL OBJSIZE
====================================================================
0xffff88102f8e0d80 vm_area_struct                     37264K     200
0xffff8810299f1000 filp                               25648K     256
0xffff88102f960f80 dentry                             15348K     192
0xffff88102f920e80 radix_tree_node                    13616K     560
0xffff88103fcf03c0 size-2048                          11616K    2048
0xffff88103fc40100 size-64                             6984K      64
0xffff881029a61140 proc_inode_cache                    6672K     656
0xffff8810292a1480 sock_inode_cache                    6144K     704
0xffff88102f870bc0 task_struct                         5824K    2672
0xffff88102f850b40 anon_vma_chain                      5652K      48
====================================================================

crash> meminfo -U anon_vma
    <struct kmem_cache 0xffff8da6bfc0a200>
      SLAB Layout
     +--------+--------+
     |OBJ Size|track at|
     +--------+--------+
     |      72|      80|
     +--------+--------+

     COUNT   FUNCTION
      3355 : ffffffff82400d45 (t) anon_vma_alloc+0x15
       849 : ffffffff82403309 (T) anon_vma_fork+0x69

Total allocated slab count = 4202


crash> meminfo --meminfo
MemTotal:             32394624.0 kB
MemFree:               2166016.0 kB
MemAvailable:         30228608.0 kB
Buffers:                     0.0 kB
Cached:                 700928.0 kB
SwapCached:                    0 kB
Active:                    52197 kB
...
VmallocChunk:      8795764752384 kB
HardwareCorrupted:             0 kB
HugePages_Total:               0
HugePages_Free:                0
HugePages_Rsvd:                0
HugePages_Surp:                0
Hugepagesize:              16384 kB


crash> meminfo --numa
available: 2 nodes (0-1)
node 0 cpus:  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53
node 0 : 0x0000000000000000 - 0x0000004040000000
node 0 size : 263168 MB
node 1 cpus:  18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71
node 1 : 0x0000004040000000 - 0x000000803ffff000
node 1 size : 262143 MB
node distances:
  node    0    1
    0:   10   21
    1:   21   10


crash> meminfo -b -d
Node 0, zone      DMA      0      0      0      0      0      0      0      0      1      1      3
Node 0, zone    DMA32      8      7      6      5      5      5      7      7      6      6    619
Node 0, zone   Normal    221    746    717    496    309    245    145     80     84     48   4974
Node 0, zone  Movable      0      0      0      0      0      0      0      0      0      0      0
Node 0, zone   Device      0      0      0      0      0      0      0      0      0      0      0
Node 1, zone      DMA      0      0      0      0      0      0      0      0      0      0      0
Node 1, zone    DMA32      0      0      0      0      0      0      0      0      0      0      0
Node 1, zone   Normal    922    657    389    198    375    276    328    285    174     92   5718
Node 1, zone  Movable      0      0      0      0      0      0      0      0      0      0      0
Node 1, zone   Device      0      0      0      0      0      0      0      0      0      0      0

# Order                  2^0    2^1    2^2    2^3    2^4    2^5    2^6    2^7    2^8    2^9   2^10
# Size (KB)                4      8     16     32     64    128    256    512   1024   2048   4096


crash> meminfo -O
[236198.066904] java invoked oom-killer: gfp_mask=0x6200ca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0
==========================================================
NAME                                                 Usage
==========================================================
java                                             121.1 GiB
ds_am                                            326.5 MiB
wdavdaemon                                       266.9 MiB
bash                                             223.1 MiB
ds_agent                                         207.6 MiB
su                                               136.1 MiB
	<...>
==========================================================
Total memory usage from processes = 124.2 GiB
[236204.876687] Out of memory: Killed process 281864 (java) total-vm:37363292kB, anon-rss:13863416kB, file-rss:0kB, shmem-rss:48kB, UID:23312672 pgtables:27796kB oom_score_adj:0

[245177.286137] ds_agent invoked oom-killer: gfp_mask=0x6200ca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0
==========================================================
NAME                                                 Usage
==========================================================
java                                             120.9 GiB
ds_am                                            326.8 MiB
wdavdaemon                                       266.4 MiB
ds_agent                                         214.7 MiB
bash                                             129.7 MiB
sshd                                              81.3 MiB
su                                                68.5 MiB
	<...>
==========================================================
Total memory usage from processes = 123.5 GiB
[245184.406619] Out of memory: Killed process 574755 (java) total-vm:37363292kB, anon-rss:9893024kB, file-rss:460kB, shmem-rss:48kB, UID:23312672 pgtables:20032kB oom_score_adj:0
```

### revs ###
It provides some basic information you may need to understand disassembled instructions. The idea is to provide as many instrution details as possible, but it may takes long time to complete yet.

```
crash> revs -h
Usage: revs.py [options]

Options:
  -h, --help         show this help message and exit
  -r, --regs         Registers used for argument passing
  -a ASM, --asm=ASM  Simple manual for GNU assembly
  -l, --list         Shows the list of instructions you can check details

crash> revs
** function parameters for x86_64 **
%rdi - 1st argument (%rdi:64, %edi:32, %di:16, %dl:8)
%rsi - 2nd argument (%rsi:64, %esi:32, %si:16, %sl:8)
%rdx - 3rd argument (%rdx:64, %edx:32, %dx:16, %dl:8)
%rcx - 4th argument (%rcx:64, %ecx:32, %cx:16, %cl:8)
%r8 - 5th argument (%r8:64, %r8d:32, %r8w:16, %r8b:8)
%r9 - 6th argument (%r9:64, %r9d:32, %r9w:16, %r9b:8)
%rsp - Stack pointer
%rax - Return value

crash> revs --asm=lea
lea - Load effective address
     The lea instruction places the address specified by its
     first operandinto the register specified by its second
     operand.Note, the contents of the memory location are
     notloaded, only the effective address is computed and
     placed into the register.This is useful for obtaining
     a pointer into a memory region or to perform simple
     arithmetic operations.

     Syntax
     lea <mem>, <reg32>

     Examples
     lea (%ebx,%esi,8), %edi - the quantity EBX+8*ESI is placed in EDI.
     lea val(,1), %eax - the value val is placed in EAX.

```


### psinfo ###

Provides 'ps'-like output.

```
crash> psinfo -h
Usage: psinfo.py [options]

Options:
  -h, --help            show this help message and exit
  --aux                 ps aux
  --auxcww              ps auxcww
  --auxww               ps auxww
  --ef                  ps -ef
  -p POLICY_TYPE, --policy=POLICY_TYPE
                        Shows specific policy type of processes only.
                        0 : NORMAL, 1 : FIFO, 2 : RR, 3 : BATCH,
                        5 : IDLE, 6 : DEADLINE
  -s, --searchstack     Search each task stack to find value specified in
                        include with 'bt -f'
  -S, --Searchstack     Search each task stack to find value specified in
                        include with 'bt -F'
  -n, --nodetails       Shows no stack contents
  -i INCLUDE, --include=INCLUDE
                        comma separated value list to search with
                        --searchstack
  -e EXCLUDE, --exclude=EXCLUDE
                        comma separated value list to ignore in
                        --searchstack
  -k TASK_NAME, --taskname=TASK_NAME
                        limit search range only to tasks with matching task
                        name
  -t TASKADDR, --task=TASKADDR
                        Shows general information about a task

crash> psinfo --aux | head
USER              PID %CPU %MEM      VSZ      RSS TTY      STAT       START     TIME COMMAND
root                0  n/a  0.0        0        0 ?        R          May26  116,05:21:33 [swapper]
root                0  n/a  0.0        0        0 ?        R          May26  116,05:21:33 [swapper]
root                1  n/a  0.0    33644     1096 ?        S          May26  116,05:21:33 init
root                2  n/a  0.0        0        0 ?        S          May26  116,05:21:33 [kthreadd]
root                3  n/a  0.0        0        0 ?        S          May26  116,05:21:33 [migration/0]
root                4  n/a  0.0        0        0 ?        S          May26  116,05:21:33 [ksoftirqd/0]
root                5  n/a  0.0        0        0 ?        S          May26  116,05:21:33 [stopper/0]
root                6  n/a  0.0        0        0 ?        S          May26  116,05:21:33 [watchdog/0]
root                7  n/a  0.0        0        0 ?        S          May26  116,05:21:33 [migration/1]
crash> psinfo --ef | head
UID               PID     PPID  C    STIME      TTY     TIME CMD
root                0        0  0    May26        ?  116,05:21:33 [swapper]
root                0        0  0    May26        ?  116,05:21:33 [swapper]
root                1        0  0    May26        ?  116,05:21:33 init
root                2        0  0    May26        ?  116,05:21:33 [kthreadd]
root                3        2  0    May26        ?  116,05:21:33 [migration/0]
root                4        2  0    May26        ?  116,05:21:33 [ksoftirqd/0]
root                5        2  0    May26        ?  116,05:21:33 [stopper/0]
root                6        2  0    May26        ?  116,05:21:33 [watchdog/0]
root                7        2  0    May26        ?  116,05:21:33 [migration/1]
```

### git ###

It runs `git log` / `git show` on the kernel source repositories hosted by the 'remoteapi' server. This is useful to find which commit introduced or changed a symbol without leaving 'crash'. It needs 'CRASHEXT_SERVER' to be set (see the 'edis' section and README.md under ./remoteapi).

```
crash> git -h
Usage:
  git <log|show> [git-options]

Subcommands:
  log              Search git log (supports all git log options, default: --max-count=1)
  show             Show commit details (supports all git show options)

Options:
  --repos=<repos>  Comma-separated list of repos (e.g., rhel9,linux,upstream)
  --timeout=<n>    Request timeout in seconds (default: 3600)
  --verbose        Show verbose output
  -h, --help       Show help
```

Examples)

```
crash> git log -Sclip_push --max-count=5
crash> git show abc123def --stat
crash> git log -Sinit_new_ldt --repos=rhel9,upstream
```

### ai ###

It sends the output of a crash command (or a file) to an AI engine running behind the 'remoteapi' server and prints the analysis in markdown. It needs 'CRASHEXT_SERVER' to be set; the engine/model can be selected per invocation or via the 'AI_ENGINE'/'AI_MODEL' environment variables.

```
crash> ai -h
Options:
  -h, --help            show this help message and exit
  -c CMD_STR, --cmd=CMD_STR
                        The output of this command will be analysed
  -e AI_ENGINE, --engine=AI_ENGINE
                        Choose AI engine to use (ollama, podman)
  -i INPUT_FILE, --input=INPUT_FILE
                        Use file for input data
  -m AI_MODEL, --model=AI_MODEL
                        Choose AI model to use
  -r, --reset           Reset AI prompt history
  -t TASKID, --taskid=TASKID
                        vmcore taskid
```

Examples)

```
crash> ai -c "bt"
crash> ai -c "log" -m llama3.2
```
