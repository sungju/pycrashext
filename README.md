# pycrashext
Crash extensions for Pykdump. This requires pykdump loaded before use. You can find pykdump binary at [https://sourceforge.net/projects/pykdump/](https://sourceforge.net/projects/pykdump/).

![Example screen of "edis -lrg"](https://github.com/sungju/pycrashext/blob/master/docs/edis_example.png)

### How to install

```
$ git clone https://github.com/sungju/pycrashext
$ cd pycrashext
$ sh ./install.sh
$ logout
< login again >
```

## Commands ##

### insights ###

- Insights is a rule based engine to detect known issues. [https://github.com/RedHatInsights/insights-core](https://github.com/RedHatInsights/insights-core)
- In this exteion, it is cowork with 'remoteapi' server located under ./remoteapi/ directory. For details, how to use 'remoteapi', please check README.md under ./remoteapi directory

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
  -g          Print number of threads
  -s          Print task state
  -t TASK_ID  Print specific task and its children
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


### cgroupinfo ###
It provides cgroup related information. It is mostly useful to find out how many cgroups were created in the system.

```
crash> cgroupinfo --tree
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


crash> cgroupinfo --tglist
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


### vmw_mem ###
It displays VMware ballooning usage. It is useful to check out unacounted memory in VMware virtual guest.

```
crash> vmw_mem
  size = 0x2e1c39
  target = 0x606770
  stats = {
    timer = 0x2138df, 
    alloc = 0x2e130b, 
    alloc_fail = 0x7, 
    sleep_alloc = 0xa59, 
    sleep_alloc_fail = 0x0, 
    refused_alloc = 0x123, 
    refused_free = 0x123, 
    free = 0x0, 
    lock = 0x2e1d5c, 
    lock_fail = 0x123, 
    unlock = 0x0, 
    unlock_fail = 0x0, 
    target = 0x2138df, 
    target_fail = 0x14, 
    start = 0x15, 
    start_fail = 0x0, 
    guest_type = 0x15, 
    guest_type_fail = 0x0
  }

allocated size (pages)     = 3021881
allocated size (bytes)     = 12377624576, (11.53GB)
required target (pages)    = 6317936
required target (bytes)    = 25878265856, (24.10GB)

rate_alloc                 = 2048

```


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
  -h, --help  show this help message and exit
  --memusage  Show memory usages by tasks
  --nogroup   Show data in individual tasks
  --all       Show all the output
  --slabtop   Show slabtop-like output
  --meminfo   Show /proc/meminfo-like output

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
```

### revs ###
It provides some basic information you may need to understand disassembled instructions. The idea is to provide as many instrution details as possible, but it may takes long time to complete yet.

```
crash> revs -h
Usage: revs.py [options]

Options:
  -h, --help  show this help message and exit
  --regs      Registers used for argument passing
  --asm=ASM   Simple manual for GNU assembly
  --list      Shows the list of instructions you can check details

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
  -h, --help  show this help message and exit
  --aux       ps aux
  --auxcww    ps auxcww
  --auxww     ps auxww
  --ef        ps -ef

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
