# pycrashext
Crash extensions for Pykdump


### How to install

```
$ git clone https://github.com/sungju/pycrashext
$ cd pycrashext
$ sh ./install.sh
$ logout
< login again >
```

## Commands ##

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
