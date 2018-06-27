# pycrashext
Crash extensions for Pykdump. This requires pykdump loaded before use. You can find pykdump binary at [https://sourceforge.net/projects/pykdump/](https://sourceforge.net/projects/pykdump/).


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

### edis ###
Enhanced disassembly command. It provides the source code line by line if the remote server is up and running. The server code is packed in docker image, so, it can be run on any envivronment as long as the system has docker commands.

To make it work properly, the docke image should mount source repository by setting 'RHEL_SOURCE_DIR' environment variable before start the docker. 

Here is an example to start remoteapi. Please run it in a system that has the source code.

```
$ export RHEL_SOURCE_DIR="/Users/sungju/source"
$ cd remoteapi
$ ./start_docker.sh
```

Once it is running, you can use this in your crash command. But, this also needs to set 'CRASHEXT_SERVER' environment variable before start 'crash'.

```
$ export CRASHEXT_SERVER=http://myexample.com:5000
$ crash
```

If everything goes well, you now can run 'edis'.

```
crash> edis -rg ffffffff81363bf7
/usr/src/debug/kernel-2.6.32-696.28.1.el6/linux-2.6.32-696.28.1.el6.x86_64/drivers/char/sysrq.c: 495
                 494 void __handle_sysrq(int key, struct tty_struct *tty, int check_mask)
                 495 {
            0xffffffff81363ac0 <__handle_sysrq>:        push   %rbp
            0xffffffff81363ac1 <__handle_sysrq+0x1>:    mov    %rsp,%rbp
            0xffffffff81363ac4 <__handle_sysrq+0x4>:    sub    $0x40,%rsp
            0xffffffff81363ac8 <__handle_sysrq+0x8>:    mov    %rbx,-0x28(%rbp)
            0xffffffff81363acc <__handle_sysrq+0xc>:    mov    %r12,-0x20(%rbp)
            0xffffffff81363ad0 <__handle_sysrq+0x10>:   mov    %r13,-0x18(%rbp)
            0xffffffff81363ad4 <__handle_sysrq+0x14>:   mov    %r14,-0x10(%rbp)
            0xffffffff81363ad8 <__handle_sysrq+0x18>:   mov    %r15,-0x8(%rbp)
            0xffffffff81363adc <__handle_sysrq+0x1c>:   nopl   0x0(%rax,%rax,1)
            0xffffffff81363ae1 <__handle_sysrq+0x21>:   mov    %edi,%ebx
            /usr/src/debug/kernel-2.6.32-696.28.1.el6/linux-2.6.32-696.28.1.el6.x86_64/drivers/char/sysrq.c: 501
                 501    spin_lock_irqsave(&sysrq_key_table_lock, flags);
            0xffffffff81363ae3 <__handle_sysrq+0x23>:   mov    $0xffffffff8200cf94,%rdi
            0xffffffff81363aea <__handle_sysrq+0x2a>:   mov    %edx,-0x38(%rbp)

...
+----------*0xffffffff81363b20 <__handle_sysrq+0x60>:   jbe    0xffffffff81363bab <__handle_sysrq+0xeb>
|           /usr/src/debug/kernel-2.6.32-696.28.1.el6/linux-2.6.32-696.28.1.el6.x86_64/drivers/char/sysrq.c: 461
|                461    else if ((key >= 'a') && (key <= 'z'))
|                462            retval = key + 10 - 'a';
|           0xffffffff81363b26 <__handle_sysrq+0x66>:   lea    -0x61(%rbx),%eax
|           0xffffffff81363b29 <__handle_sysrq+0x69>:   cmp    $0x19,%eax
|+---------*0xffffffff81363b2c <__handle_sysrq+0x6c>:   jbe    0xffffffff81363ba8 <__handle_sysrq+0xe8>
||          /usr/src/debug/kernel-2.6.32-696.28.1.el6/linux-2.6.32-696.28.1.el6.x86_64/drivers/char/sysrq.c: 526
||               526            printk("HELP : ");
||      +==>0xffffffff81363b2e <__handle_sysrq+0x6e>:   mov    $0xffffffff817fcf79,%rdi
||      |   0xffffffff81363b35 <__handle_sysrq+0x75>:   xor    %eax,%eax
||      |   0xffffffff81363b37 <__handle_sysrq+0x77>:   mov    $0xffffffff81b15500,%r12
||      |   0xffffffff81363b3e <__handle_sysrq+0x7e>:   xor    %ebx,%ebx
||      |   0xffffffff81363b40 <__handle_sysrq+0x80>:   callq  0xffffffff8155296f <printk>
||      |   0xffffffff81363b45 <__handle_sysrq+0x85>:   nopl   (%rax)
||      |   /usr/src/debug/kernel-2.6.32-696.28.1.el6/linux-2.6.32-696.28.1.el6.x86_64/drivers/char/sysrq.c: 529
||      |        529                    if (sysrq_key_table[i]) {
||    +====>0xffffffff81363b48 <__handle_sysrq+0x88>:   mov    (%r12),%rsi
||    | |   0xffffffff81363b4c <__handle_sysrq+0x8c>:   test   %rsi,%rsi
||+--------*0xffffffff81363b4f <__handle_sysrq+0x8f>:   je     0xffffffff81363b7f <__handle_sysrq+0xbf>
|||   | |   /usr/src/debug/kernel-2.6.32-696.28.1.el6/linux-2.6.32-696.28.1.el6.x86_64/drivers/char/sysrq.c: 532
|||   | |        532                            for (j = 0; sysrq_key_table[i] !=
|||   | |        533                                            sysrq_key_table[j]; j++)
|||   | |        534                                    ;
|||   | |   0xffffffff81363b51 <__handle_sysrq+0x91>:   xor    %edx,%edx
|||   | |   0xffffffff81363b53 <__handle_sysrq+0x93>:   cmp    0x7b19a6(%rip),%rsi        # 0xffffffff81b15500 <sysrq_key_table>
|||   | |   0xffffffff81363b5a <__handle_sysrq+0x9a>:   mov    $0xffffffff81b15508,%rax
|||+-------*0xffffffff81363b61 <__handle_sysrq+0xa1>:   je     0xffffffff81363b77 <__handle_sysrq+0xb7>
||||  | |   0xffffffff81363b63 <__handle_sysrq+0xa3>:   nopl   0x0(%rax,%rax,1)
||||  | |   /usr/src/debug/kernel-2.6.32-696.28.1.el6/linux-2.6.32-696.28.1.el6.


crash> edis -f include/linux/list.h:697:700
/usr/src/debug/kernel-2.6.32-431.el6/linux-2.6.32-431.el6.x86_64/include/linux/list.h: 697 700

     697 	for (pos = (pos)->next;						 \
     698 	     pos &&							 \
     699 		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
     700 	     pos = pos->next)

crash> edis -f __list_add
/usr/src/debug/kernel-2.6.32-431.el6/linux-2.6.32-431.el6.x86_64/lib/list_debug.c: 22

      12 /*
      13  * Insert a new entry between two known consecutive entries.
      14  *
      15  * This is only for internal list manipulation where we know
      16  * the prev/next entries already!
      17  */
      18 
      19 void __list_add(struct list_head *new,
      20 			      struct list_head *prev,
      21 			      struct list_head *next)
      22 {
      23 	WARN(next->prev != prev,
      24 		"list_add corruption. next->prev should be "
      25 		"prev (%p), but was %p. (next=%p).\n",
      26 		prev, next->prev, next);
      27 	WARN(prev->next != next,
      28 		"list_add corruption. prev->next should be "
      29 		"next (%p), but was %p. (prev=%p).\n",
      30 		next, prev->next, prev);
      31 	next->prev = new;
      32 	new->next = next;
      33 	new->prev = prev;
      34 	prev->next = new;
      35 }

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
```
