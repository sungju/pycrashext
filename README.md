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


