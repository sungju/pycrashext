"""
 Written by Daniel Sungju Kwon
"""

from crash import register_epython_prog as rprog

from pykdump.API import *


"""

help = '''
Dump character device list example code
'''

rprog("dump_chrdevs", "Char device list",
      "-h   - list available options",
      help)


help = '''
Dump block device list example code
'''

rprog("dump_blkdevs", "Block device list",
      "-h   - list available options",
      help)

"""



help = '''
vmware's ballooning value check
'''

rprog("vmw_mem", "vmware ballooning information ",
      "-h   - list available options",
      help)


help = '''
CPU lock check

-r       - Show longest holder at top
--tasks  - Show tasks in each runqueue
'''

rprog("lockup", "LOCKUP check",
      "-h   - list available options",
      help)


help = '''
Helper function for reverse engineering

--regs  - register details
--asm <instruction> - details about an instruction
'''

rprog("revs", "Reverse engineering helper",
      "-h    - list available options",
      help)


help = '''
cgroup information

--tglist    - task group list with details
--tree      - hierarchial display of cgroups
'''

rprog("cgroupinfo", "cgroup information",
      "-h    - list available options",
      help)


help = '''
scheduling information

--classes    - Show scheduling classes
--details    - Show details
'''

rprog("sched", "scheduling information",
      "-h    - list available options",
      help)


help = '''
Print process list in tree format.

-p          - Print process ID
-g          - Print number of threads
-s          - Print task state
-t          - Print a specific task and its children
'''


rprog("pstree", "Print process list in tree format",
      "-h   - list available options",
      help)


help = '''
Module related information.

--disasm <module name>    - Disassemble functions in a module
--details <module name>   - Show details
'''

rprog("modinfo", "Module related information",
      "-h       - list available options",
      help)


help = '''
ipmi related information.

--smi_list      - Show smi_info list
--details       - Show additional information
'''

try:
    pa = readSymbol("smi_infos")
    if (pa != 0):
        rprog("ipmi", "ipmi related information",
              "-h       - list available options",
              help)
except:
    pass

help = '''
command list test.

--cmd <command> - The command set to run
--list          - Show the command set list
'''

rprog("cmds_test", "command list test",
      "-h       - list available options",
      help)


help = '''
Showing softirq and tasklet details.
'''

rprog("bh", "Bottom Half information",
      "-h       - list available options",
      help)


help = '''
filesystem related information.
'''

rprog("fsinfo", "Filesystem information",
      "-h       - list available options",
      help)

help = '''
networking related information.
'''

rprog("netinfo", "Network information",
      "-h       - list available options",
      help)
