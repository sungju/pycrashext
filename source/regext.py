"""
 Written by Daniel Sungju Kwon
"""

from crash import register_epython_prog as rprog

from pykdump.API import *

import os
import sys

try:
    if "PYTHON_LIB" in os.environ:
        additional_lib = os.environ["PYTHON_LIB"]
        python_path_list = additional_lib.split(':')
        for python_path in python_path_list:
            python_lib = python_path
            if python_lib not in sys.path:
                sys.path.insert(0, python_lib)
except Exception as e:
    print('Error: ' + str(e))


help = '''
Show device related information
'''

rprog("devinfo", "Device information",
      "-h   - list available options",
      help)


help = '''
vmware information
'''

rprog("vminfo", "virtual machine information ",
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

rprog("schedinfo", "scheduling information",
      "-h    - list available options",
      help)


help = '''
Print process list in tree format.

-p          - Print process ID
-g          - Print number of threads
-s          - Print task state
-t          - Print a specific task and its children
'''


rprog("epstree", "Print process list in tree format",
      "-h   - list available options",
      help)


help = '''
Module related information.

--disasm <module name>    - Disassemble functions in a module
--details <module name>   - Show details
'''

rprog("emodinfo", "Module related information",
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
CPU related information.
'''

rprog("cpuinfo", "CPU information",
      "-h       - list available options",
      help)

help = '''
networking related information.
'''

rprog("netinfo", "Network information",
      "-h       - list available options",
      help)



help = '''
memory related information
'''

rprog("meminfo", "Memory information",
      "-h       - list available options",
      help)



help = '''
time related information
'''

rprog("timeinfo", "Time information",
      "-h       - list available options",
      help)

help = '''
enhanced disasm command related information
'''

#if 'CRASHEXT_SERVER' in os.environ and \
#   len(os.environ['CRASHEXT_SERVER'].strip()) > 0:
rprog("edis", "Enhanced disasm",
      "-h       - list available options",
      help)


help = '''
system call table checking
'''

rprog("syscallinfo", "System call table checking",
      "-h       - list available options",
      help)


help = '''
Diagnose some known issues automatically
'''

rprog("autocheck", "Diagnose some known issues",
      "-h       - list available options",
      help)

help = '''
Checking the data through insights
'''

rprog("insights", "Run insights with the currently available data",
      "-h       - list available options",
      help)


help = '''
Show process information
'''

rprog("psinfo", " ps output",
      "-h    - list available options",
      help)


help = '''
Show selinux related information
'''

rprog("seinfo", "SELinux output",
      "-h    - list available options",
      help)


help = '''
Shows UN(D) state processes with details
'''

rprog("hangcheck", "hang task(s) heck",
      "-h   - list available options",
      help)


help = '''
Shows audit information
'''

rprog("auditinfo", "audit information",
      "-h   - list available options",
      help)

help = '''
Shows tracing information
'''

rprog("traceinfo", "trace information",
      "-h   - list available options",
      help)

# added by amdas
help='''
SELinux status
'''

rprog("selinuxinfo",
        "show selinux status",
        "-h     list available options",
        help)

help='''
Screen handling
'''

rprog("screen",
        "handle screen",
        "-h     list available options",
        help)


help='''
RPC information 
'''

rprog("rpcinfo",
        "rpc information",
        "-h     list available options",
        help)



import crashcolor

crashcolor.set_color(crashcolor.BLUE)
#print("\n\tWritten by Daniel Kwon (dkwon@redhat.com)")
crashcolor.set_color(crashcolor.RESET)
