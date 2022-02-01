"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys
import crashcolor

def show_shared_memory(options):
    try:
        result_lines = exec_crash_command("ipcs -m").splitlines()
        print(result_lines[0])
        if len(result_lines) == 1:
            return
        for shm_line in result_lines[1:]:
            words = shm_line.split()
            alloc_bytes = int(words[5])
            alloc_str = ""
            if alloc_bytes > (1024*1024*1024): #GB
                crashcolor.set_color(crashcolor.LIGHTRED)
                alloc_str = "%d GB" % (alloc_bytes / 1024/1024/1024)
            elif alloc_bytes > (1024*1024): # MB
                crashcolor.set_color(crashcolor.LIGHTGREEN)
                alloc_str = "%d MB" % (alloc_bytes / 1024/1024)
            else:
                crashcolor.set_color(crashcolor.RESET)
                alloc_str = "%d Bytes" % (alloc_bytes)

            print(shm_line)
            if options.show_details:
                shmid_kernel = readSU("struct shmid_kernel", int(words[0], 16))
                if (shmid_kernel.shm_creator != 0):
                    creator = shmid_kernel.shm_creator
                    print("\tcreator = 0x%x (%s) : %s" %
                          (creator, creator.comm, alloc_str))

    except:
        pass

    crashcolor.set_color(crashcolor.RESET)


def ipcinfo():
    op = OptionParser()
    op.add_option("-m", "--memory", dest="show_shared_memory", default=0,
                  action="store_true",
                  help="Show Shared Memory information")
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()

    if o.show_shared_memory:
        show_shared_memory(o)
        sys.exit(0)



if ( __name__ == '__main__'):
    ipcinfo()
