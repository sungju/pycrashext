"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys
import crashcolor


def bytes_to_str(num_bytes):
    num_str = ""
    if num_bytes > (1024*1024*1024):
        num_str = "%d GB" % (num_bytes / 1024/1024/1024)
    elif num_bytes > (1024*1024):
        num_str = "%d MB" % (num_bytes / 1024/1024)
    elif num_bytes > 1024:
        num_str = "%d KB" % (num_bytes / 1024)
    else:
        num_str = "%d Bytes" % (num_bytes)

    return num_str


def getKey(shmObj):
    shm_bytes = shmObj["bytes"]
    return shm_bytes


def show_shared_memory(options):
    try:
        result_lines = exec_crash_command("ipcs -m").splitlines()
        print(result_lines[0])
        if len(result_lines) == 1:
            return

        shm_list = []
        for shm_line in result_lines[1:]:
            words = shm_line.split()
            if len(words) < 6:
                continue
            shm_data = {"bytes" : int(words[5]), "data": words, "raw": shm_line}
            shm_list.append(shm_data)

        shm_list_sorted = sorted(shm_list, key=getKey, reverse=False)

        total_bytes = 0
        for shm_data in shm_list_sorted:
            alloc_bytes = shm_data["bytes"]
            total_bytes = total_bytes + alloc_bytes
            alloc_str = ""
            if alloc_bytes > (1024*1024*1024): #GB
                crashcolor.set_color(crashcolor.LIGHTRED)
            elif alloc_bytes > (1024*1024): # MB
                crashcolor.set_color(crashcolor.LIGHTGREEN)
            else:
                crashcolor.set_color(crashcolor.RESET)

            alloc_str = bytes_to_str(alloc_bytes)

            print(shm_data["raw"])
            if options.show_details:
                shmid_kernel = readSU("struct shmid_kernel",
                                      int(shm_data["data"][0], 16))
                creator = 0
                creator_comm = ""
                if member_offset("struct shmid_kernel", "shm_creator") >= 0:
                    if (shmid_kernel.shm_creator != 0):
                        creator = shmid_kernel.shm_creator
                        creator_comm = creator.comm

                print("\tcreator = 0x%x (%s) : %s" %
                      (creator, creator_comm, alloc_str))

        crashcolor.set_color(crashcolor.BLUE)
        print("\n\tTotal allocation = %s" % (bytes_to_str(total_bytes)))
    except Exception as e:
        print(e)
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


    # when no selection is given
    show_shared_memory(o)



if ( __name__ == '__main__'):
    ipcinfo()
