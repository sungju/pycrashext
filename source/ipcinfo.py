"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys
import crashcolor


page_size = 4096


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
    width = 0
    try:
        result_lines = exec_crash_command("ipcs -m").splitlines()
        print(result_lines[0])
        if len(result_lines) == 1:
            return

        width = len(result_lines[0])
        shm_list = []
        for shm_line in result_lines[1:]:
            words = shm_line.split()
            if len(words) < 6:
                continue
            shm_data = {"bytes" : int(words[5]), "data": words, "raw": shm_line}
            shm_list.append(shm_data)

        shm_list_sorted = sorted(shm_list, key=getKey, reverse=False)

        total_bytes = 0
        total_alloc_bytes = 0
        total_rss_bytes = 0
        total_swap_bytes = 0
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

            print("%-*s  %s" % (width, shm_data["raw"], alloc_str))
            if options.show_details:
                shmid_kernel = readSU("struct shmid_kernel",
                                      int(shm_data["data"][0], 16))
                creator = 0
                creator_comm = ""
                if member_offset("struct shmid_kernel", "shm_creator") >= 0:
                    if (shmid_kernel.shm_creator != 0):
                        creator = shmid_kernel.shm_creator
                        creator_comm = creator.comm

                print("\tcreator = 0x%x (%s), shm_file = 0x%x" %
                      (creator, creator_comm, shmid_kernel.shm_file))

                detail_lines = exec_crash_command("ipcs -M 0x%x" %\
                                                 (shmid_kernel)).splitlines()
                if len(detail_lines) < 3:
                    continue

                words = detail_lines[2].split()
                if len(words) < 3:
                    continue
                pages = words[2].split('/')
                alloc_bytes = int(pages[0]) * page_size
                rss_bytes = int(pages[1]) * page_size
                swap_bytes = int(pages[2]) * page_size

                total_alloc_bytes = total_alloc_bytes + alloc_bytes
                total_rss_bytes = total_rss_bytes + rss_bytes
                total_swap_bytes = total_swap_bytes + swap_bytes

                print("\tALLOCATED = %s, RSS = %s, SWAP = %s" % \
                     (bytes_to_str(alloc_bytes),
                      bytes_to_str(rss_bytes),
                      bytes_to_str(swap_bytes)))


        crashcolor.set_color(crashcolor.BLUE)
        print("\n\tTotal allocation = %s" % (bytes_to_str(total_bytes)))
        if options.show_details:
            print("\tTotal RSS = %s, SWAP = %s" %\
                  (bytes_to_str(total_rss_bytes),
                   bytes_to_str(total_swap_bytes)))
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
