"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys
import operator
import os
from os.path import expanduser
import time
import urllib

import crashcolor
import crashhelper

sysinfo={}

def get_system_info():
    global sysinfo

    resultlines = exec_crash_command("sys").splitlines()
    for line in resultlines:
        words = line.split(":")
        sysinfo[words[0].strip()] = words[1].strip()


def get_sysdata_dict():
    global sysinfo
    dict = {}
    get_system_info()
    machine = sysinfo["MACHINE"].split()[0]
    dict["hostname"] = sysinfo["NODENAME"]
    dict["uname"] = "Linux %s %s %s %s %s %s GNU/Linux" % \
            (sysinfo["NODENAME"], sysinfo["RELEASE"], sysinfo["VERSION"],
             machine, machine, machine)
    dict["dmesg"] = exec_crash_command("log")

    return dict


def convert_to_base64(string):
    # There's a high chance that it is going to conflict due to single quote
    # but, let's see how it goes for now.
    result_str = crashhelper.run_gdb_command_with_file("!base64 -w 0", string)
    return result_str

def dump_to_json(sysdata_dict):
    result_str = "{"
    for key, value in sysdata_dict.items():
        result_str = result_str + "\"%s\" : \"%s\"," % (key, convert_to_base64(value))

    result_str = result_str + "}"
    print (result_str)
    return result_str


def exec_insights(o, args, cmd_path_list):
    path_list = cmd_path_list.split(':')
    insights_path = ""
    for path in path_list:
        if os.path.exists(path + "/insights_call.py"):
            insights_path = path + "/insights_call.py"
            break

    if insights_path == "":
        print("Can't find insights_call.py in path")
        return

    sysdata_dict = get_sysdata_dict()
    sysdata_str = dump_to_json(sysdata_dict)
    cmd_options = ""

    result_str = crashhelper.run_gdb_command("!echo '%s' | python %s %s" % \
                                            (sysdata_str, insights_path, cmd_options))


    print(result_str)


def insights():
    op = OptionParser()

    (o, args) = op.parse_args()
    exec_insights(o, args, os.environ["PYKDUMPPATH"])


if ( __name__ == '__main__'):
    insights()
