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
import base64

import crashcolor
import crashhelper


def is_command_exist(name):
    result_str = crashhelper.run_gdb_command("!which %s" % (name))
    if result_str.find(":") >= 0:
        return False
    return True


def ai_send(ins_addr, o, args, cmd_path_list):
    path_list = cmd_path_list.split(':')
    ai_send_path = ""
    for path in path_list:
        if os.path.exists(path + "/ai_send.py"):
            ai_send_path = path + "/ai_send.py"
            break

    if ai_send_path == "":
        print("Can't find ai_send.py in path")
        return

    options = ""
    cmd_options = ""
    if o.ai_model != "":
        cmd_options = cmd_options + " -m " + o.ai_model

    result_str = ""
    python_list = { "python", "python3", "python2" }
    for python_cmd in python_list:
        if (is_command_exist(python_cmd)):
            cmd_to_run = ' '.join(args)
            result_str = "crash> " + cmd_to_run + "\n" +\
                    exec_crash_command(cmd_to_run)
            if cmd_to_run.strip().startswith("dis "):
                result_str = "Please analyze the following assembly code " +\
                             "focusing on the flags set by each instruction " +\
                             "and how they affect the branch decisions made " +\
                             "by conditional jump instructions. Provide a " +\
                             "step-by-step breakdown of the code, describing " +\
                             "the function and any side effects for each line and explain " +\
                             "how the flags are used to make branch decisions." +\
                             "\n\n~~~\n" + result_str.rstrip() + "\n~~~"
            else:
                result_str = "Analyse the below output from linux kernel vmcore" +\
                        "\n\n~~~\n" + result_str + "\n~~~"

            result_str = crashhelper.run_gdb_command("!echo '%s' | %s %s %s" % \
                                                (result_str, python_cmd, \
                                                 ai_send_path, cmd_options))
            print(result_str)
            break


def ai():
    op = OptionParser()

    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/ai'
    except:
        encode_url = ""

    if encode_url == None or encode_url == "":
        print("No server to use AI is available")
        return 

    op.add_option("-m", "--model",
                  action="store",
                  type="string",
                  default="",
                  dest="ai_model",
                  help="Choose AI model to use")
    (o, args) = op.parse_args()


    if len(args) != 0:
        ai_send(args[0], o, args, os.environ["PYKDUMPPATH"])
    else:
        print("ERROR> ai needs an instruction to run before send data.\n",
              "\ti.e) ai \"bt -a\"")


if ( __name__ == '__main__'):
    ai()
