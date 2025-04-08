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
import io
from os.path import expanduser
import time
import base64
import tempfile
from io import StringIO

import crashcolor
import crashhelper


question_dict = {}

def read_ai_questions_from_a_file(filepath):
    global question_dict

    try:
        with open(filepath, 'r', encoding="utf-8") as f:
            lines = f.readlines()
            cmd_str = ""
            q_str = ""
            for line in lines:
                if line.startswith("CMD:"):
                    cmd_str = line.split(":")[1].strip()
                    q_str = ""
                    continue
                elif line.startswith("CMD_END:"):
                    if line.split(":")[1].strip() == cmd_str:
                        question_dict[cmd_str] = q_str.strip()
                        cmd_str = q_str = ""
                        continue

                q_str = q_str + line + "\n"
    except:
        pass


def read_ai_questions():
    global question_dict

    default_file= "ai_questions.txt"
    try:
        cmd_path_list = os.environ["PYKDUMPPATH"]
        path_list = cmd_path_list.split(':')
        for path in path_list:
            if os.path.exists(path + ("/ai_questions.txt")):
                default_file = path + ("/ai_questions.txt")
                break
    except:
        pass


    user_questions_file = "~/.ai_questions.cfg"
    try:
        user_questions_file = expanduser("~") + "/.ai_questions.cfg"
    except:
        pass

    question_dict = {}
    for fpath in [default_file, user_questions_file]:
        read_ai_questions_from_a_file(fpath)



def is_command_exist(name):
    result_str = crashhelper.run_gdb_command("!which %s" % (name))
    if result_str.find(":") >= 0:
        return False
    return True


def my_exec_command(cmdline):
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    orig_stdout = sys.stdout
    orig_stderr = sys.stderr

    sys.stdout = stdout_capture
    sys.stderr = stderr_capture

    try:
        exec_command(cmdline)
    except Exception as e:
        print(e)
    finally:
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr

    result = stdout_capture.getvalue()

    return result


def get_crash_command_output(cmd_str):
    result_str = ""
    try:
        '''
        result_str = "crash> sys\n" +\
                exec_crash_command("sys").rstrip() +\
                "\ncrash> " + cmd_str + "\n" +\
                my_exec_command(cmd_str).rstrip()
        '''
        result_str = "crash> " + cmd_str + "\n" +\
                my_exec_command(cmd_str).rstrip()
    except Exception as e:
        result_str = "crash> " + cmd_str + "\nERROR: " + repr(e)

    return result_str


def ai_send(o, args, cmd_path_list):
    global question_dict

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
            cmd_str = ""
            if o.cmd_str != "":
                cmd_str = o.cmd_str
                result_str = get_crash_command_output(cmd_str)
                if "crash: command not found:" in result_str:
                    print("Cannot execute command '%s'" % cmd_str)
                    return

                result_str = "\n\n~~~\n" + result_str + "\n~~~"
                cmd_str = cmd_str.split()[0]
            elif o.input_file != "":
                try:
                    with open(o.input_file) as fp:
                        result_str = "".join(fp.readlines())
                except Exception as e:
                    print(e)
                    pass

            read_ai_questions()
            if len(args) != 0:
                result_str = " ".join(args) + "\n" + result_str
            elif cmd_str in question_dict:
                result_str = question_dict[cmd_str] + result_str
            elif len(args) == 0:
                result_str = "Analyse the below output from linux kernel vmcore" +\
                        result_str
            

            try:
                with tempfile.NamedTemporaryFile(delete=False) as fp:
                    fp.write(result_str.encode())
                    cmd_options = cmd_options + " -i " + fp.name
                    result_str = ""
            except Exception as e:
                print("Error", e)
                pass

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

    op.add_option("-c", "--cmd",
                  action="store",
                  type="string",
                  default="",
                  dest="cmd_str",
                  help="The output of this command will be anlaysed")

    op.add_option("-i", "--input",
                  action="store",
                  type="string",
                  default="",
                  dest="input_file",
                  help="Use file for input data")

    op.add_option("-m", "--model",
                  action="store",
                  type="string",
                  default="",
                  dest="ai_model",
                  help="Choose AI model to use")
    (o, args) = op.parse_args()


    if o.cmd_str != "" or len(args) != 0 or o.input_file != "":
        ai_send(o, args, os.environ["PYKDUMPPATH"])
    else:
        print("ERROR> ai needs an instruction to run before send data.\n",
              "\ti.e) ai -c \"bt -a\"")


if ( __name__ == '__main__'):
    ai()
