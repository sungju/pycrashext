"""
 Written by Daniel Sungju Kwon
"""

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
import re

import crashcolor
import crashhelper

sysinfo = {}
sys_str = ""

def get_system_info():
    global sysinfo
    global sys_str

    if (len(sysinfo) > 0):
        return

    sys_str = exec_crash_command("sys")
    resultlines = sys_str.splitlines()
    for line in resultlines:
        words = line.split(":")
        sysinfo[words[0].strip()] = line[len(words[0]) + 2:].strip()



def get_taskid():
    global sysinfo

    get_system_info()
    dump_path = sysinfo["DUMPFILE"]

    task_id = "UNKNOWN_ID"
    if "/tasks/" in dump_path:
        task_id = dump_path[dump_path.find("/tasks/") + 7:]
        task_id = task_id[:task_id.find("/")]

    return task_id


question_dict = {}

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
        question_dict = question_dict | parse_commands(fpath)


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



def parse_commands(filename):
    cmd_re = re.compile(r'^\s*CMD:\s*(.+?)\s*$')
    end_re = re.compile(r'^\s*CMD_END:\s*(.+?)\s*$')

    commands = {}
    current_variants = None
    buffer = []

    with open(filename, 'r') as f:
        for lineno, line in enumerate(f, start=1):
            cmd_match = cmd_re.match(line)
            if cmd_match:
                raw = cmd_match.group(1)
                variants = [v.strip() for v in raw.split(',')]
                current_variants = variants
                buffer = []
                continue

            end_match = end_re.match(line)
            if end_match and current_variants:
                content = ''.join(buffer).strip()
                for cmd in current_variants:
                    commands[cmd] = content
                current_variants = None
                buffer = []
                continue

            if current_variants:
                buffer.append(line)

    return commands


def find_best_match(commands, full_input):
    # Split off parameters — only match the base command
    base = full_input.split()[0]

    matches = [(cmd, content)
               for cmd, content in commands.items()
               if cmd.startswith(base)]
    if not matches:
        return None
    return max(matches, key=lambda x: len(x[0]))


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
    if o.ai_engine != "":
        cmd_options = cmd_options + " -e " + o.ai_engine

    if o.taskid != "":
        cmd_options = cmd_options + " -t " + o.taskid

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
            key, match_question = find_best_match(question_dict, o.cmd_str)

            if len(args) != 0:
                result_str = " ".join(args) + "\n" + result_str
            elif match_question != None:
                result_str = match_question + "\n" + result_str
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

    op.add_option("-e", "--engine",
                  action="store",
                  type="string",
                  default="",
                  dest="ai_engine",
                  help="Choose AI engine to use")

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

    op.add_option("-t", "--taskid",
                  action="store",
                  type="string",
                  default="",
                  dest="taskid",
                  help="vmcore taskid")
    (o, args) = op.parse_args()

    if o.taskid == "":
        o.taskid = get_taskid()

    if o.cmd_str != "" or len(args) != 0 or o.input_file != "":
        ai_send(o, args, os.environ["PYKDUMPPATH"])
    else:
        print("ERROR> ai needs an instruction to run before send data.\n",
              "\ti.e) ai -c \"bt -a\"")


if ( __name__ == '__main__'):
    ai()
