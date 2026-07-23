"""
'ai' command: analyse a crash command's output with an AI model through the remoteapi server.

Written by Sungju Kwon <sungju.kwon@gmail.com>
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

    try:
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
    except:
        pass

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


MAX_CONTENT_SIZE = 100000

def truncate_content(data, limit=MAX_CONTENT_SIZE):
    if len(data) <= limit:
        return data
    truncated = data[-limit:]
    newline_pos = truncated.find('\n')
    if newline_pos >= 0:
        truncated = truncated[newline_pos + 1:]
    return "[Truncated: showing last %d chars of %d total]\n\n" % \
            (len(truncated), len(data)) + truncated


RESPONSE_START_MARKER = "---AI_RESPONSE_START---"
RESPONSE_END_MARKER = "---AI_RESPONSE_END---"

def extract_response(result_str):
    start_idx = result_str.find(RESPONSE_START_MARKER)
    end_idx = result_str.find(RESPONSE_END_MARKER)
    if start_idx >= 0 and end_idx > start_idx:
        return result_str[start_idx + len(RESPONSE_START_MARKER):end_idx].strip()
    return result_str


def print_rich_result(result_str):
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        code_theme = os.environ.get('CODE_THEME', 'tango')
        console = Console(color_system="truecolor")
        console.print(Markdown(result_str, code_theme=code_theme))
        return
    except:
        pass

    data_path = ""
    script_path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as fp:
            fp.write(result_str.encode())
            data_path = fp.name

        script = """import sys, os
fpath = sys.argv[1]
data = open(fpath).read()
os.remove(fpath)
try:
    from rich.console import Console
    from rich.markdown import Markdown
    code_theme = os.environ.get('CODE_THEME', 'tango')
    Console(color_system='truecolor').print(Markdown(data, code_theme=code_theme))
except:
    print(data)
    print('\\nNotes) pip install rich can enhance the output', end='')
"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.py') as fp:
            fp.write(script.encode())
            script_path = fp.name

        rendered = crashhelper.run_gdb_command("!python3 %s %s" % \
                                               (script_path, data_path))
        print(rendered)
    except:
        print(result_str)
    finally:
        try:
            os.remove(script_path)
        except:
            pass


def ai_send_local(prompt_data, engine, model=""):
    model_opt = ""
    if model != "":
        model_opt = " -m " + model

    prompt_data = truncate_content(prompt_data)
    prompt_data = prompt_data + \
            "\n\nIMPORTANT: Start your response with exactly '" + \
            RESPONSE_START_MARKER + "' on its own line and end with " + \
            "exactly '" + RESPONSE_END_MARKER + "' on its own line."

    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as fp:
            fp.write(prompt_data.encode())
            temp_path = fp.name
    except Exception as e:
        print("Error writing temp file:", e)
        return

    if engine == "claude":
        cmd = "!cat %s | claude -p %s 2>/dev/null" % (temp_path, model_opt)
    else:
        cmd = "!cat %s | gemini --skip-trust -p 'Analyze the following' %s 2>/dev/null" % (temp_path, model_opt)

    result_str = crashhelper.run_gdb_command(cmd)
    try:
        os.remove(temp_path)
    except:
        pass

    result_str = extract_response(result_str)
    print_rich_result(result_str)


def ai_send(o, args, cmd_path_list, local_engine=""):
    global question_dict

    result_str = ""
    cmd_str = ""
    if len(o.cmd_list) > 0:
        per_cmd_limit = MAX_CONTENT_SIZE // len(o.cmd_list)
        for c in o.cmd_list:
            output = get_crash_command_output(c)
            if "crash: command not found:" in output:
                print("Cannot execute command '%s'" % c)
                return
            output = truncate_content(output, per_cmd_limit)
            result_str = result_str + "\n\n~~~\n" + output + "\n~~~"
        cmd_str = o.cmd_list[0].split()[0]
    elif o.input_file != "":
        try:
            with open(o.input_file) as fp:
                result_str = "".join(fp.readlines())
        except Exception as e:
            print(e)
            pass

    if len(o.cmd_list) > 0:
        read_ai_questions()
        matchset = find_best_match(question_dict, o.cmd_list[0])
        key, match_question = matchset if matchset != None else ('', '')
    else:
        key = match_question = ""

    if len(args) != 0:
        result_str = " ".join(args) + "\n" + result_str
    elif match_question != None:
        result_str = match_question + "\n" + result_str
    elif len(args) == 0:
        result_str = "Analyse the below output from linux kernel vmcore" +\
                result_str

    if local_engine != "":
        ai_send_local(result_str, local_engine, o.ai_model)
        return

    path_list = cmd_path_list.split(':')
    ai_send_path = ""
    for path in path_list:
        if os.path.exists(path + "/ai_send.py"):
            ai_send_path = path + "/ai_send.py"
            break

    if ai_send_path == "":
        print("Can't find ai_send.py in path")
        return

    cmd_options = ""
    if o.ai_engine != "":
        cmd_options = cmd_options + " -e " + o.ai_engine

    if o.taskid != "":
        cmd_options = cmd_options + " -t " + o.taskid

    if o.ai_model != "":
        cmd_options = cmd_options + " -m " + o.ai_model

    if o.reset:
        cmd_options = cmd_options + " -r "

    python_list = { "python", "python3", "python2" }
    for python_cmd in python_list:
        if (is_command_exist(python_cmd)):
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


def detect_local_engine():
    for engine in ["claude", "gemini"]:
        if is_command_exist(engine):
            return engine
    return ""


def ai():
    op = OptionParser()

    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/ai'
    except:
        encode_url = ""

    op.add_option("-c", "--cmd",
                  action="append",
                  type="string",
                  default=[],
                  dest="cmd_list",
                  help="The output of this command will be analysed (repeatable)")

    op.add_option("-e", "--engine",
                  action="store",
                  type="string",
                  default="",
                  dest="ai_engine",
                  help="Choose AI engine to use (claude, gemini, or remote engine)")

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

    op.add_option("-r", "--reset",
                  action="store_true",
                  dest="reset",
                  default=False,
                  help="Reset AI prompt history")

    op.add_option("-t", "--taskid",
                  action="store",
                  type="string",
                  default="",
                  dest="taskid",
                  help="vmcore taskid")
    (o, args) = op.parse_args()

    if o.taskid == "":
        o.taskid = get_taskid()

    local_engine = ""
    if o.ai_engine in ("claude", "gemini"):
        if is_command_exist(o.ai_engine):
            local_engine = o.ai_engine
        else:
            print("'%s' is not installed" % o.ai_engine)
            return
    elif o.ai_engine == "":
        local_engine = detect_local_engine()
        if local_engine == "" and (encode_url == None or encode_url == ""):
            print("No AI server or local CLI (claude, gemini) is available")
            return

    if len(o.cmd_list) > 0 or len(args) != 0 or o.input_file != "":
        ai_send(o, args, os.environ["PYKDUMPPATH"], local_engine)
    else:
        print("ERROR> ai needs an instruction to run before send data.\n",
              "\ti.e) ai -c \"bt -a\"")


if ( __name__ == '__main__'):
    ai()
