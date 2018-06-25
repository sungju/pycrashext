"""
Written by Daniel Sungju Kwon

It provides additional information into the disassembled code
Currently it provides source lines if the proper source can be found
and displays jump graphs as well
"""
from flask import Flask
from flask import request
import re
import os
import base64

cur_kernel_version = ""
cur_rhel_path = ""


def add_plugin_rule(app):
    app.add_url_rule('/api/setgit/<string:asm_str>', 'setgit',
                     setgit, methods=['GET'])
    app.add_url_rule('/api/disasm', 'disasm', disasm, methods=['POST'])


def set_kernel_version(asm_str):
    global cur_kernel_version
    global cur_rhel_path

    first_line = asm_str.splitlines()[0]
    pattern = re.compile(r"(.+)/debug/(?P<kernelversion>.+)/linux.*")
    m = pattern.search(first_line)
    kernel_version = m.group('kernelversion')
    # Below 'rhel_version' is going to be used to find source directory
    rhel_version = 'rh' + kernel_version.split('.')[-1]

    cur_rhel_path = os.environ['RHEL_SOURCE_DIR'] + "/" + rhel_version

    os.chdir(cur_rhel_path)

    if cur_kernel_version == kernel_version:
        return kernel_version

    result = os.system('git checkout -f ' + kernel_version)
    if result != 0:
        return "FAILED to git checkout %s" % (kernel_version)
    cur_kernel_version = kernel_version

    return kernel_version


def setgit(asm_str):
    result = set_kernel_version(asm_str)
    return result


"""
Check if the line ends properly to make one statement
"""
def is_end_of_one_statement(a_line):
    my_line = re.sub(r"/\*.*\*/", "", a_line).strip()
    if my_line.endswith(';') or \
       my_line.endswith(':') or \
       my_line.endswith('{') or \
       my_line.endswith('}'):
        return True

    return False


def is_assembly_source(source_file):
    if source_file.endswith(".S") or \
       source_file.endswith(".s") or \
       source_file.endswith(".asm") or \
       source_file.endswith(".ASM"):
        return True

    return False


def read_source_line(source_line, has_header):
    pattern = re.compile(r"(.+)/linux-[^/]*/(?P<source_file>.+): (?P<line_number>[0-9]+)")
    try:
        m = pattern.search(source_line)
        source_file = m.group('source_file')
        ln = m.group('line_number')
        line_number = int(ln)
    except:
        return ""

    file_lines = []
    try:
        os.chdir(cur_rhel_path)
        f = open(source_file, 'r')
        file_lines = f.readlines()
        f.close()
    except:
        return ""


    if line_number > len(file_lines):
        return "file_lines {}".format(len(file_lines))

    source_line = ""
    result = ""
    if is_assembly_source(source_file) == True and has_header == False:
        has_header = True # Assembly doesn't require to check prototype
        result = result + '%8d %s' % (line_number -1, file_lines[line_number - 2])

    if has_header == False:
        for i in range(line_number - 1, 0, -1):
            if "(" in file_lines[i]:
                for j in range(i, line_number - 1):
                    result = result + '%8d %s' % (j + 1, file_lines[j])
                break


    if is_assembly_source(source_file) == False:
        prev_line_number = line_number - 2
        if has_header == True:
            source_line = file_lines[prev_line_number]
            while not is_end_of_one_statement(source_line):
                prev_line_number = prev_line_number - 1
                source_line = file_lines[prev_line_number]
            while file_lines[prev_line_number + 1].strip() == "":
                prev_line_number = prev_line_number + 1

        for i in range(prev_line_number + 1, line_number):
            source_line = file_lines[i]
            result = result + '%8d %s' % (i + 1, source_line)

        while not is_end_of_one_statement(source_line):
            source_line = file_lines[line_number]
            line_number = line_number + 1
            result = result + '%8d %s' % (line_number, source_line)

    return result


JUMP_ORIGIN = 0x10000
JUMP_TARGET = 0x20000
JUMP_CORNER = 0x30000

MAX_JMP_LINES = 100

def draw_branches(disasm_str):
    result = ""
    asm_addr_dict = {}
    loc = 0
    for line in disasm_str.splitlines():
        if line.startswith("0x"):
            words = line.split()
            asm_addr_dict[words[0]] = loc
        loc = loc + 1

    total_num = loc
    jmp_dict = [[0 for x in range(MAX_JMP_LINES)] for y in range(total_num)]
    has_jmp_dict = [0 for x in range(total_num)]
    loc = 0
    jmp_found = 1
    for line in disasm_str.splitlines():
        if line.startswith("0x"):
            words = line.split()
            if words[2].startswith("j"):
                if words[3] in asm_addr_dict:
                    target_idx = asm_addr_dict[words[3]]
                else:
                    target_idx = total_num

                current_idx = loc
                start = min(current_idx, target_idx)
                end = max(current_idx, target_idx)
                if end >= total_num:
                    end = total_num - 1

                for i in range(start, end):
                    jmp_dict[i][jmp_found - 1] = jmp_dict[i][jmp_found - 1] + 1
                    has_jmp_dict[i] = has_jmp_dict[i] + 1
                jmp_dict[current_idx][jmp_found] = JUMP_ORIGIN # current
                jmp_dict[current_idx][jmp_found - 1] = JUMP_CORNER # current
                if target_idx < total_num:
                    jmp_dict[target_idx][jmp_found] = JUMP_TARGET # target
                    jmp_dict[target_idx][jmp_found - 1] = JUMP_CORNER # target

                jmp_found = jmp_found + 1
        loc = loc + 1

    result = ""
    loc = 0
    for line in disasm_str.splitlines():
        jmp_str = " "
        line_str = ""
        for i in range(0, jmp_found):
            if (jmp_dict[loc][i] & JUMP_ORIGIN) == JUMP_ORIGIN:
                jmp_str = "-"
            if (jmp_dict[loc][i] & JUMP_TARGET) == JUMP_TARGET:
                jmp_str = "="
            if (jmp_dict[loc][i] & JUMP_CORNER) == JUMP_CORNER:
                jmp_str = "+"
            if jmp_dict[loc][i] > 0 and jmp_str == " ":
                jmp_str = "|"

            if i == jmp_found - 1:
                if jmp_str == "-":
                    jmp_str = "*"
                if jmp_str == "=":
                    jmp_str = ">"

            line_str = line_str + jmp_str
            if jmp_str != "-" and jmp_str != "=" and \
               jmp_str != ">" and jmp_str != '*':
                jmp_str = " "

        result = result + line_str + line + "\n"
        loc = loc + 1

    return result


def disasm():
    # First line can be used to identify kernel version
    try:
        asm_str = request.form["asm_str"]
    except:
        return 'error getting asm_str data'

    try:
        asm_str = base64.b64decode(asm_str)
    except:
        return 'error found in base64'


    # Draw branch graphs
    try:
        jump_graph = request.form["jump_graph"]
    except:
        jump_graph = ""

    result = set_kernel_version(asm_str)
    if result.startswith("FAIL"):
        return result

    result = ""

    asm_lines = asm_str.splitlines()
    has_header = False
    for line in asm_lines:
        result = result + line + "\n"
        if has_header == False:
            result = result + read_source_line(line, has_header)
            has_header = True
            continue

        if  line.startswith("/"):
            source_line = read_source_line(line, has_header)
            result = result + source_line

    if jump_graph != "":
        result = draw_branches(result)

    return result.strip()
