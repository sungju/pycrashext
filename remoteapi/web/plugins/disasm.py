"""
Written by Daniel Sungju Kwon

It provides additional information into the disassembled code
Currently it provides source lines if the proper source can be found
"""
from flask import Flask
from flask import request
import re
import os
import base64
import subprocess
import textwrap

cur_kernel_version = ""
cur_release_version = ""
cur_rhel_path = ""


def add_plugin_rule(app):
    app.add_url_rule('/api/setgit/<string:asm_str>', 'setgit',
                     setgit, methods=['GET'])
    app.add_url_rule('/api/disasm', 'disasm', disasm, methods=['POST'])


def set_kernel_version(asm_str):
    global cur_kernel_version
    global cur_release_version
    global cur_rhel_path

    first_line = asm_str.splitlines()[0]
    if not first_line.startswith("/"):
        return ""
    pattern = re.compile(r"(.+)/debug/(?P<kernelversion>.+)/linux-(?P<releaseversion>[^/]+)/.*")
    m = pattern.search(first_line)
    kernel_version = m.group('kernelversion')
    release_version = m.group('releaseversion')
    # Below 'gitdir' is going to be used to find source directory
    if release_version.find(".el5.") >= 0 or release_version.find("2.6.18.") >= 0:
        gitdir = 'rhel5'
        kernel_version = release_version[:release_version.rfind(".")]
    elif release_version.find(".fc") >= 0:
        gitdir = 'fedora'
        kernel_version = "kernel-" + release_version[:release_version.rfind(".")]
    elif kernel_version.find("-alt-") >= 0:
        gitdir = 'alt'
    elif kernel_version.find(".el8") >= 0:
        gitdir = 'rhel8'
    elif release_version.find(".el8_") >= 0:
        kernel_version = "kernel-rt-" + release_version
        gitdir = 'rhel8'
    elif release_version.find(".el9_") >= 0:
        gitdir = 'rhel9'
    elif release_version.find(".el10_") >= 0:
        gitdir = 'rhel10'
    elif first_line.find(".rt") >= 0:
        gitdir = "kernel-rt"
        kernel_version = "kernel-rt-" + release_version
    else:
        gitdir = 'rh' + kernel_version.split('.')[-1]

    cur_rhel_path = os.environ['RHEL_SOURCE_DIR'] + "/" + gitdir

    try:
        os.chdir(cur_rhel_path)
    except:
        return "FAILED to change directory to %s" % cur_rhel_path

    if cur_kernel_version == kernel_version:
        return kernel_version

    # Validate kernel_version format to prevent command injection
    # Allow alphanumeric, dots, dashes, underscores
    if not re.match(r'^[a-zA-Z0-9._-]+$', kernel_version):
        return "FAILED: Invalid kernel version format: %s" % kernel_version

    try:
        # Use subprocess without shell=True to prevent command injection
        process = subprocess.Popen(
            ['git', 'checkout', '-f', kernel_version],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        result = process.wait()
        out = b"".join(process.stdout.readlines())
        err = b"".join(process.stderr.readlines())
        if err != None and \
           (err.startswith(b"error:") or err.startswith(b"fatal:")):
            # Git checkout failed - try fetching from all remotes first
            print("Initial git checkout failed for %s, attempting to fetch from remotes..." % kernel_version)

            # Get list of all remotes
            remote_process = subprocess.Popen(
                ['git', 'remote', '-v'],
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            remote_process.wait()
            remote_output = remote_process.stdout.read().decode("utf-8")

            # Parse remotes manually instead of using awk/sort/uniq
            remotes = set()
            for line in remote_output.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1:
                        remotes.add(parts[0])

            # Fetch from each remote
            fetch_success = False
            for remote in remotes:
                if remote.strip():  # Skip empty lines
                    # Validate remote name format
                    if not re.match(r'^[a-zA-Z0-9._-]+$', remote):
                        continue

                    print("Fetching from %s..." % remote)
                    fetch_process = subprocess.Popen(
                        ['git', 'fetch', remote, '--tags', '-f'],
                        shell=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    fetch_result = fetch_process.wait()
                    if fetch_result == 0:
                        fetch_success = True

            # Try git checkout again after fetching
            if fetch_success:
                print("Retrying git checkout after fetch...")
                retry_process = subprocess.Popen(
                    ['git', 'checkout', '-f', kernel_version],
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                retry_result = retry_process.wait()
                retry_out = b"".join(retry_process.stdout.readlines())
                retry_err = b"".join(retry_process.stderr.readlines())

                if retry_err != None and \
                   (retry_err.startswith(b"error:") or retry_err.startswith(b"fatal:")):
                    return 'FAILED to git checkout even after fetching\n' + \
                           retry_err.decode("utf-8").rstrip() + "\n" + \
                           kernel_version + " at " + cur_rhel_path + "\n"

                # Retry succeeded
                cur_kernel_version = kernel_version
                cur_release_version = release_version.split("/")[0]
                print("Successfully checked out %s after fetch" % kernel_version)
            else:
                return 'FAILED to git checkout\n' + err.decode("utf-8").rstrip() + "\n" + \
                        kernel_version + " at " + cur_rhel_path + "\n" + \
                        "No remotes available to fetch from\n"
        else:
            # Initial checkout succeeded
            cur_kernel_version = kernel_version
            cur_release_version = release_version.split("/")[0]
    except Exception as e:
        cur_kernel_version = ""
        cur_release_version = ""
        return "FAILED to git checkout %s" % (kernel_version) + str(e)


    return kernel_version


def setgit(asm_str):
    result = set_kernel_version(asm_str)
    return result


"""
Check if the line ends properly to make one statement
"""
def is_end_of_one_statement(a_line):
    my_line = re.sub(r"/\*.*\*/", "\"\"", a_line).strip()
    if my_line.endswith(';') or \
       my_line.endswith(':') or \
       my_line.endswith('{') or \
       my_line.endswith('}') or \
       my_line.startswith("#"):
        return True

    return False

def is_function_header(a_line):
    a_line = a_line.strip()
    my_line = re.findall(r"SYSCALL_DEFINE[0-9][ \t]*\(", a_line)
    if my_line is not None and len(my_line) > 0:
        return True, my_line[0];

    my_line = re.findall(r"[a-zA-Z]*[ \n\t]*[a-zA-Z_][a-zA-Z0-9_]*[ \n\t]+[\*]*[a-zA-Z0-9_]+[ \n\t]*\(", a_line)
    if my_line is None or len(my_line) == 0:
        return False, None;

    if my_line[0].startswith("return"):
        return False, None;  # ex) return wait_noreap_copyout(wo...

    return True, my_line[0];


def is_assembly_source(source_file):
    if source_file.endswith(".S") or \
       source_file.endswith(".s") or \
       source_file.endswith(".asm") or \
       source_file.endswith(".ASM"):
        return True

    return False


def parse_source_line(source_line):
    if not source_line.startswith("/"):
        return "", 0, 0

    words = source_line.split(":")

#    pattern = re.compile(r"(.+)/linux-[^/]*/(?P<source_file>.+): (?P<line_number>[0-9]+)([ \t]*)(?P<end_line_number>[0-9]+)")
    pattern = re.compile(r"(.+)/linux-[^/]*/(?P<source_file>.+)")
    try:
        m = pattern.search(words[0])
        source_file = m.group('source_file')
        line_number = 0
        end_line_number = 0
        line_words = words[1].split()

        try:
            line_number = int(line_words[0])
        except:
            pass

        try:
            end_line_number = int(line_words[1])
        except:
            pass

        return source_file, line_number, end_line_number

    except:
        return "", 0, 0


def read_source_line(source_line, has_header):
    source_file, line_number, end_line_number = parse_source_line(source_line)
    if source_file == "":
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

    if has_header == False and end_line_number == 0:
        header_lines, open_brace, close_brace = read_a_function_header(file_lines, line_number - 1)
        result = result + header_lines
        '''
        for i in range(line_number - 1, 0, -1):
            if "(" in file_lines[i]:
                for j in range(i, line_number - 1):
                    result = result + '%8d %s' % (j + 1, file_lines[j])
                break
        '''


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


def read_a_function_header(file_lines, line_number):
    result = ""
    is_in_comment = False
    # Read function header
    prev_line_number = line_number
    source_line = file_lines[prev_line_number]
    is_function_def = False
    while True:
        a_line = re.sub(r"\".*\"", "", source_line).strip()
        if a_line.find("*/") >= 0 and a_line.find("\"") == -1:
            is_in_comment = True
        if a_line.find("/*") >= 0 and a_line.find("\"") == -1:
            is_in_comment = False

        prev_line_number = prev_line_number - 1
        if prev_line_number < 0:
            break
        prev_line = file_lines[prev_line_number]
        if not is_in_comment and not is_function_def:
            prev_a_line = re.sub(r"\".*\"", "", prev_line).strip()
            search_line = prev_a_line + a_line
            is_function_def, found_str = is_function_header(search_line)
            if is_function_def:
                if found_str != None and found_str.find("\n") > -1:
                    prev_line_number = prev_line_number - 1
                    prev_line = file_lines[prev_line_number]

        source_line = prev_line
        if not is_in_comment and is_function_def:
            while True:
                a_line = re.sub(r"\".*\"", "\"\"", source_line).strip()

                prev_line_number = prev_line_number - 1
                if prev_line_number < 0:
                    break
                source_line = file_lines[prev_line_number]

                if a_line.find("/*") >= 0:
                    is_in_comment = False
                    prev_line_number = prev_line_number - 1
                    break

                if is_in_comment:
                    continue

                if a_line.find("*/") >= 0:
                    is_in_comment = True
                    continue

                if a_line == "" or is_end_of_one_statement(a_line):
                    break

            prev_line_number = prev_line_number + 3 # adjust line number
            break

    while file_lines[prev_line_number + 1].strip() == "":
        prev_line_number = prev_line_number + 1

    in_comment = False
    open_brace = 0
    close_brace = 0
    for i in range(prev_line_number - 1, line_number):
        line = file_lines[i]
        result = result + '%8d %s' % (i + 1, line)
        for i in range(0, len(line) - 1):
            if line[i] == '{' and in_comment == False:
                open_brace = open_brace + 1
            elif line[i] == '}' and in_comment == False:
                close_brace = close_brace + 1
            elif line[i] == '/' and line[i + 1] == '*':
                in_comment = True
            elif line[i] == '*' and line[i + 1] == '/':
                in_comment = False
    # end of Read function header
    return result, open_brace, close_brace


def read_a_function(asm_str):
    '''
    Read a function, but it only works when the symbol is availabe in
    vmcore.
    '''
    first_line = asm_str.splitlines()[1]
    result = ""
    source_file, line_number, end_line_number = parse_source_line(first_line)
    if source_file == "":
        return first_line + "\n" + "Source code is not available"


    file_lines = []
    try:
        os.chdir(cur_rhel_path)
        f = open(source_file, 'r')
        file_lines = f.readlines()
        f.close()
    except:
        return "Failed to read file %s/%s" % (cur_rhel_path, source_file)

    result = first_line + "\n"
    if line_number == 0:
        for line in file_lines:
            line_number = line_number + 1
            result = result + "%8d %s" % (line_number, line)

        return result

    line_number = line_number - 1
    open_brace = 0
    close_brace = 0
    in_comment = False
    if end_line_number >= len(file_lines):
        end_line_number = len(file_lines)

    if end_line_number == 0:
        header_lines, open_brace, close_brace = read_a_function_header(file_lines,
                                                                       line_number)
        result = result + "\n" + header_lines

    while line_number < len(file_lines):
        line = file_lines[line_number]
        result = result + "%8d %s" % (line_number + 1, line)
        for i in range(0, len(line) - 1):
            if line[i] == '{' and in_comment == False:
                open_brace = open_brace + 1
            elif line[i] == '}' and in_comment == False:
                close_brace = close_brace + 1
            elif line[i] == '/' and line[i + 1] == '*':
                in_comment = True
            elif line[i] == '*' and line[i + 1] == '/':
                in_comment = False

        line_number = line_number + 1

        if end_line_number == 0:
            if open_brace > 0 and open_brace == close_brace:
                break
        else:
            if line_number >= end_line_number:
                break


    return result


def wrap_text_preserving_all_newlines(text, width=75):
    """
    Wraps text to a specific width while respecting all original newlines.
    """
    lines = text.splitlines(True) # keeps the newline endings
    wrapped_text = ""
    wrapper = textwrap.TextWrapper(width=width, break_long_words=True, replace_whitespace=False)

    for line in lines:
        if line.strip(): # Check if line has actual content
            # wrap returns a list of lines, join them back
            wrapped_line = '\n'.join(wrapper.wrap(line))
            wrapped_text += wrapped_line
            # If the original line ended with a newline, add it back (TextWrapper removes it)
            if line.endswith('\n'):
                 # Check for specific line ending to preserve type if needed, but '\n' works generally
                 wrapped_text += '\n'
        else:
            wrapped_text += line # Keep blank lines as they are

    return wrapped_text


def disasm():
    # First line can be used to identify kernel version
    try:
        asm_str = request.form["asm_str"]
    except:
        return 'error getting asm_str data'

    try:
        asm_str = base64.b64decode(asm_str).decode("utf-8")
    except:
        return 'error found in base64'

    # Print source code only
    try:
        full_source = request.form["full_source"]
    except:
        full_source = ""


    # Print source lines only
    try:
        source_only = request.form["source_only"]
    except:
        source_only = ""


    error_str = ""

    result = set_kernel_version(asm_str)
    if result.startswith("FAIL"):
        str_width = 75
        bound_str = "=" * str_width + "\n"
        error_str = error_str + bound_str + wrap_text_preserving_all_newlines(result, str_width) + bound_str

    if full_source != "":
        return read_a_function(asm_str) + "\n" + error_str # Read function and return


    result = ""

    asm_lines = asm_str.splitlines()[1:]
    has_header = False
    for line in asm_lines:
        if not line.startswith("/") and source_only != "":
            continue

        if source_only == "":
            result = result + line + "\n"
        if has_header == False and error_str == "":
            result = result + read_source_line(line, has_header)
            has_header = True
            continue

        if  line.startswith("/") and error_str == "":
            source_line = read_source_line(line, has_header)
            result = result + source_line

    return result + "\n" + error_str
