"""
Member path parsing for the 'follow' command, kept free of crash so it can
be checked on its own (python3 followpath_test.py).

A path is the members to walk from a structure, separated by '.' or '->'
(either works for pointers and embedded structures alike):

    mm.exe_file.f_path.dentry
    mm->exe_file->f_path.dentry->d_name.name

Each member can carry:
    name[N]          an array element (name[2][0] works too)
    name:type        cast the member's value to 'struct type *', for void *
                     and unsigned long members (file.private_data:socket);
                     a type with a space or '*' is used as given
                     ('name:union foo *', 'name:unsigned long *')
    name:type@member container_of(): the value is the address of 'member'
                     inside a 'struct type' (tasks.next:task_struct@tasks);
                     the member may be nested (@se.group_node), so continue
                     the path after it with '->'

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re


class PathError(Exception):
    pass


STEP_RE = re.compile(r"^([A-Za-z_]\w*)((?:\[[^\]]+\])*)(?::([^@]+?))?(?:@([\w.]+))?$")


def split_path(path):
    """['mm', 'exe_file', ...] from 'mm->exe_file.f_path'.

    Anything inside [] is kept, and so is '.' after '@' (container_of's
    member may be nested: '@se.group_node'), which only '->' ends.
    """
    parts = []
    cur = ""
    depth = 0
    in_container = False
    i = 0
    path = path.strip()
    while i < len(path):
        c = path[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
        elif c == "@" and depth == 0:
            in_container = True
        if depth == 0 and path.startswith("->", i):
            parts.append(cur)
            cur = ""
            in_container = False
            i += 2
            continue
        if depth == 0 and not in_container and c == ".":
            parts.append(cur)
            cur = ""
            i += 1
            continue
        cur += c
        i += 1
    parts.append(cur)
    if any(p.strip() == "" for p in parts):
        raise PathError("empty member in path '%s'" % path)
    return [p.strip() for p in parts]


def normalize_type(name):
    """'struct foo' or the type as given when it already says what it is."""
    name = " ".join(name.split())
    if name.startswith("struct ") or name.startswith("union ") or \
       name.startswith("enum "):
        return name
    if " " in name or "*" in name:
        return name
    return "struct " + name


def pointer_type(name):
    """The pointer type a cast step turns its value into."""
    t = normalize_type(name)
    if t.endswith("*"):
        return t
    return t + " *"


def parse_step(text):
    """{'member', 'index', 'cast', 'container'} for one path element."""
    m = STEP_RE.match(text.strip())
    if not m:
        raise PathError("cannot read path element '%s'" % text)
    member, index, cast, container = m.groups()
    if container and not cast:
        raise PathError("'@%s' needs a type: name:type@%s" % (container, container))
    return {"member": member, "index": index or "",
            "cast": cast.strip() if cast else None,
            "container": container}


def parse_path(path):
    return [parse_step(p) for p in split_path(path)]


def start_expr(type_name, address):
    """The gdb expression for the starting object."""
    return "((%s)%s)" % (pointer_type(type_name), address)


def step_expr(expr, is_pointer, step):
    """The gdb expression for 'step' applied to 'expr'.

    The cast and container_of are applied to the member's value so the
    next step can dereference it.
    """
    e = "%s%s%s%s" % (expr, "->" if is_pointer else ".", step["member"], step["index"])
    if step["container"]:
        t = normalize_type(step["cast"])
        e = "((%s *)((char *)(%s) - (unsigned long)&((%s *)0)->%s))" % \
            (t, e, t, step["container"])
    elif step["cast"]:
        e = "((%s)(%s))" % (pointer_type(step["cast"]), e)
    return e


def step_label(step):
    s = step["member"] + step["index"]
    if step["cast"]:
        s += ":" + step["cast"]
    if step["container"]:
        s += "@" + step["container"]
    return s


def parse_whatis(output):
    """The type from gdb's 'whatis' output ('type = struct file *')."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("type = "):
            return line[len("type = "):].strip()
    return None


def type_kind(type_str):
    """('ptr' | 'struct' | 'other', base type).

    'ptr' is a single pointer to a struct or union, which the walk can go
    through and the final dump can show member by member; a struct or union
    held by value is 'struct'.
    """
    t = type_str.strip()
    if t.endswith("*") and not t.endswith("**") and "(" not in t:
        base = t[:-1].strip()
        if base.startswith("struct ") or base.startswith("union "):
            return ("ptr", base)
        return ("other", base)
    if (t.startswith("struct ") or t.startswith("union ")) and \
       not any(c in t for c in "*[("):
        return ("struct", t)
    return ("other", t)


VALUE_RE = re.compile(r"^\$\d+\s*=\s*(.*)$", re.S)


def parse_print(output):
    """What follows '$N = ' in gdb 'print' output, or None."""
    m = VALUE_RE.match(output.strip())
    if not m:
        return None
    return m.group(1).strip()


def parse_number(text):
    if text is None:
        return None
    m = re.match(r"^(0x[0-9a-fA-F]+|-?\d+)", text)
    if not m:
        return None
    return int(m.group(1), 0)


ERROR_HINTS = ("No symbol", "There is no member", "Cannot access memory",
               "Attempt to", "syntax error", "No struct type", "No union type",
               "cannot subscript", "not a structure", "invalid", "A syntax error")


def gdb_error(output):
    """The first error line of gdb output, or None."""
    for line in output.splitlines():
        for hint in ERROR_HINTS:
            if hint in line:
                return line.strip()
    return None
