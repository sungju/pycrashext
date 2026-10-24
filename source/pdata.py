"""
'pdata' command: walk a chain of structure members without writing casts.

Instead of
    px ((struct file *)((struct task_struct *)0xffff95a0529a8000)->mm->exe_file)->f_path.dentry
type
    pdata task_struct 0xffff95a0529a8000 mm.exe_file.f_path.dentry

Every step is printed with its value and type, so a NULL or a bad pointer
shows where the chain broke, and the last member is then dumped member by
member ('struct <type> <address>' for a structure, gdb 'print' otherwise).
A char * shows its string on the line below its address.

    pdata <type> <address> [<path>]
        <type>     task_struct, 'struct task_struct' or 'union foo'
        <address>  hex (0x optional) or any gdb expression ('&init_task')
        <path>     members separated by '.' or '->', with name[N],
                   name:type (cast) and name:type@member (container_of);
                   see pdatapath.py

    -a   also dump every structure on the way
    -n   do not dump the last member, only the chain
    -o   show member offsets in the dumps (struct -o)
    -x   hexadecimal dumps, -d decimal dumps

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

import difflib
import re

import crashcolor
import pdatapath


USAGE = "pdata [-a|-n] [-o] [-x|-d] <type> <address> [<path>]"


def gdb(cmd):
    """(output, error line or None) of a gdb command."""
    try:
        out = exec_gdb_command(cmd)
    except Exception as e:
        return "", str(e).strip() or "gdb failed: %s" % cmd
    if out is None:
        out = ""
    return out, pdatapath.gdb_error(out)


def whatis(expr):
    out, err = gdb("whatis %s" % expr)
    if err:
        return None, err
    t = pdatapath.parse_whatis(out)
    if t is None:
        return None, "cannot read the type of %s" % expr
    return t, None


def number_of(expr):
    out, err = gdb("p/x (unsigned long)(%s)" % expr)
    if err:
        return None, err
    n = pdatapath.parse_number(pdatapath.parse_print(out))
    if n is None:
        return None, "cannot read the value of %s" % expr
    return n, None


def short_value(expr, hex_out):
    """One-line value of a non-struct member."""
    out, err = gdb("p%s %s" % ("/x" if hex_out else "", expr))
    if err:
        return None, err
    v = pdatapath.parse_print(out)
    if v is None:
        return None, "cannot read %s" % expr
    v = " ".join(v.split())
    if len(v) > 70:
        v = v[:67] + "..."
    return v, None


def char_string(expr):
    """(address, string) of a char * member, the string as gdb quotes it."""
    try:
        out = exec_gdb_command("p %s" % expr)
    except Exception as e:
        return None, "<%s>" % str(e).strip()
    return pdatapath.split_string(pdatapath.parse_print(out or ""))


def member_names(base):
    """Member names of a struct or union, for suggestions."""
    out, err = gdb("ptype %s" % base)
    if err:
        return []
    names = []
    for line in out.splitlines()[1:]:
        line = line.split("/*")[0].strip()
        if not line.endswith(";"):
            continue
        m = re.search(r"\(\*\s*(\w+)\)\s*\(", line)
        if not m:
            m = re.search(r"(\w+)\s*(?:\[[^\]]*\])*\s*(?::\s*\d+)?\s*;$", line)
        if m:
            names.append(m.group(1))
    return names


def dump(kind, base, addr, expr, o):
    """Every member of the object an expression ends at."""
    flags = ""
    if o.offsets:
        flags += " -o"
    if o.hex_out:
        flags += " -x"
    elif o.dec_out:
        flags += " -d"
    if kind in ("ptr", "struct"):
        cmd, name = base.split(None, 1)
        try:
            print(exec_crash_command("%s%s %s 0x%x" % (cmd, flags, name, addr)).rstrip())
            return
        except Exception:
            pass
    out, err = gdb("p%s %s" % ("/x" if o.hex_out else "", expr))
    if err:
        print("  %s" % err)
        return
    print(out.rstrip())


def print_step(label, value, type_str, depth, color=None, below=None):
    """One line of the chain; 'below' goes on the next line, under the value."""
    if color is not None:
        crashcolor.set_color(color)
    width = max(28 - 2 * depth, 8)
    print("%s%-*s = %-24s %s" % ("  " * depth, width, label, value, type_str))
    if below:
        print("%s%s" % (" " * (2 * depth + width + 3), below))
    if color is not None:
        crashcolor.set_color(crashcolor.RESET)


def start_address(text):
    """A bare hex address gets its 0x; anything else goes to gdb as is."""
    if re.match(r"^[0-9a-fA-F]{8,16}$", text) and not re.match(r"^\d+$", text):
        return "0x" + text
    return text


def pdata(type_name, address, path, o):
    try:
        steps = pdatapath.parse_path(path) if path else []
    except pdatapath.PathError as e:
        print(e)
        return

    expr = pdatapath.start_expr(type_name, start_address(address))
    t, err = whatis(expr)
    if err:
        print("%s: %s" % (type_name, err))
        return
    kind, base = pdatapath.type_kind(t)
    addr, err = number_of(expr)
    if err:
        print("%s: %s" % (address, err))
        return
    print_step("(%s)" % t, "0x%x" % addr, "", 0, crashcolor.LIGHTGREEN)
    if o.all and kind == "ptr" and steps and addr:
        dump(kind, base, addr, expr, o)

    for i, step in enumerate(steps):
        if kind == "ptr" and addr == 0:
            crashcolor.set_color(crashcolor.LIGHTRED)
            print("NULL pointer before '%s', cannot follow further" %
                  pdatapath.step_label(step))
            crashcolor.set_color(crashcolor.RESET)
            return
        prev_base = base
        expr = pdatapath.step_expr(expr, t.endswith("*"), step)
        t, err = whatis(expr)
        if err:
            crashcolor.set_color(crashcolor.LIGHTRED)
            print("%s%s: %s" % ("  " * (i + 1), pdatapath.step_label(step), err))
            crashcolor.set_color(crashcolor.RESET)
            close = difflib.get_close_matches(step["member"],
                                              member_names(prev_base), n=5)
            if close:
                print("  members of %s like '%s': %s" %
                      (prev_base, step["member"], ", ".join(close)))
            return
        kind, base = pdatapath.type_kind(t)
        last = (i == len(steps) - 1)
        label = ("->" if i else "") + pdatapath.step_label(step)
        string = None
        if pdatapath.is_char_pointer(t):
            addr, err = number_of(expr)
            value = "0x%x" % addr if err is None else err
            if err is None and addr:
                string = char_string(expr)[1]
        elif kind == "ptr" or (t.endswith("*") and "(" not in t):
            addr, err = number_of(expr)
            value = "0x%x" % addr if err is None else err
        elif kind == "struct":
            addr, err = number_of("&(%s)" % expr)
            value = "(at 0x%x)" % addr if err is None else err
        else:
            addr = None
            value, err = short_value(expr, o.hex_out)
            if err:
                value = err
        print_step(label, value, t, i + 1,
                   crashcolor.LIGHTRED if err else
                   (crashcolor.LIGHTCYAN if last else None), string)
        if err:
            return
        if o.all and not last and kind in ("ptr", "struct") and addr:
            dump(kind, base, addr, expr, o)

    if o.no_dump:
        return
    print()
    if kind in ("ptr", "struct"):
        if not addr:
            print("NULL, nothing to dump")
            return
        crashcolor.set_color(crashcolor.LIGHTYELLOW)
        print("%s 0x%x" % (base, addr))
        crashcolor.set_color(crashcolor.RESET)
        dump(kind, base, addr, expr, o)
    else:
        crashcolor.set_color(crashcolor.LIGHTYELLOW)
        print(expr)
        crashcolor.set_color(crashcolor.RESET)
        if pdatapath.is_char_pointer(t):
            # The address and type, then the string it points to.
            print("0x%x %s" % (addr, t))
            if addr:
                print(char_string(expr)[1])
            return
        dump(kind, base, addr, expr, o)
        # A pointer to something other than a struct: show what it points to.
        if t.endswith("*") and "(" not in t and addr:
            out, err = gdb("p%s *(%s)" % ("/x" if o.hex_out else "", expr))
            print(err if err else "*%s" % out.strip())


def pdata_cmd():
    op = OptionParser(usage=USAGE)
    op.add_option("-a", "--all", dest="all", default=0, action="store_true",
                  help="Also dump every structure on the way")
    op.add_option("-n", "--no-dump", dest="no_dump", default=0,
                  action="store_true",
                  help="Only show the chain, do not dump the last member")
    op.add_option("-o", "--offsets", dest="offsets", default=0,
                  action="store_true",
                  help="Show member offsets in the dumps")
    op.add_option("-x", "--hex", dest="hex_out", default=0,
                  action="store_true", help="Hexadecimal dumps")
    op.add_option("-d", "--dec", dest="dec_out", default=0,
                  action="store_true", help="Decimal dumps")

    (o, args) = op.parse_args()
    if args and args[0] in ("struct", "union") and len(args) > 1:
        args = [args[0] + " " + args[1]] + args[2:]
    if len(args) < 2:
        print("usage: %s" % USAGE)
        print("  e.g. pdata task_struct 0xffff95a0529a8000 mm.exe_file.f_path.dentry")
        print("       pdata task_struct ffff95a0529a8000 mm->exe_file->f_path.dentry->d_name.name")
        print("       pdata -n task_struct 0xffff95a0529a8000 tasks.next:task_struct@tasks->comm")
        return
    pdata(args[0], args[1], " ".join(args[2:]), o)


if ( __name__ == '__main__'):
    pdata_cmd()
