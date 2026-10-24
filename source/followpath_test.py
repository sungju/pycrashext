"""
Checks for the 'follow' command's path parsing.

Run directly: python3 source/followpath_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from followpath import (PathError, parse_path, split_path, start_expr,
                        step_expr, parse_whatis, type_kind, parse_print,
                        parse_number, gdb_error, normalize_type)


def check_split():
    assert split_path("mm.exe_file.f_path.dentry") == \
        ["mm", "exe_file", "f_path", "dentry"]
    assert split_path("mm->exe_file->f_path.dentry") == \
        ["mm", "exe_file", "f_path", "dentry"]
    assert split_path("fd[3].private_data:socket.sk") == \
        ["fd[3]", "private_data:socket", "sk"]
    assert split_path("se.group_node.next:task_struct@se.group_node->comm") == \
        ["se", "group_node", "next:task_struct@se.group_node", "comm"]
    assert split_path("a[i.j].b") == ["a[i.j]", "b"]
    try:
        split_path("mm..exe_file")
        assert False
    except PathError:
        pass


def check_steps():
    s = parse_path("fd[3][1]:union foo *")[0]
    assert s == {"member": "fd", "index": "[3][1]", "cast": "union foo *",
                 "container": None}
    s = parse_path("tasks.next:task_struct@tasks")[1]
    assert s["cast"] == "task_struct" and s["container"] == "tasks"
    for bad in ["3abc", "next@tasks"]:
        try:
            parse_path(bad)
            assert False, bad
        except PathError:
            pass


def check_exprs():
    e = start_expr("task_struct", "0xffff95a0529a8000")
    assert e == "((struct task_struct *)0xffff95a0529a8000)"
    assert start_expr("struct task_struct", "1") == "((struct task_struct *)1)"
    steps = parse_path("mm.exe_file:file.f_path.dentry")
    e = step_expr(e, True, steps[0])
    e = step_expr(e, True, steps[1])
    assert e == "((struct file *)(((struct task_struct *)0xffff95a0529a8000)->mm->exe_file))"
    e = step_expr(e, True, steps[2])
    e = step_expr(e, False, steps[3])
    assert e.endswith("->f_path.dentry")
    c = step_expr("(x)", False, parse_path("next:task_struct@tasks")[0])
    assert c == "((struct task_struct *)((char *)((x).next) - " \
                "(unsigned long)&((struct task_struct *)0)->tasks))"
    assert normalize_type("unsigned long *") == "unsigned long *"
    assert normalize_type("union  foo") == "union foo"


def check_gdb_output():
    assert parse_whatis("type = struct mm_struct *\n") == "struct mm_struct *"
    assert type_kind("struct mm_struct *") == ("ptr", "struct mm_struct")
    assert type_kind("struct path") == ("struct", "struct path")
    assert type_kind("struct page **")[0] == "other"
    assert type_kind("char [16]")[0] == "other"
    assert type_kind("struct list_head [4]")[0] == "other"
    assert type_kind("int (*)(struct file *)")[0] == "other"
    assert type_kind("atomic_t")[0] == "other"
    assert parse_print("$12 = 0xffff95a05a2f1e00\n") == "0xffff95a05a2f1e00"
    assert parse_number(parse_print("$1 = 18446744071562067968")) == 18446744071562067968
    assert parse_number('0xffff "bash"') == 0xffff
    assert gdb_error("There is no member named foo.") == "There is no member named foo."
    assert gdb_error("$1 = 0x0") is None


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
