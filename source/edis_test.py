"""
Checks for the parts of 'edis' that don't need a live crash session: jump and
call detection, branch targets, the jump graph, call graph walking, 'bt' frame
matching and operand parsing. pykdump is stubbed out.

Run directly: python3 source/edis_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import subprocess
import sys
import types


class _SysInfo(object):
    machine = "x86_64"
    pointersize = 8


# 'dis <func>' output served by the stubbed exec_crash_command.
_dis_output = {}


def _exec_crash_command(cmd):
    return _dis_output.get(cmd, "")


def _exec_gdb_command(cmd):
    # Stands in for gdb's '!' shell escape.
    assert cmd.startswith("!")
    subprocess.call(cmd[1:], shell=True)


_api = types.ModuleType("pykdump.API")
_api.sys_info = _SysInfo()
_api.exec_crash_command = _exec_crash_command
_api.exec_gdb_command = _exec_gdb_command
_api.readULong = lambda addr: 0
_api.__all__ = ["sys_info", "exec_crash_command", "exec_gdb_command", "readULong"]
sys.modules["pykdump"] = types.ModuleType("pykdump")
sys.modules["pykdump.API"] = _api
_linuxdump = types.ModuleType("LinuxDump")
_linuxdump.Tasks = None
sys.modules["LinuxDump"] = _linuxdump
sys.modules["LinuxDump.Tasks"] = types.ModuleType("LinuxDump.Tasks")

import crashcolor
import crashhelper
import edis


def _set_arch(arch):
    edis.sys_info.machine = arch


def check_arch_family():
    assert edis.get_arch_family("x86_64") == "x86"
    assert edis.get_arch_family("aarch64") == "arm"
    assert edis.get_arch_family("ppc64le") == "ppc"
    assert edis.get_arch_family("s390x") == "s390x"
    assert edis.get_arch_family("riscv64") == "riscv"


def check_jump_ops():
    edis.set_jump_op_list("x86_64")
    assert edis.check_jump_op("jne") and edis.check_jump_op("jmpq")
    assert not edis.check_jump_op("callq")

    # aarch64 used to fall back to x86's 'j' list and draw no graph.
    edis.set_jump_op_list("aarch64")
    for op in ("b", "b.ne", "cbz", "cbnz", "tbz", "tbnz", "br"):
        assert edis.check_jump_op(op), op
    for op in ("bl", "blr", "bic", "bics", "bfi", "mov"):
        assert not edis.check_jump_op(op), op

    edis.set_jump_op_list("ppc64le")
    assert edis.check_jump_op("bne") and not edis.check_jump_op("bctrl")

    # Switching architectures does not keep the previous exclusions.
    edis.set_jump_op_list("x86_64")
    assert edis.exclude_set == []


def check_branch_target():
    t = edis.get_branch_target
    assert t("0xffffffff81000004 <f+4>: jne 0xffffffff81000020 <f+32>".split()) \
        == "0xffffffff81000020"
    assert t("0xc000000000001000 <f+4>: bne cr7,0xc000000000001040 <f+64>".split()) \
        == "0xc000000000001040"
    assert t("0xffff800010000004 <f+4>: cbz x0, 0xffff800010000020 <f+32>".split()) \
        == "0xffff800010000020"
    assert t("0xffff800010000004 <f+4>: tbz w0, #3, 0xffff800010000020 <f+32>".split()) \
        == "0xffff800010000020"
    assert t("0xffffffff81000004 <f+4>: jmpq *0x10(%rax)".split()) == ""
    assert t("0xffff800010000004 <f+4>: br x1".split()) == ""


def _dis(lines):
    return "\n".join(lines) + "\n"


def check_draw_branches_aarch64():
    _set_arch("aarch64")
    text = _dis([
        "0xffff800010000000 <f>:\tcbz\tx0, 0xffff80001000000c <f+12>",
        "0xffff800010000004 <f+4>:\tmov\tx1, x2",
        "0xffff800010000008 <f+8>:\tmov\tx3, x4",
        "0xffff80001000000c <f+12>:\tret",
    ])
    lines = edis.draw_branches(text, "").splitlines()
    assert not edis.jump_graph_truncated
    graph = [l[:l.find("0x")] for l in lines]
    assert graph[0].endswith("*"), graph     # jump origin
    assert "|" in graph[1] and "|" in graph[2], graph
    assert graph[3].endswith(">"), graph     # jump target
    _set_arch("x86_64")


def check_draw_branches_truncated():
    _set_arch("x86_64")
    count = edis.MAX_JMP_LINES + 5
    lines = []
    for i in range(count):
        lines.append("0x%x <f+%d>:\tjmp\t0x%x <f>" % (0x1000 + i, i, 0x1000))
    edis.draw_branches(_dis(lines), "")
    assert edis.jump_graph_truncated
    edis.draw_branches(_dis(lines[:3]), "")
    assert not edis.jump_graph_truncated


def check_call_list():
    edis.set_call_op_list("x86_64")
    text = _dis([
        "0xffffffff81000000 <f>:\tcallq\t0xffffffff81100000 <foo>",
        "0xffffffff81000005 <f+5>:\tcall\t0xffffffff81200000 <bar>",
        "0xffffffff8100000a <f+10>:\tcall\t*%rax",
        "0xffffffff8100000c <f+12>:\tcall\t0xffffffff81300000",
        "0xffffffff81000011 <f+17>:\tret",
    ])
    assert edis.get_call_list(text) == ["foo", "bar", "*%rax",
                                        "0xffffffff81300000"]

    # 'bic' is bit clear, not a call; 'blr' is an indirect call.
    edis.set_call_op_list("aarch64")
    text = _dis([
        "0xffff800010000000 <f>:\tbl\t0xffff800010100000 <foo>",
        "0xffff800010000004 <f+4>:\tbic\tx0, x0, #0x1",
        "0xffff800010000008 <f+8>:\tblr\tx1",
    ])
    assert edis.get_call_list(text) == ["foo", "*x1"]

    edis.set_call_op_list("ppc64le")
    assert "bctrl" in edis.call_op_set and "ctrl" not in edis.call_op_set


class _Opts(object):
    max_depth = 5


def check_callgraph_recursion():
    _set_arch("x86_64")
    edis.set_call_op_list("x86_64")
    _dis_output.clear()
    _dis_output["dis a"] = _dis(["0x1000 <a>:\tcall\t0x2000 <b>"])
    _dis_output["dis b"] = _dis(["0x2000 <b>:\tcall\t0x1000 <a>",
                                 "0x2005 <b+5>:\tcall\t*%rax"])
    edis.callgraph_cache.clear()
    del edis.callgraph_path[:]
    del edis.branch_bar[:]
    del edis.branch_locations[:]

    saved = crashcolor.set_color
    crashcolor.set_color = lambda c: None
    out = []
    saved_stdout = sys.stdout

    class _Capture(object):
        def write(self, s):
            out.append(s)

        def flush(self):
            pass

    sys.stdout = _Capture()
    try:
        edis.show_callgraph_func("a", 0, True, _Opts())
        edis.show_callgraph("a", 0, _Opts())
    finally:
        sys.stdout = saved_stdout
        crashcolor.set_color = saved
    text = "".join(out)
    assert "{b}" in text and "(recursive)" in text and "{*%rax}" in text, text
    assert edis.callgraph_path == []
    _dis_output.clear()


def check_address_match():
    n = edis.normalize_address
    assert n("0xFFFFFFFF8F7B9C5D") == "ffffffff8f7b9c5d"
    assert n("ffffffff8f7b9c5d") == "ffffffff8f7b9c5d"
    assert n("schedule") == "schedule"

    frame = "#1 [ffffb3c0c0a3fd50] __schedule at ffffffff8f7b9c5d".split()
    m = edis.bt_frame_matches
    assert m(frame, "__schedule", "0xffffffff8f7b9c5d")
    assert m(frame, "__schedule", "ffffffff8f7b9c5d")
    assert m(frame, "__schedule", "__schedule")
    assert not m(frame, "__schedule", "0xffffffff8f7b9c60")
    assert not m(frame, "schedule", "0xffffffff8f7b9c5d")
    assert not m("#1 [ffff] __schedule".split(), "__schedule", "__schedule")


def check_call_color():
    _set_arch("x86_64")
    edis.set_asm_colors()
    assert edis.get_colored_asm("call") is not None
    assert edis.get_colored_asm("callq") == edis.get_colored_asm("call")


def check_parse_offset():
    p = edis.parse_offset
    assert p("16") == 16 and p("-8") == -8
    assert p("0x10") == 16 and p("-0x10") == -16
    assert p("#16") == 16 and p("$0x8") == 8
    assert p("") == 0 and p("junk") == 0


def check_arm_mem_operand():
    p = edis.parse_aarch64_mem_operand
    assert p("[sp, #-32]!") == ("sp", -32, True, False)
    assert p("[sp], #32") == ("sp", 32, False, True)
    assert p("[x29,#24]") == ("x29", 24, False, False)
    assert p("[sp]") == ("sp", 0, False, False)
    assert p("x0") == (None, 0, False, False)


def check_source_path_header():
    h = edis.is_source_path_header
    assert h("/usr/src/debug/kernel-3.10.0-1160/linux/mm/swap_state.c: 333")
    assert not h("    333   struct page *page;")
    assert not h("0xffffffff81000000 <f>: ret")


def check_pipe_to_helper():
    # The disassembly reaches disasm.py on stdin intact, quotes included.
    # It used to go through "echo '...'", which a quote broke.
    text = "line with a 'quote' and \"double\"\nsecond line\n"
    out = crashhelper.run_gdb_command_with_file("!cat", text)
    assert out == text, repr(out)


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
