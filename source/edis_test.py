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
    graph = [l[:l.find("0x")] for l in lines]
    assert graph[0].endswith("*"), graph     # jump origin
    assert "|" in graph[1] and "|" in graph[2], graph
    assert graph[3].endswith(">"), graph     # jump target
    _set_arch("x86_64")


def check_jump_lanes():
    # Two jumps that don't overlap share a lane; one around them gets
    # the next lane out.
    lanes, count = edis.assign_jump_lanes([(0, 2), (3, 5), (0, 9)])
    assert count == 2 and lanes == [0, 0, 1], (lanes, count)

    # Touching ranges (one jump lands where the next leaves) can't share.
    lanes, count = edis.assign_jump_lanes([(0, 3), (3, 6)])
    assert count == 2, (lanes, count)

    assert edis.assign_jump_lanes([]) == ([], 0)


def check_draw_branches_compact():
    # 50 short jumps in a row used to take 50 columns.
    _set_arch("x86_64")
    lines = []
    for i in range(0, 100, 2):
        lines.append("0x%x <f+%d>:\tjmp\t0x%x <f+%d>" % (0x1000 + i, i, 0x1001 + i, i + 1))
        lines.append("0x%x <f+%d>:\tnop" % (0x1001 + i, i + 1))
    out = edis.draw_branches(_dis(lines), "").splitlines()
    assert out[0] == "+*" + lines[0], out[0]
    assert out[1] == "+>" + lines[1], out[1]
    assert all(len(l) - len(src) == 2 for l, src in zip(out, lines))

    # A jump out of the function runs to the last line without an arrow.
    out = edis.draw_branches(_dis([
        "0x1000 <f>:\tjmp\t0x9000 <g>",
        "0x1001 <f+1>:\tret",
    ]), "").splitlines()
    assert out[0].startswith("+*") and out[1].startswith("| "), out


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


def check_target_line():
    pt = edis.parse_target
    assert pt("schedule") is None
    assert pt("0xFFFFFFFF8F7B9C5D") == ("addr", "ffffffff8f7b9c5d")
    assert pt("ffffffff8f7b9c5d") == ("addr", "ffffffff8f7b9c5d")
    assert pt("schedule+0x12") == ("sym", "schedule", 18)
    assert pt("schedule+18") == ("sym", "schedule", 18)
    assert pt("mm/swap_state.c: 333") is None

    line = "0xffffffff8f7b9c5d <schedule+18>:\tmov    %rax,%rdi".split()
    first = "0xffffffff8f7b9c4b <schedule>:\tpush   %rbp".split()
    t = edis.is_target_line
    assert t(line, pt("0xffffffff8f7b9c5d"))
    assert t(line, pt("ffffffff8f7b9c5d"))
    assert t(line, pt("schedule+0x12"))
    assert not t(line, pt("schedule+0x13"))
    assert not t(line, pt("__schedule+0x12"))
    assert t(first, pt("schedule+0"))
    assert not t(line, None)


_FUNC = [
    "/usr/src/debug/kernel-5.14.0/linux-5.14.0/kernel/f.c: 10",
    "0xffffffff81000000 <f>:\tpush   %rbp",
    "0xffffffff81000001 <f+1>:\ttest   %rdi,%rdi",
    "0xffffffff81000004 <f+4>:\tje     0xffffffff8100000a <f+10>",
    "/usr/src/debug/kernel-5.14.0/linux-5.14.0/kernel/f.c: 12",
    "0xffffffff81000006 <f+6>:\tcall   0xffffffff81100000 <g>",
    "0xffffffff8100000a <f+10>:\tmov    0x58(%rdi),%rax",
    "0xffffffff8100000e <f+14>:\tjne    0xffffffff8100000a <f+10>",
    "0xffffffff81000010 <f+16>:\tret",
]


def check_asm_start():
    a = edis.asm_start
    assert a("0xffffffff81000000 <f>:\tpush   %rbp") == 0
    assert a("+-*0xffffffff81000000 <f>:\tpush   %rbp") == 3
    assert a("    333   if (flags & 0x10)") == -1
    assert a("|| 333   x = 0x10;") == -1
    assert a("/usr/src/debug/f.c: 12") == -1


def check_join_around_target():
    before = "\n".join(_FUNC[:7]) + "\n"           # start .. f+10
    after = "\n".join(_FUNC[6:]) + "\n"            # f+10 .. end
    assert edis.join_around_target(before, after) == "\n".join(_FUNC) + "\n"
    # Target is the last instruction, or 'dis -f' failed: keep 'before'.
    assert edis.join_around_target(before, _FUNC[6] + "\n") == before
    assert edis.join_around_target(before, "dis: invalid option") == before


def check_context_rows():
    target = edis.parse_target("f+0xa")
    shown = edis.context_rows(_FUNC, target, 1)
    # f+6 and f+14 around f+10, and the f.c:12 header f+6 belongs to.
    assert shown == {4, 5, 6, 7}, sorted(shown)

    # f+16 is the first shown instruction; its source header (row 4) is
    # found by walking back over the skipped ones.
    shown = edis.context_rows(_FUNC, edis.parse_target("f+16"), 0)
    assert shown == {4, 8}, sorted(shown)

    assert edis.context_rows(_FUNC, edis.parse_target("f+99"), 1) is None


def check_jump_sources():
    _set_arch("x86_64")
    assert edis.jump_sources(_FUNC) == {6: "from f+4, f+14"}

    lines = ["0x10 <f>:\tret"]
    for i in range(6):
        lines.append("0x%x <f+%d>:\tjmp\t0x10 <f>" % (0x20 + i, i + 1))
    assert edis.jump_sources(lines) == \
        {0: "from f+1, f+2, f+3, f+4, +2 more"}


def check_plain_source_when_piped():
    class _Pipe(object):
        def isatty(self):
            return False

    saved = sys.stdout
    sys.stdout = _Pipe()
    edis._source_highlighter_ready = False
    try:
        out = edis.highlight_source_code("   10   int x = 0;", 80)
    finally:
        sys.stdout = saved
        edis._source_highlighter_ready = False
    assert out == "   10   int x = 0;", repr(out)


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
