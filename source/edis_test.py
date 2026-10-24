"""
Checks for the parts of 'edis' that don't need a live crash session: jump and
call detection, branch targets, the jump graph, call graph walking, 'bt' frame
matching and operand parsing. pykdump is stubbed out.

Run directly: python3 source/edis_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import optparse
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
_api.OptionParser = optparse.OptionParser
_api.__all__ = ["sys_info", "exec_crash_command", "exec_gdb_command", "readULong",
                "OptionParser"]
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


def check_call_list_tail_calls_and_thunks():
    _set_arch("x86_64")
    edis.set_call_op_list("x86_64")
    edis.callee_address.clear()
    text = _dis([
        "0xffffffff81000000 <f>:\tcall\t0xffffffff81e00000 <__fentry__>",
        "0xffffffff81000005 <f+5>:\tcall\t0xffffffff81c00000 <__x86_indirect_thunk_rax>",
        "0xffffffff8100000a <f+10>:\tje\t0xffffffff81000020 <f+32>",
        "0xffffffff8100000c <f+12>:\tcall\t0xffffffff81100000 <foo>",
        "0xffffffff81000011 <f+17>:\tjmp\t0xffffffff81200000 <bar>",
        "0xffffffff81000016 <f+22>:\tjmp\t0xffffffff81300010 <baz+16>",
        "0xffffffff8100001b <f+27>:\tjne\t0xffffffff81000000 <f>",
        "0xffffffff81000020 <f+32>:\tjmp\t0xffffffff81e00010 <__x86_return_thunk>",
    ])
    # __fentry__ and the return thunk are noise, the retpoline thunk is an
    # indirect call, 'jmp <bar>' is a tail call; jumps inside a function
    # (or to itself, or into the middle of another) are not calls.
    assert edis.get_call_list(text) == ["*%rax", "foo", "bar"], edis.get_call_list(text)
    assert edis.callee_address == {"foo": "0xffffffff81100000",
                                   "bar": "0xffffffff81200000"}


def check_callees_by_address():
    # A name shared by two functions makes 'dis <name>' fail, so callees
    # are disassembled from the address the call used.
    _set_arch("x86_64")
    edis.set_call_op_list("x86_64")
    edis.callgraph_cache.clear()
    edis.callee_address.clear()
    _dis_output.clear()
    _dis_output["dis root"] = _dis(["0x1000 <root>:\tcall\t0x2000 <dput>"])
    _dis_output["dis -f 0x2000"] = _dis(["0x2000 <dput>:\tcall\t0x3000 <iput>"])
    _dis_output["dis dput"] = "dis: dput: duplicate text symbols found:\n"
    _dis_output["dis iput"] = _dis(["0x3000 <iput>:\tret"])
    assert edis.callees_of("root") == ["dput"]
    assert edis.callees_of("dput") == ["iput"]
    assert edis.find_call_paths("root", "iput", 3, edis.callees_of) == \
        [["root", "dput", "iput"]]
    _dis_output.clear()
    edis.callgraph_cache.clear()
    edis.callee_address.clear()


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


def check_operands():
    c = edis.canonical_register
    assert c("%edi", "x86") == "rdi" and c("%r8d", "x86") == "r8"
    assert c("%al", "x86") == "rax" and c("0x8(%rax)", "x86") is None
    assert c("w1", "arm") == "x1" and c("x19", "arm") == "x19"

    assert edis.split_operands("0x8(%rax,%rbx,8),%rcx") == ["0x8(%rax,%rbx,8)", "%rcx"]
    assert edis.split_operands("x0, [sp, #16]") == ["x0", "[sp, #16]"]

    d = edis.dest_register
    assert d("0x1 <f+1>: mov 0x58(%rdi),%rax".split(), "x86") == "rax"
    assert d("0x1 <f+1>: xor %esi,%esi".split(), "x86") == "rsi"
    assert d("0x1 <f+1>: mov %rax,0x8(%rbx)".split(), "x86") is None
    assert d("0x1 <f+1>: cmp $0x1,%rdi".split(), "x86") is None
    assert d("0x1 <f+1>: pop %rbx".split(), "x86") == "rbx"
    assert d("0x1 <f+1>: ldr w0, [x19, #8]".split(), "arm") == "x0"
    assert d("0x1 <f+1>: str x0, [sp, #16]".split(), "arm") is None
    assert d("0x1 <f+1>: bic x0, x0, #0x1".split(), "arm") == "x0"


def check_parse_prototype():
    p = edis.parse_prototype
    assert p("int foo(struct page *, unsigned int);") == ["struct page *", "unsigned int"]
    assert p("void schedule(void);") == []
    assert p("int bar(int (*)(void *, int), void *);") == ["int (*)(void *, int)", "void *"]
    assert p("whatis: invalid argument: nosuch") is None


def _with_arch(arch, fn):
    saved = edis.sys_info.machine
    edis.sys_info.machine = arch
    try:
        return fn()
    finally:
        edis.sys_info.machine = saved


def check_call_arg_notes():
    lines = [
        "0x1000 <f>:\tmov    %rbx,%rdi",
        "0x1003 <f+3>:\tmov    $0x1,%esi",
        "0x1008 <f+8>:\tmov    $0x2,%edx",
        "0x100d <f+13>:\tcall   0x2000 <foo>",
        "0x1012 <f+18>:\tmov    %rax,%rdi",
        "0x1015 <f+21>:\tcall   *%r11",
    ]
    protos = {"foo": ["struct page *", "int"]}
    notes = _with_arch("x86_64", lambda: edis.call_arg_notes(lines, protos.get))
    # foo takes 2 arguments: %edx is not one of them.
    assert notes == {0: "arg1 of foo (struct page *)", 1: "arg2 of foo (int)",
                     4: "arg1 of indirect call"}, notes

    # Without a prototype every argument register written is named, and
    # the walk stops at a jump target.
    lines = [
        "0x1000 <f>:\tmov    $0x5,%ecx",
        "0x1005 <f+5>:\tje     0x100a <f+10>",
        "0x100a <f+10>:\tmov    $0x1,%edi",
        "0x100f <f+15>:\tcall   0x2000 <bar>",
    ]
    notes = _with_arch("x86_64", lambda: edis.call_arg_notes(lines, lambda n: None))
    assert notes == {2: "arg1 of bar"}, notes

    lines = ["0x10 <f>:\tmov\tx0, x19", "0x14 <f+4>:\tbl\t0x80 <baz>"]
    notes = _with_arch("aarch64", lambda: edis.call_arg_notes(lines, lambda n: None))
    assert notes == {0: "arg1 of baz"}, notes


_STRUCT_PAGE = """struct page {
   [0x0] unsigned long flags;
         union {
             struct {
   [0x8]         struct list_head lru;
  [0x18]         struct address_space *mapping;
  [0x20]         unsigned long index;
             };
         };
  [0x28] unsigned int refcnt : 24;
  [0x30] void (*free)(struct page *);
  [0x38] char name[8];
}
SIZE: 64"""

_STRUCT_LIST_HEAD = """struct list_head {
   [0] struct list_head *next;
   [8] struct list_head *prev;
}
SIZE: 16"""

_STRUCT_AS = """struct address_space {
   [0x0] struct inode *host;
  [0x10] unsigned long nrpages;
}
SIZE: 24"""

def _layout(kind, name):
    text = {"page": _STRUCT_PAGE, "list_head": _STRUCT_LIST_HEAD,
            "address_space": _STRUCT_AS}.get(name, "")
    return edis.parse_struct_offsets(text)


def check_struct_offsets():
    members, size = edis.parse_struct_offsets(_STRUCT_PAGE)
    assert size == 64
    assert members == [
        (0x0, "flags", "unsigned long"),
        (0x8, "lru", "struct list_head"),
        (0x18, "mapping", "struct address_space *"),
        (0x20, "index", "unsigned long"),
        (0x28, "refcnt", "unsigned int"),
        (0x30, "free", "function pointer"),
        (0x38, "name", "char[]"),
    ], members
    assert edis.parse_struct_offsets(_STRUCT_LIST_HEAD)[0][1] == \
        (8, "prev", "struct list_head *")

    r = edis.resolve_field
    assert r("struct", "page", 0x18, _layout) == ("mapping", "struct address_space *")
    assert r("struct", "page", 0x10, _layout) == ("lru.prev", "struct list_head *")
    assert r("struct", "page", 0x4, _layout) == ("flags+0x4", None)
    assert r("struct", "page", 0x3a, _layout) == ("name+0x2", None)
    assert r("struct", "page", 0x40, _layout) is None      # past SIZE
    assert r("struct", "nosuch", 0, _layout) is None


def check_struct_field_notes():
    lines = [
        "0x1000 <f>:\tpush   %rbx",
        "0x1001 <f+1>:\tmov    %rdi,%rbx",
        "0x1004 <f+4>:\tmov    0x18(%rbx),%rax",
        "0x1008 <f+8>:\tmov    0x10(%rax),%rdx",
        "0x100c <f+12>:\tmov    (%rax),%rcx",
        "0x100f <f+15>:\tlea    0x8(%rbx),%rsi",
        "0x1013 <f+19>:\tmov    0x8(%rsi),%rdi",
        "0x1017 <f+23>:\tcall   0x2000 <g>",
        "0x101c <f+28>:\tmov    0x20(%rbx),%rax",
        "0x1020 <f+32>:\tmov    0x8(%rcx),%rax",
        "0x1024 <f+36>:\tmov    %eax,0x28(%rbx)",
    ]
    protos = {"f": ["struct page *"]}
    notes = _with_arch("x86_64", lambda: edis.struct_field_notes(
        lines, protos.get, _layout))
    assert notes == {
        2: "page->mapping",
        3: "address_space->nrpages",
        4: "address_space->host",
        5: "&page->lru",
        6: "list_head->prev",
        8: "page->index",        # %rbx survives the call
        10: "page->refcnt",
    }, notes                     # %rcx did not: no note on row 9

    # A jump target forgets what was known.
    lines = [
        "0x1000 <f>:\tje     0x1004 <f+4>",
        "0x1002 <f+2>:\tnop",
        "0x1004 <f+4>:\tmov    0x18(%rdi),%rax",
    ]
    notes = _with_arch("x86_64", lambda: edis.struct_field_notes(
        lines, protos.get, _layout))
    assert notes == {}, notes
    assert _with_arch("aarch64", lambda: edis.struct_field_notes(
        lines, protos.get, _layout)) == {}


def check_find_call_paths():
    graph = {"a": ["b", "c", "*%rax"], "b": ["d", "a"], "c": ["d+16"], "d": ["e"]}
    get = lambda n: graph.get(n, [])
    assert edis.find_call_paths("a", "d", 2, get) == [["a", "b", "d"], ["a", "c", "d"]]
    assert edis.find_call_paths("a", "e", 2, get) == []
    assert edis.find_call_paths("a", "e", 3, get) == [["a", "b", "d", "e"],
                                                      ["a", "c", "d", "e"]]
    assert len(edis.find_call_paths("a", "d", 5, get, limit=1)) == 1


_SRC = {
    "/usr/src/debug/kernel-5.14/linux-5.14/mm/f.c": [
        "int f(struct page *page)",
        "{",
        "\tint x = foo(page,",
        "\t\t    1);",
        "\treturn x;",
        "}",
    ],
}


def check_local_source():
    dis = "\n".join([
        "/usr/src/debug/kernel-5.14/linux-5.14/mm/f.c: 3",
        "0x1000 <f>:\tcall   0x2000 <foo>",
        "/usr/src/debug/kernel-5.14/linux-5.14/mm/f.c: 5",
        "0x1005 <f+5>:\tret",
    ]) + "\n"
    text, found = edis.add_local_source(dis, _SRC.get)
    assert found
    assert text.splitlines() == [
        "/usr/src/debug/kernel-5.14/linux-5.14/mm/f.c: 3",
        "       3 \tint x = foo(page,",
        "       4 \t\t    1);",
        "0x1000 <f>:\tcall   0x2000 <foo>",
        "/usr/src/debug/kernel-5.14/linux-5.14/mm/f.c: 5",
        "       5 \treturn x;",
        "0x1005 <f+5>:\tret",
    ], text

    # No file here: plain 'dis' output, headers dropped.
    text, found = edis.add_local_source(dis, lambda p: None)
    assert not found
    assert text.splitlines() == ["0x1000 <f>:\tcall   0x2000 <foo>",
                                 "0x1005 <f+5>:\tret"]

    # The whole definition: signature, braces, body.
    full = edis.local_function_source(dis, _SRC.get).splitlines()
    assert full[0].endswith("f.c: 1"), full
    assert full[1] == "       1 int f(struct page *page)", full
    assert full[-1] == "       6 }", full
    assert edis.local_function_source(dis, lambda p: None) is None

    assert edis.statement_range(_SRC[list(_SRC)[0]], 3) == (2, 3)


def check_save_and_diff():
    old = "\n".join([
        "0xffffffff81000000 <f>:\tpush   %rbp",
        "0xffffffff81000001 <f+1>:\tcall   0xffffffff81100000 <g>",
        "0xffffffff81000006 <f+6>:\tmov    0xffffffff82345678,%rax",
    ])
    new = "\n".join([
        "/usr/src/debug/kernel-5.14/linux-5.14/mm/f.c: 3",
        "0xffffffff9a000000 <f>:\tpush   %rbp",
        "0xffffffff9a000001 <f+1>:\tcall   0xffffffff9a100000 <g>",
        "0xffffffff9a000006 <f+6>:\tmov    0xffffffff9b345678,%rbx",
    ])
    a = edis.normalize_disasm(old)
    b = edis.normalize_disasm(new)
    assert a == ["<f> push %rbp", "<f+1> call <g>", "<f+6> mov ADDR,%rax"], a
    diff = edis.diff_disasm(a, b, "old", "new")
    assert "-<f+6> mov ADDR,%rax" in diff and "+<f+6> mov ADDR,%rbx" in diff
    assert edis.diff_disasm(a, a, "old", "new") == []

    import os
    import tempfile

    class _O(object):
        pass

    path = os.path.join(tempfile.mkdtemp(), "f.edis")
    o = _O()
    o.save, o.diff = path, ""
    out = []
    saved_stdout = sys.stdout

    class _Capture(object):
        def write(self, s):
            out.append(s)

        def flush(self):
            pass

        def isatty(self):
            return False

    sys.stdout = _Capture()
    try:
        edis.save_or_diff(old, "f", o)
        o.save, o.diff = "", path
        edis.save_or_diff(new, "f", o)
    finally:
        sys.stdout = saved_stdout
    text = "".join(out)
    assert "Saved 3 instructions" in text, text
    assert "+<f+6> mov ADDR,%rbx" in text, text


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
