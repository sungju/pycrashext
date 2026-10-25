"""
Checks for the parts of 'modinfo' that don't need a live crash session:
taint letters, module memory layouts, parameter values, load arguments and
modules in backtraces. pykdump is stubbed out.

Run directly: python3 source/modinfo_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import optparse
import sys
import types


class _SysInfo(object):
    machine = "x86_64"
    pointersize = 8


_symbols = {}


def _read_symbol(name):
    if name not in _symbols:
        raise KeyError(name)
    return _symbols[name]


_api = types.ModuleType("pykdump.API")
_api.sys_info = _SysInfo()
_api.readSymbol = _read_symbol
_api.OptionParser = optparse.OptionParser
_api.__all__ = ["sys_info", "readSymbol", "OptionParser"]
sys.modules["pykdump"] = types.ModuleType("pykdump")
sys.modules["pykdump.API"] = _api
_linuxdump = types.ModuleType("LinuxDump")
_linuxdump.Tasks = None
sys.modules["LinuxDump"] = _linuxdump
sys.modules["LinuxDump.Tasks"] = types.ModuleType("LinuxDump.Tasks")

import modinfo


class Obj(object):
    """A struct with the given members, like a pykdump StructResult."""

    def __init__(self, **members):
        self.__dict__.update(members)


def _table(spec):
    """'0:PGm 1:Fm 2:S ...' (from the vmcores' taint_flags) as a table."""
    table = []
    for item in spec.split():
        bit, flag = item.split(":")
        assert int(bit) == len(table)
        c_true = flag[0]
        c_false = flag[1] if len(flag) > 1 and flag[1] not in "m-" else ""
        table.append((c_true, c_false, flag.endswith("m")))
    return table


# Read from the RHEL 8.10 and 9.8 vmcores' taint_flags[].
RHEL8 = _table("0:PGm 1:Fm 2:S 3:R 4:M 5:B 6:U 7:D 8:A 9:W 10:Cm 11:I 12:Om 13:Em "
               "14:L 15:Km 16:Xm 17:Tm 18:Nm 19:?- 20:?- 21:?- 22:?- 23:?- 24:?- "
               "25:?- 26:?- 27:r 28:?- 29:tm 30:u 31:?-")
RHEL9 = _table("0:PGm 1:Fm 2:S 3:R 4:M 5:B 6:U 7:D 8:A 9:W 10:Cm 11:I 12:Om 13:Em "
               "14:L 15:Km 16:Xm 17:Tm 18:Nm 19:Jm 20:?- 21:?- 22:?- 23:?- 24:?- "
               "25:?- 26:p 27:h 28:?- 29:?- 30:?- 31:u")


def check_taint_letters():
    t = modinfo.taint_letters
    # tainted_mask 0x3000 on the RHEL 8.10 vmcore: 'G' for no proprietary
    # module, then O and E.
    assert t(0x3000, RHEL8) == "GOE"
    assert t(0x3001, RHEL9) == "POE"
    # A module's own taints only show the set bits that apply to modules.
    assert t(0x3000, RHEL8, module_only=True) == "OE"
    assert t(0x1, RHEL8, module_only=True) == "P"
    assert t(0x0, RHEL8, module_only=True) == ""
    # The RHEL-specific bits differ between releases.
    assert t(1 << 29, RHEL8) == "Gt" and t(1 << 27, RHEL9) == "Gh"
    assert t(1 << 31, RHEL9) == "Gu" and t(1 << 30, RHEL8) == "Gu"
    # A bit past the table is still visible.
    assert t(1 << 40, RHEL8) == "G?"
    for c in "GPOEruhpt":
        assert c in modinfo.taint_flags_desc, c


def check_rhel7_fallback_table():
    # No taint_flags[] or tnts[] in the vmcore: the RHEL 7 table.
    table = modinfo.rhel7_taint_table()
    assert table[28][0] == "H" and table[29][0] == "T" and table[29][2] is True
    assert modinfo.taint_letters((1 << 12) | (1 << 29), table) == "GOT"


def check_kernel_taint_table():
    _symbols["taint_flags"] = [Obj(c_true=0x50, c_false=0x47, module=1),
                               Obj(c_true=0x46, c_false=0x20, module=1),
                               Obj(c_true=0x3f, c_false=0x2d, module=0)]
    modinfo._taint_table = None
    try:
        assert modinfo.kernel_taint_table() == [("P", "G", True), ("F", "", True),
                                                ("?", "", False)]
    finally:
        del _symbols["taint_flags"]
        modinfo._taint_table = None


def check_module_layouts():
    core = Obj(size=819200, base=0xffffffffc066b000)
    rhel8 = Obj(core_layout=core, init_layout=Obj(size=0, base=0))
    assert modinfo.get_module_core_size(rhel8) == 819200
    assert modinfo.get_module_core_base(rhel8) == 0xffffffffc066b000

    rhel7 = Obj(core_size=4096, module_core=0xffffffffa0000000,
                init_size=512, module_init=0xffffffffa0100000)
    assert modinfo.get_module_core_size(rhel7) == 4096
    assert modinfo.get_module_init_range(rhel7) == (0xffffffffa0100000, 512)

    # 6.4+ (RHEL 9.4+): mem[] per type; core is TEXT, DATA, RODATA and
    # RO_AFTER_INIT, init the INIT_* types (sizes 0 once freed).
    mem = [Obj(base=0xffffffffc04d9000, size=16384), Obj(base=0xffffffffc04dd000, size=8192),
           Obj(base=0xffffffffc04e0000, size=4096), Obj(base=0, size=0),
           Obj(base=0, size=0), Obj(base=0, size=0), Obj(base=0, size=0)]
    rhel9 = Obj(mem=mem)
    assert modinfo.get_module_core_size(rhel9) == 28672
    assert modinfo.get_module_core_base(rhel9) == 0xffffffffc04d9000
    assert modinfo.get_module_init_range(rhel9) == (0, 0)
    mem[4] = Obj(base=0xffffffffc0500000, size=4096)
    assert modinfo.get_module_init_range(rhel9) == (0xffffffffc0500000, 4096)


def check_module_state_and_refs():
    assert modinfo.module_state(Obj(state=0)) == "LIVE"
    assert modinfo.module_state(Obj(state=2)) == "GOING"
    assert modinfo.module_state(Obj(state=9)) == "state 9"
    # refcnt starts at MODULE_REF_BASE (1): lsmod's 'Used by' is one less.
    assert modinfo.module_refs(Obj(refcnt=Obj(counter=5))) == 4
    assert modinfo.module_refs(Obj()) is None


def check_last_unloaded_module():
    _symbols["last_unloaded_module"] = "traps"
    assert modinfo.last_unloaded_module_str() == "traps"
    # RHEL 9.2+: a struct with the name and its taints.
    _symbols["last_unloaded_module"] = Obj(name="nvidia", taints="POE")
    assert modinfo.last_unloaded_module_str() == "nvidia (taints: POE)"
    _symbols["last_unloaded_module"] = Obj(name="ext4", taints="")
    assert modinfo.last_unloaded_module_str() == "ext4"
    del _symbols["last_unloaded_module"]
    assert modinfo.last_unloaded_module_str() == ""


def check_param_values():
    f = modinfo.format_param_scalar
    assert f("I", (150).to_bytes(4, "little")) == "150"
    assert f("i", (-1).to_bytes(4, "little", signed=True)) == "-1"
    assert f("I", (150).to_bytes(4, "big"), ">") == "150"       # s390x
    assert f("Q", (2 ** 40).to_bytes(8, "little")) == str(2 ** 40)
    assert f("bool", b"\x01") == "Y" and f("bool", b"\x00") == "N"
    assert f("invbool", b"\x01") == "N"
    assert f("bint", (1).to_bytes(4, "little")) == "Y"
    assert f("hex", (0x20f7).to_bytes(4, "little")) == "0x20f7"
    assert f("charp", b"") is None
    assert modinfo.byte_order("s390x") == ">" and modinfo.byte_order("ppc64le") == "<"

    a = modinfo.format_param_array
    assert a([], 0) == "[]"
    assert a(["1", "2", "3"], 3) == "[1, 2, 3]"
    # bonding's arp_ip_target: 16 unset slots.
    assert a(["(null)"] * 16, 16) == "[(null)] x 16"
    assert a(["0"] * 16, 20) == "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ... 4 more]"


def check_module_args():
    r = modinfo.rebuild_module_args
    names = ["rx_ring", "tx_ring", "debug", "lro"]
    # sfc on the RHEL 8.10 vmcore: 'rx_ring\04096\0tx_ring\02048...'.
    assert r(["rx_ring", "4096", "tx_ring", "2048"], names) == "rx_ring=4096 tx_ring=2048"
    # A flag with no value, followed by another argument.
    assert r(["debug", "lro", "0"], names) == "debug lro=0"
    # Something that can't be an argument name ends it: past the buffer.
    assert r(["rx_ring", "4096", "\x7f?!"], names) == "rx_ring=4096"
    assert r([], names) == ""


BT = """PID: 2102015  TASK: ffff8c4b9e7a8000  CPU: 1    COMMAND: "VMS 2026.08.27-"
 #0 [ffffb2a3c3e3b8d8] machine_kexec at ffffffff9b07a2b7
 #6 [ffffb2a3c3e3bb60] asm_exc_page_fault at ffffffff9bc00bc2
    [exception RIP: afsremove+0x6e5]
    RIP: ffffffffc0d90175  RSP: ffffb2a3c3e3bc18  RFLAGS: 00010246
    RAX: 0000000000000000  RBX: ffff8c4b0f6a7e00  RCX: 0000000000000000
 #7 [ffffb2a3c3e3bc70] afs_remove at ffffffffc0d90875 [openafs]
 #8 [ffffb2a3c3e3bcc0] afs_linux_unlink at ffffffffc0dcbce2 [openafs]
 #9 [ffffb2a3c3e3bd00] vfs_unlink at ffffffff9b3a3c6e

PID: 0        TASK: ffffffff9cc1a940  CPU: 0    COMMAND: "swapper/0"
 #0 [fffffe0000007e50] crash_nmi_callback at ffffffff9b06a2e3
PID: 0        TASK: ffff8c4a80250000  CPU: 2    COMMAND: "swapper/2"
 #0 [fffffe0000083e50] crash_nmi_callback at ffffffff9b06a2e3
    RIP: 00007f12c4a2b0d7  RSP: 00007ffd5bd0c1c8  RFLAGS: 00000246
"""


def check_backtrace_modules():
    frames = modinfo.parse_backtraces(BT)
    assert frames[0] == (2102015, "VMS 2026.08.27-", 1, "#0", "machine_kexec", 0xffffffff9b07a2b7)
    rip = [f for f in frames if f[3] == "RIP"]
    # The exception RIP is a frame, named from the '[exception RIP: ...]'
    # line; a user-space RIP with no such line is not.
    assert rip == [(2102015, "VMS 2026.08.27-", 1, "RIP", "afsremove+0x6e5", 0xffffffffc0d90175)]
    # The idle tasks are all PID 0: told apart by CPU.
    assert len(set((f[0], f[2]) for f in frames)) == 3

    ranges = [("openafs", 0xffffffffc0d4b000, 0xffffffffc10e8000),
              ("dm_mod", 0xffffffffc0500000, 0xffffffffc0540000)]
    found = modinfo.frames_by_module(frames, ranges)
    assert [name for name, _ in found] == ["openafs"]
    assert [f[4] for f in found[0][1]] == ["afsremove+0x6e5", "afs_remove", "afs_linux_unlink"]
    assert modinfo.frames_by_module(frames, []) == []


# The rest is the output of crash commands on the RHEL 8.10 vmcore.

TIMER = """JIFFIES
4759208567

TIMER_BASES[0][BASE_STD]: ffff959e80c22a40
  EXPIRES        TTE        TIMER_LIST     FUNCTION
  4759208564      -3  ffffa6a41c707700  ffffffff8ef94910  <process_timeout>
  4759209360     793  ffff9540f11146f8  ffffffff8ef18090  <delayed_work_timer_fn>
CPU: 0  HRTIMER_CPU_BASE: ffff959e80c24f40
  CLOCK: 0  HRTIMER_CLOCK_BASE: ffff959e80c24f80  [ktime_get]
      CURRENT
  464541271000000
    SOFTEXPIRES        EXPIRES            TTE           HRTIMER           FUNCTION
  464541268000000  464541268000000        -3000000  ffff959e80c25580  ffffffff8efa85f0  <tick_sched_timer>
"""


def check_parse_timers():
    assert modinfo.parse_timer_output(TIMER) == [
        (0xffffa6a41c707700, 0xffffffff8ef94910, -3),
        (0xffff9540f11146f8, 0xffffffff8ef18090, 793),
        (0xffff959e80c25580, 0xffffffff8efa85f0, -3000000),
    ]


def check_parse_irq_ps_percpu():
    irq = ''' IRQ   IRQ_DESC/_DATA      IRQACTION      NAME
  0   ffff9540c0067600  ffffffff908293c0  "timer"
  1   ffff9540c0065800      (unused)
 87   ffff9540d2a1c800  ffff9542292d1a00  "ens1f0-0"
'''
    assert modinfo.parse_irq_output(irq) == [(0, 0xffffffff908293c0),
                                             (87, 0xffff9542292d1a00)]
    ps = '''   PID    PPID  CPU       TASK        ST  %MEM      VSZ      RSS  COMM
      2       0  39  ffff9540cc834000  RU   0.0        0        0  [kthreadd]
>  1173       2  11  ffff95422a2b0000  IN   0.0        0        0  [xfsaild/dm-4]
'''
    assert modinfo.parse_ps_tasks(ps) == [(2, 0xffff9540cc834000, "[kthreadd]"),
                                          (1173, 0xffff95422a2b0000, "[xfsaild/dm-4]")]
    percpu = '''PER-CPU DATA TYPE:
  struct worker_pool cpu_worker_pools[2];
PER-CPU ADDRESSES:
  [0]: ffff959e80c2b000
  [1]: ffff959e80c6b000
'''
    assert modinfo.parse_percpu_addresses(percpu) == [0xffff959e80c2b000, 0xffff959e80c6b000]


def check_parse_kmem():
    kmem_v = '''   VMAP_AREA         VM_STRUCT                 ADDRESS RANGE                SIZE
ffff9540c0025c40  ffff9540c014a2c0  ffffa6a400000000 - ffffa6a400005000    20480
ffff9540c00251c0                    ffffa6a400005000 - ffffa6a400007000     8192
'''
    assert modinfo.parse_kmem_v(kmem_v) == [
        (0xffff9540c014a2c0, 0xffffa6a400000000, 0xffffa6a400005000, 20480),
        (0, 0xffffa6a400005000, 0xffffa6a400007000, 8192)]
    kmem_s = '''CACHE             OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE  NAME
ffff9540c00048c0      704          1        46      1    32k  onloadfs_inode_cache
'''
    assert modinfo.parse_kmem_s(kmem_s) == (704, 1, 46, 1, 32768)
    assert modinfo.parse_kmem_s("kmem: invalid cache") is None
    assert modinfo.size_with_unit("8k") == 8192 and modinfo.size_with_unit("2M") == 2 << 20
    assert modinfo.size_with_unit("4096") == 4096 and modinfo.size_with_unit("x") == 0


RANGES = [("sfc", 0xffffffffc066b000, 0xffffffffc0733000),
          ("(BPF: bpf_prog_6deef7357e7b4530_sd_fw_ingress)", 0xffffffffc0777000, 0xffffffffc0778000),
          ("(ftrace trampoline)", 0xffffffffc07e7000, 0xffffffffc07e8000)]
AREAS = [(0xffffffffc023c000, 0xffffffffc1225000)]


def check_classify_address():
    c = modinfo.classify_address
    assert c(0xffffffffc06763a0, RANGES, AREAS) == "sfc"
    # BPF JIT code and ftrace trampolines live in the module area too.
    assert c(0xffffffffc0777010, RANGES, AREAS).startswith("(BPF: ")
    assert c(0xffffffffc07e7000, RANGES, AREAS) == "(ftrace trampoline)"
    # Module area, nothing there now: what 958191513's RIP looked like.
    assert c(0xffffffffc0745ee4, RANGES, AREAS) == modinfo.UNLOADED
    assert c(0xffffffff8ef94910, RANGES, AREAS) is None
    assert c(0xffffffffc0745ee4, RANGES, []) is None


def check_hooks_grouping():
    hooks = [
        ("irq handler", 0xffffffffc06763a0, 'IRQ 87 "ens1f0-0"', 0xffff9542292d1a00),
        ("irq handler", 0xffffffffc06763a0, 'IRQ 88 "ens1f0-1"', 0xffff9542292d1b00),
        ("timer", 0xffffffff8ef94910, "timer_list 0xffffffffc0700100 in 3 jiffies", 0xffffffffc0700100),
        ("timer", 0xffffffff8ef94910, "timer_list 0xffff9540c0000000 in 3 jiffies", 0xffff9540c0000000),
        ("notifier", 0xffffffffc0745ee4, "netdev_chain, notifier_block 0x1", 0),
    ]
    found = modinfo.hooks_by_module(hooks, RANGES, AREAS)
    assert sorted(found) == [modinfo.UNLOADED, "sfc"]
    # A kernel function on a timer that is module data counts, marked so.
    assert ("timer", 0xffffffff8ef94910,
            "timer_list 0xffffffffc0700100 in 3 jiffies [object in sfc]") in found["sfc"]
    groups = modinfo.group_hooks(found["sfc"])
    assert groups[0] == ("irq handler", 0xffffffffc06763a0,
                         ['IRQ 87 "ens1f0-0"', 'IRQ 88 "ens1f0-1"'])
    assert len(groups) == 2

    frames = [(5230, "cribl", 6, "RIP", "unknown or invalid address", 0xffffffffc0745ee4),
              (1, "x", 0, "#3", "efx_poll", 0xffffffffc066b100)]
    # In the order first seen.
    assert [n for n, _ in modinfo.frames_by_module(frames, RANGES, AREAS)] == \
        [modinfo.UNLOADED, "sfc"]


LOG = """[    1.847807] sfc 0000:3b:00.0: Solarflare NIC detected: device 1924:0b03
[    1.888335] sfc 0000:3b:00.0 eth1: driverlink registering nic
[    1.900000] sfc_char: loaded
[    4.777686] [sfc efrm] 0000:3b:00.0 pci_dev=1924:0b03(1) type=1:C1 ifindex=3
[    5.753482] openafs: loading out-of-tree module taints kernel.
[    5.754065] openafs: module verification failed: signature and/or required key missing - tainting kernel
[  100.000000] sfc 0000:3b:00.0 ens1f0: link down
[  100.100000] sfc 0000:3b:00.0 ens1f0: link down
[  100.200000] sfc 0000:3b:00.0 ens1f0: link down
[495099.605149] RIP: 0010:afsremove+0x6e5/0x770 [openafs]
"""


def check_module_log():
    lines = modinfo.module_log_lines(LOG, "sfc")
    # 'sfc_char' is another module; '[sfc efrm]' is sfc.
    assert [l[2][:16] for l in lines] == ["sfc 0000:3b:00.0", "sfc 0000:3b:00.0",
                                          "[sfc efrm] 0000:", "sfc 0000:3b:00.0"], lines
    # The same message three times in a row is one line, x3.
    assert lines[-1] == ("100.000000", "", "sfc 0000:3b:00.0 ens1f0: link down", 3)

    afs = modinfo.module_log_lines(LOG, "openafs")
    assert [l[1] for l in afs] == ["taint", "taint", "error"]
    assert afs[0][0] == "5.753482"
    # Kernel log lines may spell the module with '-' for '_'.
    assert modinfo.module_log_lines("[1.0] dm-mod: hello\n", "dm_mod")[0][2] == "dm-mod: hello"


DIS = """0xffffffffc0d90000 <afsremove>:\tcall   0xffffffffa6e00000 <__fentry__>
0xffffffffc0d90005 <afsremove+0x5>:\tcall   0xffffffffa7123450 <__memcpy>
0xffffffffc0d9000a <afsremove+0xa>:\tcall   0xffffffffc0d95000 <afs_PutVCache>
0xffffffffc0d9000f <afsremove+0xf>:\tmov    0xffffffffa8000000(%rip),%rax        # 0xffffffffa8000000 <jiffies>
0xffffffffc0d90016 <afsremove+0x16>:\tjmp    0xffffffffa7001000 <srso_return_thunk>
0xffffffffc0d9001b <afs_remove>:\tcall   0xffffffffa7123450 <__memcpy>
0xffffffffc0d90020 <afs_remove+0x5>:\tcall   0xffffffffa7200000 <d_splice_alias+0x10>
"""


def check_kernel_refs_in_dis():
    inside = lambda addr: 0xffffffffc0d4b000 <= addr < 0xffffffffc10e8000
    refs = modinfo.kernel_refs_in_dis(DIS, inside)
    # Its own functions and compiler-emitted calls are left out.
    assert refs == {"__memcpy": {"afsremove", "afs_remove"}, "jiffies": {"afsremove"},
                    "d_splice_alias": {"afs_remove"}}, refs


def check_kabi_lists():
    import os
    import shutil
    import tempfile
    root = tempfile.mkdtemp()
    try:
        path = os.path.join(root, "kabi_stablelist_x86_64")
        with open(path, "w") as f:
            f.write("[rhel8_x86_64_stablelist]\n\tmemcpy\n\tjiffies\n# comment\n")
        assert modinfo.read_kabi_list(path) == {"memcpy", "jiffies"}
        d = os.path.join(root, "kabi_x86_64")
        os.makedirs(d)
        for name in ("memcpy", "d_splice_alias"):
            with open(os.path.join(d, name), "w") as f:
                f.write("#6-\n0x0a2e5f59\t%s\tvmlinux\tEXPORT_SYMBOL\n" % name)
        assert modinfo.read_kabi_list(d) == {"memcpy", "d_splice_alias"}
    finally:
        shutil.rmtree(root)

    c = modinfo.kabi_list_candidates("5.14.0-570.141.1.el9_6.x86_64", "x86_64", "/x",
                                     {"KABI_STABLELIST": "/y", "EDIS_SOURCE_DIR": "/src"})
    assert c[:3] == ["/x", "/y", "/lib/modules/kabi-rhel96/kabi_stablelist_x86_64"], c
    assert c[-1] == "/src/redhat/kabi/kabi-module/kabi_x86_64"

    # crash names memcpy's address __memcpy: the module meant memcpy.
    addrs = {"__memcpy": 0x10, "memcpy": 0x10, "__other": 0x20, "other": 0x30}
    assert modinfo.kabi_alias("__memcpy", {"memcpy"}, addrs.get) == "memcpy"
    assert modinfo.kabi_alias("__other", {"other"}, addrs.get) is None
    assert modinfo.kabi_alias("memcpy", {"memcpy"}, addrs.get) is None


def _elf(sections):
    """A minimal little-endian ELF64 file with these (name, type, bytes)
    sections and a .shstrtab."""
    import struct
    names = b"\0"
    offsets = []
    for name, _, _ in sections + [(".shstrtab", 3, b"")]:
        offsets.append(len(names))
        names = names + name.encode() + b"\0"
    body = b""
    placed = []
    data_start = 64
    for name, stype, data in sections:
        placed.append((data_start + len(body), len(data)))
        body = body + data
    placed.append((data_start + len(body), len(names)))
    body = body + names
    shoff = data_start + len(body)
    header = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    header = header + struct.pack("<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0,
                                  64, len(sections) + 2, len(sections) + 1)
    shdrs = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    types = [t for _, t, _ in sections] + [3]
    for (off, size), name_off, stype in zip(placed, offsets, types):
        shdrs = shdrs + struct.pack("<IIQQQQIIQQ", name_off, stype, 0, 0, off, size, 0, 0, 1, 0)
    return header + body + shdrs


def check_build_id_and_srcversion():
    import os
    import struct
    import tempfile
    build_id = bytes.fromhex("48951daf9dc8d4f792866e7d5d97054f31d6d3fb")
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
    assert modinfo.parse_build_id(note) == build_id.hex()
    assert modinfo.parse_build_id(struct.pack("<III", 4, 4, 1) + b"GNU\0abcd") is None

    modinfo_sec = b"license=GPL\0srcversion=EFBAAC855FA04AA13E16937\0vermagic=4.18.0\0"
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(_elf([(".note.gnu.build-id", 7, note), (".modinfo", 1, modinfo_sec)]))
        assert modinfo.elf_identity(path) == (build_id.hex(), "EFBAAC855FA04AA13E16937")
        # A .ko.debug: .modinfo is NOBITS there, so no srcversion.
        with open(path, "wb") as f:
            f.write(_elf([(".note.gnu.build-id", 7, note), (".modinfo", 8, b"")]))
        assert modinfo.elf_identity(path) == (build_id.hex(), None)
        with open(path, "wb") as f:
            f.write(b"not an elf file")
        assert modinfo.elf_identity(path) is None
    finally:
        os.remove(path)
    assert modinfo.elf_identity("/nonexistent/x.ko") is None


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
