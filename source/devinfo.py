"""
'devinfo' command: block and character devices, swiotlb, block requests,
storage status and paravirtual I/O rings.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump import Dev
from LinuxDump.block import *

import sys
import struct

import crashcolor
import pvring
import storstat


ULONG_MASK = 0xffffffffffffffff
MINORBITS = 20
IO_TLB_SHIFT = 11           # a swiotlb slot is 2 KiB
# Drivers whose targets are FC remote ports.
FC_DRIVERS = ("lpfc", "qla2xxx", "fnic", "qedf", "bfa", "zfcp", "bnx2fc")


def _atomic(v):
    try:
        return int(v.counter)
    except Exception:
        return int(v)


def _local(v):
    """local_t: an atomic_long_t in a struct."""
    try:
        return int(v.a.counter)
    except Exception:
        return _atomic(v)


def _size_text(nbytes):
    if nbytes is None:
        return "-"
    for unit in ("B", "K", "M", "G", "T"):
        if nbytes < 1024 or unit == "T":
            break
        nbytes /= 1024.0
    return "%d%s" % (nbytes, unit) if unit == "B" else "%.1f%s" % (nbytes,
                                                                     unit)


def _ranges(numbers):
    """[8, 65, 66, 67] -> '8,65-67'"""
    out = []
    for n in sorted(set(numbers)):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in out)


def _symbol(addr):
    try:
        return addr2sym(int(addr)) or ""
    except Exception:
        return ""


def _driver(gd):
    """The module that provides a disk's block_device_operations."""
    try:
        fops = int(gd.fops)
    except Exception:
        return "-"
    try:
        mod = addr2mod(fops)
        if mod:
            return str(mod)
    except Exception:
        pass
    return _symbol(fops) or "-"


def _print_colored(color, text, end="\n"):
    crashcolor.set_color(color)
    print(text, end=end)
    crashcolor.set_color(crashcolor.RESET)


def _age_color(age):
    if age is None or age < storstat.SLOW_SEC:
        return crashcolor.RESET
    return crashcolor.LIGHTRED if age >= storstat.STALL_SEC \
        else crashcolor.YELLOW


# ---------------------------------------------------------------------------
# Disks and their queues
# ---------------------------------------------------------------------------

def _class_devices(class_symbol):
    """'struct device' of every device of a class, such as block_class."""
    from LinuxDump.kobjects import klistAll, klistDevicesFromClass
    knode_in_device = member_offset("struct device", "knode_class") >= 0
    devs = []
    for knode in klistAll(klistDevicesFromClass(readSymbol(class_symbol))):
        try:
            if knode_in_device:
                devs.append(container_of(knode, "struct device",
                                         "knode_class"))
            else:
                devs.append(container_of(knode, "struct device_private",
                                         "knode_class").device)
        except Exception:
            continue
    return devs


_disks = []


def block_disks():
    """
    Every gendisk, by dev_t, from block_class with the partitions left out.
    bdev_map (RHEL7/8) and all_bdevs (RHEL7) are gone in RHEL9, and
    bdev_map is an xarray of block_devices in RHEL8.10; the class is in
    every release.
    """
    if _disks:
        return _disks
    disk_type = sym2addr("disk_type")
    has_hd_struct = struct_exists("struct hd_struct")
    for dev in _class_devices("block_class"):
        try:
            if int(dev.type) != disk_type:
                continue
            if has_hd_struct:
                part = container_of(dev, "struct hd_struct", "__dev")
                gd = container_of(part, "struct gendisk", "part0")
            else:
                gd = container_of(dev, "struct block_device",
                                  "bd_device").bd_disk
            _disks.append(gd)
        except Exception:
            continue
    _disks.sort(key=lambda gd: (int(gd.major), int(gd.first_minor)))
    return _disks


def disk_names():
    """
    request_queue address -> disk name; SCSI devices without a disk (tapes,
    changers, controllers, sg-only LUNs) get their [H:C:T:L].
    """
    names = {}
    try:
        from LinuxDump.scsi import get_scsi_devices, get_scsi_device_id
        for sdev in get_scsi_devices() or []:
            names[int(sdev.request_queue)] = "[%s]" % get_scsi_device_id(sdev)
    except Exception:
        pass
    for gd in block_disks():
        try:
            if gd.queue:
                names[int(gd.queue)] = str(gd.disk_name)
        except Exception:
            continue
    return names


def _disk_sectors(gd):
    try:
        if struct_exists("struct hd_struct"):
            return int(gd.part0.nr_sects)
        return int(gd.part0.bd_nr_sectors)
    except Exception:
        return None


def _bio_inflight(gd):
    """
    I/O in flight on a bio-based disk (dm, md, ...), which has no requests
    to look at: hd_struct.in_flight on RHEL7, the per-CPU disk_stats later.
    """
    try:
        if struct_exists("struct hd_struct"):
            part = gd.part0
            if member_offset("struct hd_struct", "in_flight") >= 0:
                return sum(_atomic(v) for v in part.in_flight)
            stats = int(part.dkstats)
        else:
            stats = int(gd.part0.bd_stats)
        from LinuxDump import percpu
        total = 0
        for cpu in range(sys_info.CPUS):
            ds = readSU("struct disk_stats", percpu.percpu_ptr(stats, cpu))
            total += sum(_local(v) for v in ds.in_flight)
        return total
    except Exception:
        return None


def _queue_kind(q):
    """mq (blk-mq), sq (legacy request_fn, RHEL7) or bio (dm, md, ...)."""
    try:
        if q.mq_ops:
            return "mq"
    except Exception:
        pass
    try:
        if q.request_fn:
            return "sq"
    except Exception:
        pass
    return "bio"


def _elevator(q):
    try:
        return str(q.elevator.type.elevator_name) if q.elevator else "none"
    except Exception:
        return "?"


HCTX_STATE_BITS = ("STOPPED", "TAG_ACTIVE", "SCHED_RESTART", "INACTIVE")


def _hctxs(q):
    out = []
    try:
        n = int(q.nr_hw_queues)
    except Exception:
        return out
    for i in range(n):
        try:
            hctx = get_mq_hw_ctx(q, i)
            if hctx:
                out.append(hctx)
        except Exception:
            continue
    return out


def _hctx_flags(hctx):
    try:
        state = int(hctx.state)
    except Exception:
        return []
    return [name for bit, name in enumerate(HCTX_STATE_BITS)
            if state & (1 << bit)]


def _hctx_dispatch(hctx):
    try:
        return len(readSUListFromHead(Addr(hctx.dispatch), "queuelist",
                                      "struct request", maxel=100000))
    except Exception:
        return 0


def _queue_stopped(q, kind=None):
    """Why a queue does not dispatch ('quiesced', ...), or ''."""
    kind = kind or _queue_kind(q)
    try:
        if member_offset("struct request_queue", "quiesce_depth") >= 0 \
                and int(q.quiesce_depth) > 0:
            return "quiesced"
    except Exception:
        pass
    if kind == "mq":
        stopped = [h for h in _hctxs(q) if "STOPPED" in _hctx_flags(h)]
        if stopped:
            return "%d hw queue(s) stopped" % len(stopped)
    elif kind == "sq":
        try:
            if int(q.queue_flags) & (1 << 2):       # QUEUE_FLAG_STOPPED
                return "stopped"
        except Exception:
            pass
    return ""


def _block_majors():
    """{name: [major, ...]} from the major_names hash chains."""
    majors = {}
    for head in readSymbol("major_names"):
        addr, n = int(head), 0
        while addr and n < 4096:
            bmn = readSU("struct blk_major_name", addr)
            majors.setdefault(str(bmn.name), []).append(int(bmn.major))
            addr, n = int(bmn.next), n + 1
    return majors


def show_blkdevs(options):
    majors = _block_majors()
    print("Block device majors")
    for name, nums in sorted(majors.items(), key=lambda e: min(e[1])):
        print("  %-16s %s" % (name, _ranges(nums)))

    disks = block_disks()
    print("\nDisks (%d)" % len(disks))
    print("  %-9s %-14s %8s %-14s %-4s %4s %-12s %-18s %-18s"
          % ("MAJ:MIN", "NAME", "SIZE", "DRIVER", "TYPE", "HWQ", "SCHED",
             "gendisk", "request_queue"))
    hz = get_hz()
    for gd in disks:
        q = gd.queue
        kind = _queue_kind(q) if q else "-"
        sectors = _disk_sectors(gd)
        hwq = "-"
        if kind == "mq":
            try:
                hwq = str(int(q.nr_hw_queues))
            except Exception:
                pass
        print("  %-9s %-14s %8s %-14s %-4s %4s %-12s 0x%-16x 0x%-16x"
              % ("%d:%d" % (int(gd.major), int(gd.first_minor)),
                 gd.disk_name, _size_text(sectors * 512 if sectors is not None
                                          else None),
                 _driver(gd)[:14], kind, hwq,
                 _elevator(q)[:12] if q and kind != "bio" else "-",
                 int(gd), int(q) if q else 0))
        if options.show_details and q:
            _show_queue_details(q, kind, gd, hz)


def _show_queue_details(q, kind, gd, hz):
    indent = " " * 12
    if kind == "bio":
        inflight = _bio_inflight(gd)
        print("%sbio-based, %s in flight" % (indent,
              "?" if inflight is None else inflight))
        return
    parts = []
    try:
        parts.append("nr_requests %d" % int(q.nr_requests))
        parts.append("timeout %ds" % (int(q.rq_timeout) // hz))
    except Exception:
        pass
    stopped = _queue_stopped(q, kind)
    if kind == "sq":
        try:
            parts.append("in driver %d (async %d, sync %d)"
                         % (int(q.in_flight[0]) + int(q.in_flight[1]),
                            int(q.in_flight[0]), int(q.in_flight[1])))
        except Exception:
            pass
        if stopped:
            parts.append(stopped)
        print("%s%s" % (indent, ", ".join(parts)))
        return
    hctxs = _hctxs(q)
    try:
        tags = hctxs[0].tags
        parts.append("tags %d (+%d reserved) per hw queue"
                     % (int(tags.nr_tags) - int(tags.nr_reserved_tags),
                        int(tags.nr_reserved_tags)))
    except Exception:
        pass
    if member_offset("struct request_queue", "quiesce_depth") >= 0:
        try:
            if int(q.quiesce_depth):
                parts.append("quiesced (depth %d)" % int(q.quiesce_depth))
        except Exception:
            pass
    print("%s%s" % (indent, ", ".join(parts)))
    for hctx in hctxs:
        flags = [f for f in _hctx_flags(hctx) if f != "TAG_ACTIVE"]
        dispatch = _hctx_dispatch(hctx)
        if flags or dispatch:
            print("%shctx %d 0x%x: %s%s" % (indent, int(hctx.queue_num),
                  int(hctx), " ".join(flags) or "-",
                  ", %d on the dispatch list" % dispatch if dispatch else ""))


def _cdev_probes():
    """[(major, first_minor, count, cdev)] registered with cdev_add()."""
    out = []
    try:
        cdev_map = readSymbol("cdev_map")
        for head in cdev_map.probes:
            p, n = head, 0
            while p and n < 4096:
                dev = int(p.dev)
                if p.data:
                    out.append((dev >> MINORBITS, dev & ((1 << MINORBITS) - 1),
                                int(p.range), int(p.data)))
                p, n = p.next, n + 1
    except Exception:
        pass
    return out


def show_chrdevs(options):
    probes = _cdev_probes()
    rows = []
    for head in readSymbol("chrdevs"):
        addr, n = int(head), 0
        while addr and n < 4096:
            cd = readSU("struct char_device_struct", addr)
            major, base, count = int(cd.major), int(cd.baseminor), \
                int(cd.minorct)
            cdev = int(cd.cdev) if cd.cdev else 0
            if not cdev:
                for pmajor, pminor, prange, pdata in probes:
                    if pmajor == major and base <= pminor < base + count:
                        cdev = pdata
                        break
            rows.append((major, base, count, str(cd.name), cdev))
            addr, n = int(cd.next), n + 1
    rows.sort()
    print("%5s  %-14s %-18s %-18s %s" % ("MAJOR", "MINORS", "NAME", "cdev",
                                         "OPERATIONS"))
    for major, base, count, name, cdev in rows:
        minors = str(base) if count <= 1 else "%d-%d" % (base, base + count - 1)
        ops = 0
        if cdev:
            try:
                ops = int(readSU("struct cdev", cdev).ops)
            except Exception:
                pass
        print("%5d  %-14s %-18s %-18s %s" % (
            major, minors, name, "0x%x" % cdev if cdev else "-",
            "0x%x <%s>" % (ops, _symbol(ops)) if ops else "-"))
    print("\ncdev '-': the driver registered the region but its cdev is not "
          "in cdev_map (no device node behind it yet, or a misc/tty-style "
          "driver that adds its own)")


# ---------------------------------------------------------------------------
# -i: swiotlb bounce buffers
# ---------------------------------------------------------------------------

def _used_runs(free_counts):
    """[(first, last)] of the slots whose free count is 0 (in use)."""
    runs, start = [], None
    for i, c in enumerate(free_counts):
        if c == 0 and start is None:
            start = i
        elif c != 0 and start is not None:
            runs.append((start, i - 1))
            start = None
    if start is not None:
        runs.append((start, len(free_counts) - 1))
    return runs


def _read_u32_field(addr, count, stride, offset):
    data = readmem(addr, count * stride)
    return [struct.unpack_from("<I", data, i * stride + offset)[0]
            for i in range(count)]


def _iotlb_pools():
    """
    [(label, nslabs, used, start, end, areas, slot_list)] for the swiotlb
    pools: io_tlb_default_mem (RHEL8.10, with a defpool in RHEL9 and later)
    or the io_tlb_* globals before it.  slot_list() reads each slot's free
    count, 0 for a slot in use.
    """
    pools = []
    if symbol_exists("io_tlb_default_mem"):
        mem = readSymbol("io_tlb_default_mem")
        pool = mem.defpool if member_offset("struct io_tlb_mem",
                                            "defpool") >= 0 else mem
        nslabs = int(pool.nslabs)
        areas = []
        try:
            nareas = int(pool.nareas)
            for a in readSUArray("struct io_tlb_area", int(pool.areas),
                                 nareas):
                areas.append((int(a.used), int(a.index)))
        except Exception:
            pass
        if areas:
            used = sum(a[0] for a in areas)
        elif member_offset("struct io_tlb_mem", "total_used") >= 0:
            used = _atomic(mem.total_used)
        else:
            used = int(mem.used)
        slot_size = struct_size("struct io_tlb_slot")
        list_off = member_offset("struct io_tlb_slot", "list")

        def slot_list(pool=pool, nslabs=nslabs):
            return _read_u32_field(int(pool.slots), nslabs, slot_size,
                                   list_off)
        pools.append(("io_tlb_default_mem", nslabs, used, int(pool.start),
                      int(pool.end), areas, slot_list,
                      bool(mem.force_bounce) if member_offset(
                          "struct io_tlb_mem", "force_bounce") >= 0 else None))
    elif symbol_exists("io_tlb_nslabs"):
        nslabs = int(readSymbol("io_tlb_nslabs"))
        lst = int(readSymbol("io_tlb_list")) if nslabs else 0

        def slot_list(lst=lst, nslabs=nslabs):
            return _read_u32_field(lst, nslabs, 4, 0)
        used = None
        if symbol_exists("io_tlb_used"):
            used = int(readSymbol("io_tlb_used"))
        elif lst:
            used = slot_list().count(0)
        areas = [(used, int(readSymbol("io_tlb_index")))] if lst else []
        pools.append(("io_tlb_list", nslabs, used,
                      int(readSymbol("io_tlb_start")),
                      int(readSymbol("io_tlb_end")), areas, slot_list, None))
    return pools


def show_iotlb(options):
    pools = _iotlb_pools()
    print("swiotlb (bounce buffers for DMA to memory a device cannot reach)")
    if not pools:
        print("  not in this kernel")
        return
    for label, nslabs, used, start, end, areas, slot_list, force in pools:
        if not nslabs:
            print("  not set up (%s has no slots): no device needed bounce "
                  "buffers, or swiotlb=noforce / an IOMMU is in use" % label)
            continue
        total = nslabs << IO_TLB_SHIFT
        print("  pool       %s, phys 0x%x-0x%x" % (label, start, end))
        print("  size       %s, %d slots of %d bytes" % (
            _size_text(total), nslabs, 1 << IO_TLB_SHIFT))
        if force is not None:
            print("  bounce     %s" % ("forced for every DMA (swiotlb=force or "
                                       "a confidential guest)" if force
                                       else "only where needed"))
        if used is None:
            print("  used       unknown")
            continue
        pct = 100.0 * used / nslabs
        text = "  used       %d slots, %s (%.1f%%)" % (
            used, _size_text(used << IO_TLB_SHIFT), pct)
        if pct >= 90:
            _print_colored(crashcolor.LIGHTRED, text + "  nearly full: expect "
                           "'swiotlb buffer is full' and failed DMA mappings")
        else:
            print(text)
        busy_areas = [(i, a[0]) for i, a in enumerate(areas) if a[0]]
        if len(areas) > 1:
            print("  areas      %d, %d in use%s" % (
                len(areas), len(busy_areas), ": " + " ".join(
                    "%d:%d" % a for a in busy_areas)
                if busy_areas and options.show_details else ""))
        if options.show_details:
            try:
                runs = _used_runs(slot_list())
            except Exception as e:
                print("  slots in use: not read (%s)" % e)
                continue
            print("\n  Slots in use (%d runs)" % len(runs))
            for first, last in runs:
                print("    %6d-%-6d %4d slots  phys 0x%x" % (
                    first, last, last - first + 1,
                    start + (first << IO_TLB_SHIFT)))


# ---------------------------------------------------------------------------
# -q: block requests
# ---------------------------------------------------------------------------

def _mono_now_ns():
    """CLOCK_MONOTONIC at the crash to within a tick, or None (RHEL7)."""
    try:
        tkr = readSymbol("tk_core").timekeeper.tkr_mono
        return int(tkr.base) + (int(tkr.xtime_nsec) >> int(tkr.shift))
    except Exception:
        return None


_op_info = {}


def _request_op(req):
    """READ, WRITE, FLUSH, DISCARD, DRV_IN, ... of a request."""
    try:
        flags = int(req.cmd_flags)
    except Exception:
        return "?"
    if not _op_info:
        # RHEL7.9 has an 'enum req_op' too, but its cmd_flags hold flag
        # bits and a cmd_type, not an op in the low bits.
        _op_info["legacy"] = member_offset("struct request", "cmd_type") >= 0
        for key, enum in (("ops", "enum req_op"), ("ops", "enum req_opf"),
                          ("bits", "enum rq_flag_bits"),
                          ("types", "enum rq_cmd_type_bits")):
            if _op_info.get(key) is None:
                try:
                    _op_info[key] = EnumInfo(enum)
                except Exception:
                    _op_info[key] = None
    if not _op_info["legacy"] and _op_info["ops"] is not None:
        try:
            return _op_info["ops"].getnam(flags & 0xff).replace("REQ_OP_", "")
        except Exception:
            return "OP%d" % (flags & 0xff)
    # RHEL7: passthrough is a cmd_type, and the op is in flag bits.
    try:
        name = _op_info["types"].getnam(int(req.cmd_type))
        if name != "REQ_TYPE_FS":
            return name.replace("REQ_TYPE_", "")
    except Exception:
        pass
    op = "WRITE" if flags & 1 else "READ"
    bits = _op_info["bits"]
    for flag, label in (("__REQ_DISCARD", "DISCARD"),
                        ("__REQ_WRITE_SAME", "WRITE_SAME"),
                        ("__REQ_FLUSH", "FLUSH")):
        try:
            if flags & (1 << int(bits[flag])):
                op = label if not (flags & 1 and label == "FLUSH") \
                    else "WRITE+FLUSH"
        except Exception:
            pass
    return op


def _request_ages(req, state, jiffies, hz, now_ns, start_in_jiffies):
    """
    (since allocation, since dispatch) in seconds, or None.  Dispatch is
    measured as pvio does, jiffies - (deadline - timeout); allocation from
    start_time in jiffies (RHEL7) or start_time_ns against CLOCK_MONOTONIC,
    which is 0 for passthrough requests and without iostats.
    """
    alloc = dispatch = None
    try:
        if start_in_jiffies:
            start = int(req.start_time)
            if start:
                alloc = ((jiffies - start) & ULONG_MASK) / float(hz)
        else:
            start = int(req.start_time_ns)
            if start and now_ns:
                alloc = (now_ns - start) / 1e9
    except Exception:
        pass
    if alloc is not None:
        if alloc > PV_AGE_LIMIT or alloc < -1:
            alloc = None
        else:
            alloc = max(alloc, 0.0)
    if state in ("active", "timeout", "softirq"):
        try:
            deadline, timeout = int(req.deadline), int(req.timeout)
            if deadline and timeout:
                age = ((jiffies - deadline + timeout) & ULONG_MASK) / float(hz)
                if age <= PV_AGE_LIMIT:
                    dispatch = age
        except Exception:
            pass
    return alloc, dispatch


def scan_requests(names):
    """
    Every request the block layer holds, except free ones, oldest first:
    dicts with the request, its queue and device name, pykdump's state
    (queued, active, timeout, softirq, flushq, unknown), op, sector, bytes,
    ages and hardware queue/tag.
    """
    try:
        jiffies, hz = int(readSymbol("jiffies")), get_hz()
    except Exception:
        return []
    now_ns = _mono_now_ns()
    start_in_jiffies = member_offset("struct request", "start_time") >= 0
    has_hctx = member_offset("struct request", "mq_hctx") >= 0
    try:
        queues = get_all_request_queues("")
    except Exception:
        queues = []
    seen, out = set(), []
    for q in queues:
        try:
            requests = get_queue_requests(q)
        except Exception:
            continue
        for req in requests:
            if int(req) in seen:
                continue
            seen.add(int(req))
            try:
                state = str(req._reqinfo_.state)
            except Exception:
                state = "unknown"
            if state == "free":
                continue
            try:
                qaddr = int(req.q)
            except Exception:
                qaddr = int(q)
            alloc, dispatch = _request_ages(req, state, jiffies, hz, now_ns,
                                            start_in_jiffies)
            r = {"req": int(req), "q": qaddr, "state": state,
                 "name": names.get(qaddr) or "0x%x" % qaddr,
                 "op": _request_op(req), "alloc": alloc,
                 "dispatch": dispatch, "sector": None, "bytes": None,
                 "hctx": None, "tag": None}
            try:
                r["sector"] = int(req.__sector)
                r["bytes"] = int(req.__data_len)
            except Exception:
                pass
            try:
                r["tag"] = int(req.tag)
                if has_hctx and req.mq_hctx:
                    r["hctx"] = int(req.mq_hctx.queue_num)
            except Exception:
                pass
            out.append(r)
    out.sort(key=lambda r: -1 if r["alloc"] is None else r["alloc"],
             reverse=True)
    return out


def _per_queue(requests):
    """request_queue address -> counts and the oldest ages of its requests."""
    agg = {}
    for r in requests:
        a = agg.setdefault(r["q"], {"held": 0, "queued": 0, "active": 0,
                                    "timeout": 0, "softirq": 0, "other": 0,
                                    "oldest": None, "oldest_queued": None,
                                    "oldest_alloc": None,
                                    "oldest_started_alloc": None,
                                    "oldest_done": None})
        a["held"] += 1
        state = r["state"] if r["state"] in ("queued", "active", "timeout",
                                             "softirq") else "other"
        a[state] += 1
        if r["dispatch"] is not None:
            if state in ("active", "timeout"):
                a["oldest"] = max(a["oldest"] or 0.0, r["dispatch"])
            elif state == "softirq":
                a["oldest_done"] = max(a["oldest_done"] or 0.0, r["dispatch"])
        if r["alloc"] is not None:
            a["oldest_alloc"] = max(a["oldest_alloc"] or 0.0, r["alloc"])
            if state == "queued":
                a["oldest_queued"] = max(a["oldest_queued"] or 0.0,
                                         r["alloc"])
            elif state in ("active", "timeout"):
                a["oldest_started_alloc"] = max(
                    a["oldest_started_alloc"] or 0.0, r["alloc"])
    return agg


def show_requests(options):
    names = disk_names()
    requests = scan_requests(names)
    if not requests:
        print("No block requests are queued or in flight")
        return
    print("Block requests, oldest first (ALLOCATED: since the request was "
          "allocated, DISPATCHED: since it was sent to the driver)")
    print("  %-18s %-10s %-8s %-11s %13s %7s %10s %10s%s"
          % ("REQUEST", "DEVICE", "STATE", "OP", "SECTOR", "SIZE",
             "ALLOCATED", "DISPATCHED", "  HWQ   TAG" if options.show_details
             else ""))
    for r in requests:
        age = r["dispatch"] if r["dispatch"] is not None else r["alloc"]
        line = "  0x%-16x %-10s %-8s %-11s %13s %7s %10s %10s" % (
            r["req"], r["name"][:10], r["state"], r["op"][:11],
            "-" if r["sector"] is None else r["sector"],
            _size_text(r["bytes"]) if r["bytes"] else "-",
            storstat.age_text(r["alloc"]), storstat.age_text(r["dispatch"]))
        if options.show_details:
            line += " %4s %5s" % ("-" if r["hctx"] is None else r["hctx"],
                                  "-" if r["tag"] is None else r["tag"])
        _print_colored(_age_color(age), line)

    agg = _per_queue(requests)
    print("\nPer device")
    print("  %-10s %5s %6s %6s %7s %7s %5s %10s %10s"
          % ("DEVICE", "HELD", "QUEUED", "ACTIVE", "TIMEOUT", "SOFTIRQ",
             "OTHER", "ALLOCATED", "DISPATCHED"))
    for qaddr, a in sorted(agg.items(), key=lambda e: names.get(e[0], "")):
        _print_colored(_age_color(a["oldest"]),
                       "  %-10s %5d %6d %6d %7d %7d %5d %10s %10s" % (
                           (names.get(qaddr) or "0x%x" % qaddr)[:10],
                           a["held"], a["queued"], a["active"], a["timeout"],
                           a["softirq"], a["other"],
                           storstat.age_text(a["oldest_alloc"]),
                           storstat.age_text(a["oldest"])))
    print("\nNotes")
    print("  - queued: waiting in the scheduler or for a driver tag; active: "
          "sent to the driver; timeout: its timer fired (SCSI error")
    print("    handling); softirq: completed by the device, waiting for the "
          "completion to be processed; flushq: in a flush sequence")
    print("  - DISPATCHED restarts when a driver resets the request timer or "
          "requeues it, so ALLOCATED can be much older")
    print("  - Per device, ALLOCATED and DISPATCHED are the oldest of each; "
          "%.0fs and more in yellow, %.0fs and more in red"
          % (storstat.SLOW_SEC, storstat.STALL_SEC))
    print("  - 'devinfo -s' tells whether a host or device is in error "
          "handling, offline or blocked")


# ---------------------------------------------------------------------------
# -s: storage status
# ---------------------------------------------------------------------------

def _task_state(task):
    try:
        if member_offset("struct task_struct", "__state") >= 0:
            state = int(task.__state)
        else:
            state = int(task.state)
    except Exception:
        return "?"
    if state == 0:
        return "RU"
    if state & 2:
        return "UN"
    if state & 1:
        return "IN"
    return "0x%x" % state


def _enum_name(enum, value):
    try:
        return enum.getnam(int(value)) if enum is not None else str(value)
    except Exception:
        return str(value)


def _enum(name):
    try:
        return EnumInfo(name)
    except Exception:
        return None


def _scsi_rows(names, agg):
    """
    ([host dict], [device dict]) for every SCSI host and device.  host_busy
    and device_busy are counters in RHEL7; from RHEL8 the host's busy count
    is the in-flight commands of its tag set and, from RHEL9, a device's is
    its budget_map, which is what scsi_host_busy() and scsi_device_busy()
    count.
    """
    try:
        import LinuxDump.scsi as ls
        shosts = list(ls.get_scsi_hosts() or [])
        sdevs = list(ls.get_scsi_devices() or [])
    except Exception:
        return [], []
    hz = get_hz()
    host_enum, sdev_enum = _enum("enum scsi_host_state"), \
        _enum("enum scsi_device_state")
    fc_enum = _enum("enum fc_port_state")
    host_counter = member_offset("struct Scsi_Host", "host_busy") >= 0
    dev_counter = member_offset("struct scsi_device", "device_busy") >= 0
    has_iotmo = member_offset("struct scsi_device", "iotmo_cnt") >= 0

    devices, inflight_cmds = [], {}
    for sdev in sdevs:
        try:
            q = int(sdev.request_queue)
            name = names.get(q, "-")
            d = {"addr": int(sdev), "host": int(sdev.host),
                 "id": ls.get_scsi_device_id(sdev),
                 "name": "-" if name.startswith("[") else name, "q": q,
                 "model": ("%s %s" % (str(sdev.vendor)[:8].strip(),
                                      str(sdev.model)[:16].strip())).strip(),
                 "state": _enum_name(sdev_enum, sdev.sdev_state),
                 "blocked": _atomic(sdev.device_blocked),
                 "ioreq": _atomic(sdev.iorequest_cnt),
                 "iodone": _atomic(sdev.iodone_cnt),
                 "ioerr": _atomic(sdev.ioerr_cnt),
                 "iotmo": _atomic(sdev.iotmo_cnt) if has_iotmo else None,
                 "timeout": None, "busy": None, "reqs": agg.get(q)}
        except Exception:
            continue
        try:
            d["timeout"] = int(sdev.request_queue.rq_timeout) // hz
        except Exception:
            pass
        try:
            d["busy"] = _atomic(sdev.device_busy) if dev_counter \
                else int(ls.get_scsi_device_busy(sdev))
        except Exception:
            pass
        if not host_counter:
            n = 0
            try:
                for cmd in ls.get_scsi_commands(sdev) or []:
                    if ls.test_bit(ls.SCMD_STATE_INFLIGHT, cmd.state):
                        n += 1
            except Exception:
                n = None
            prev = inflight_cmds.get(d["host"], 0)
            inflight_cmds[d["host"]] = None if prev is None or n is None \
                else prev + n
        devices.append(d)

    hosts = []
    for shost in shosts:
        try:
            h = {"addr": int(shost), "name": "host%d" % int(shost.host_no),
                 "driver": str(shost.hostt.proc_name),
                 "state": _enum_name(host_enum, shost.shost_state),
                 "failed": int(shost.host_failed),
                 "blocked": _atomic(shost.host_blocked),
                 "eh_scheduled": int(shost.host_eh_scheduled),
                 "can_queue": int(shost.can_queue), "eh": "-",
                 "devices": len([d for d in devices
                                 if d["host"] == int(shost)]),
                 "busy": _atomic(shost.host_busy) if host_counter
                 else inflight_cmds.get(int(shost), 0), "rports": []}
        except Exception:
            continue
        try:
            task = shost.ehandler
            if task:
                h["eh"] = "%s %s" % (str(task.comm), _task_state(task))
        except Exception:
            pass
        try:
            module = str(ls.get_hostt_module_name(shost)).strip()
        except Exception:
            module = h["driver"]
        if h["driver"] in ("", "None"):       # qla2xxx has no proc_name
            h["driver"] = module
        if module in FC_DRIVERS or h["driver"] in FC_DRIVERS:
            try:
                for starget in readSUListFromHead(shost.__targets, "siblings",
                                                  "struct scsi_target"):
                    try:
                        rport = ls.starget_to_rport(starget)
                        if not rport:
                            continue
                        h["rports"].append({
                            "name": str(starget.dev.kobj.name),
                            "addr": int(rport),
                            "state": _enum_name(fc_enum, rport.port_state),
                            "port_id": int(rport.port_id),
                            "dev_loss_tmo": int(rport.dev_loss_tmo),
                            "fast_io_fail_tmo": int(rport.fast_io_fail_tmo)})
                    except Exception:
                        continue
            except Exception:
                pass
        hosts.append(h)
    return hosts, devices


def _nvme_state(gd):
    """The NVMe controller state behind a namespace's disk, or None."""
    if not _symbol(gd.fops).startswith("nvme"):
        return None
    try:
        ns = readSU("struct nvme_ns", int(gd.private_data))
        return _enum_name(_enum("enum nvme_ctrl_state"), ns.ctrl.state)
    except Exception:
        return None


def _other_disk_rows(scsi_queues, agg):
    rows = []
    for gd in block_disks():
        try:
            q = gd.queue
            qaddr = int(q) if q else 0
        except Exception:
            continue
        if qaddr in scsi_queues:
            continue
        kind = _queue_kind(q) if q else "-"
        row = {"name": str(gd.disk_name), "driver": _driver(gd), "kind": kind,
               "q": qaddr, "reqs": agg.get(qaddr), "state": "-",
               "inflight": None, "stopped": ""}
        if kind == "bio":
            row["inflight"] = _bio_inflight(gd)
        else:
            a = row["reqs"]
            row["inflight"] = (a["active"] + a["timeout"]) if a else 0
            if a:
                row["stopped"] = _queue_stopped(q, kind)
        nvme = _nvme_state(gd)
        if nvme:
            row["state"] = nvme
        rows.append(row)
    return rows


def _queue_verdicts(a, timeout_sec, stopped):
    if not a:
        return []
    return storstat.queue_findings(
        a["active"] + a["timeout"], a["timeout"], a["oldest"], timeout_sec,
        stopped, a["held"], a["oldest_started_alloc"], a["softirq"],
        a["oldest_done"], a["queued"], a["oldest_queued"])


def show_status(options):
    """
    Storage status: SCSI hosts (state, busy, failed, blocked, error handler),
    SCSI devices (state, busy, blocked, request/done/error counts), FC
    remote ports, other disks (NVMe, virtio, dm, md, ...) and the requests
    each holds, with an answer on top: is a host in error handling, a device
    or path down, or I/O stuck, and where.
    """
    names = disk_names()
    agg = _per_queue(scan_requests(names))
    hosts, devices = _scsi_rows(names, agg)
    for d in devices:
        d["stopped"] = ""
        if d["reqs"]:
            try:
                d["stopped"] = _queue_stopped(readSU("struct request_queue",
                                                     d["q"]))
            except Exception:
                pass
    others = _other_disk_rows(set(d["q"] for d in devices), agg)

    findings = []          # (state, where, note)
    for h in hosts:
        where = "%s (%s)" % (h["name"], h["driver"])
        for state, note in storstat.host_findings(h["state"], h["busy"],
                                                  h["failed"], h["blocked"],
                                                  h["eh_scheduled"]):
            findings.append((state, where, note))
        for rp in h["rports"]:
            for state, note in storstat.rport_findings(rp["state"]):
                findings.append((state, "%s %s" % (h["name"], rp["name"]),
                                 "%s, dev_loss_tmo %s" % (
                                     note, _tmo_text(rp["dev_loss_tmo"]))))
    for d in devices:
        where = "%s [%s]" % (d["name"], d["id"]) if d["name"] != "-" \
            else "[%s]" % d["id"]
        for state, note in storstat.device_findings(d["state"], d["blocked"],
                                                    d["ioerr"], d["iotmo"]):
            findings.append((state, where, note))
        for state, note in _queue_verdicts(d["reqs"], d["timeout"],
                                           d["stopped"]):
            findings.append((state, where, note))
    for o in others:
        where = "%s (%s)" % (o["name"], o["driver"])
        for state, note in storstat.nvme_findings(o["state"]):
            findings.append((state, where, note))
        if o["kind"] == "bio":
            if o["inflight"]:
                findings.append(("BUSY", where, "%d I/O(s) in flight"
                                 % o["inflight"]))
        else:
            for state, note in _queue_verdicts(o["reqs"], None, o["stopped"]):
                findings.append((state, where, note))

    findings.sort(key=lambda f: storstat.STATES.index(f[0]))

    _print_colored(crashcolor.LIGHTCYAN, "Storage status\n==============")
    print("Answer : ", end="")
    problems = [f for f in findings if f[0] in storstat.PROBLEMS]
    if problems:
        for i, (state, where, note) in enumerate(problems[:20]):
            if i:
                print("         ", end="")
            _print_state(state, "%s: %s" % (where, note))
        if len(problems) > 20:
            print("         ... and %d more, see below" % (len(problems) - 20))
    elif not hosts and not others:
        print("no SCSI host or disk found in this dump")
    else:
        busy = [f for f in findings if f[0] == "BUSY"]
        _print_state("BUSY" if busy else "IDLE",
                     "no host in error handling, no device or path down, no "
                     "request older than %.0fs%s"
                     % (storstat.SLOW_SEC, "; %d device(s) with I/O in flight"
                        % len(busy) if busy else ""))
    errors = [f for f in findings if f[0] == "ERRORS SEEN"]
    if errors:
        print("         errors or timeouts since boot on %d device(s): %s" % (
            len(errors), ", ".join(f[1].split()[0] for f in errors[:8])
            + (", ..." if len(errors) > 8 else "")))

    if hosts:
        print("\nSCSI hosts")
        print("  %-8s %-12s %-22s %5s %6s %7s %3s %9s %5s  %s"
              % ("HOST", "DRIVER", "STATE", "BUSY", "FAILED", "BLOCKED", "EH",
                 "CAN_QUEUE", "DEVS", "EH THREAD"))
        for h in hosts:
            bad = storstat.host_findings(h["state"], h["busy"], h["failed"],
                                         h["blocked"], h["eh_scheduled"])
            _print_colored(_state_color(bad),
                           "  %-8s %-12s %-22s %5s %6d %7d %3d %9d %5d  %s" % (
                               h["name"], h["driver"][:12], h["state"],
                               "?" if h["busy"] is None else h["busy"],
                               h["failed"], h["blocked"], h["eh_scheduled"],
                               h["can_queue"], h["devices"], h["eh"]))
        rports = [(h, rp) for h in hosts for rp in h["rports"]
                  if options.show_details
                  or storstat.rport_findings(rp["state"])]
        if rports:
            print("\nFC remote ports%s" % ("" if options.show_details else
                                          " not online (-d lists all)"))
            print("  %-8s %-16s %-24s %-10s %12s %16s  %s"
                  % ("HOST", "TARGET", "STATE", "PORT_ID", "DEV_LOSS_TMO",
                     "FAST_IO_FAIL_TMO", "fc_rport"))
            for h, rp in rports:
                _print_colored(
                    _state_color(storstat.rport_findings(rp["state"])),
                    "  %-8s %-16s %-24s 0x%-8x %12s %16s  0x%x" % (
                        h["name"], rp["name"], rp["state"], rp["port_id"],
                        _tmo_text(rp["dev_loss_tmo"]),
                        _tmo_text(rp["fast_io_fail_tmo"]), rp["addr"]))

    if devices:
        shown = [d for d in devices if options.show_details or _sdev_notable(d)]
        print("\nSCSI devices (%s)" % (
            "%d" % len(devices) if len(shown) == len(devices) else
            "%d of %d; the others are SDEV_RUNNING, idle and error-free, "
            "-d lists all" % (len(shown), len(devices))))
        if shown:
            print("  %-9s %-12s %-22s %-22s %4s %3s %10s %10s %7s %5s %5s "
                  "%4s %4s %4s %4s %4s %8s"
                  % ("DEVICE", "H:C:T:L", "VENDOR/MODEL", "STATE", "BUSY",
                     "BLK", "IOREQ", "IODONE", "NOTDONE", "IOERR", "IOTMO",
                     "TMO", "REQS", "ACT", "TMOD", "DONE", "OLDEST"))
        for d in shown:
            a = d["reqs"] or {}
            bad = storstat.device_findings(d["state"], d["blocked"]) + \
                _queue_verdicts(d["reqs"], d["timeout"], d["stopped"])
            _print_colored(_state_color(bad),
                           "  %-9s %-12s %-22s %-22s %4s %3d %10d %10d %7d %5d "
                           "%5s %4s %4d %4d %4d %4d %8s" % (
                               d["name"][:9], d["id"][:12], d["model"][:22],
                               d["state"][:22],
                               "?" if d["busy"] is None else d["busy"],
                               d["blocked"], d["ioreq"], d["iodone"],
                               (d["ioreq"] - d["iodone"]) & 0xffffffff,
                               d["ioerr"],
                               "-" if d["iotmo"] is None else d["iotmo"],
                               "-" if d["timeout"] is None
                               else "%ds" % d["timeout"],
                               a.get("held", 0),
                               a.get("active", 0) + a.get("timeout", 0),
                               a.get("timeout", 0), a.get("softirq", 0),
                               storstat.age_text(a.get("oldest"))))

    shown = [o for o in others if options.show_details or o["inflight"]
             or o["reqs"] or o["state"] not in ("-", "NVME_CTRL_LIVE")]
    if others:
        print("\nOther disks (%s)" % (
            "%d" % len(others) if len(shown) == len(others) else
            "%d of %d; the others are idle, -d lists all"
            % (len(shown), len(others))))
    if shown:
        print("  %-12s %-14s %-4s %-22s %8s %4s %4s %8s  %s"
              % ("DISK", "DRIVER", "TYPE", "STATE", "INFLIGHT", "REQS", "TMOD",
                 "OLDEST", "QUEUE"))
        for o in shown:
            a = o["reqs"] or {}
            bad = storstat.nvme_findings(o["state"]) + \
                _queue_verdicts(o["reqs"], None, o["stopped"])
            _print_colored(_state_color(bad),
                           "  %-12s %-14s %-4s %-22s %8s %4d %4d %8s  %s" % (
                               o["name"][:12], o["driver"][:14], o["kind"],
                               o["state"][:22],
                               "?" if o["inflight"] is None else o["inflight"],
                               a.get("held", 0), a.get("timeout", 0),
                               storstat.age_text(a.get("oldest")),
                               o["stopped"] or "-"))

    print("\nNotes")
    print("  - BUSY: commands at the HBA (host) or LUN (device); FAILED: "
          "commands waiting for the error handler, which")
    print("    starts once FAILED equals BUSY; BLOCKED: the driver or device "
          "returned busy and dispatch is held back")
    print("  - NOTDONE: IOREQ - IODONE, which also counts every command the "
          "error handler aborted, so it is not an in-flight count")
    print("  - IOERR/IOTMO: errors and timeouts since boot; REQS/ACT/TMOD/"
          "DONE: block requests held, at the device, timed out,")
    print("    and completed by the device but not yet finished by the kernel")
    print("  - OLDEST: the oldest request at the device, from dispatch; "
          "%.0fs is slow, %.0fs or the device timeout (TMO) stalled"
          % (storstat.SLOW_SEC, storstat.STALL_SEC))
    print("  - 'devinfo -q' lists the requests, 'scsishow -c --time' the SCSI "
          "commands, 'devinfo -p' paravirtual rings")


def _tmo_text(sec):
    """FC transport timeouts: -1 is off, INT_MAX (multipath queueing) never."""
    if sec < 0 or sec >= 0xffffffff:
        return "off"
    return "never" if sec >= 0x7fffffff else "%ds" % sec


def _sdev_notable(d):
    return d["state"] != "SDEV_RUNNING" or d["busy"] or d["blocked"] or \
        d["ioerr"] or d["iotmo"] or d["reqs"]


def _state_color(findings):
    states = [f[0] for f in findings if f[0] in storstat.PROBLEMS]
    if not states:
        return crashcolor.RESET
    return crashcolor.LIGHTRED if storstat.STATES.index(
        storstat.worst(states)) < 4 else crashcolor.YELLOW


def _print_state(state, note):
    color = (crashcolor.LIGHTRED if state in storstat.PROBLEMS[:4]
             else crashcolor.YELLOW if state in storstat.PROBLEMS
             else crashcolor.RESET)
    crashcolor.set_color(color)
    print("%-15s" % state, end="")
    crashcolor.set_color(crashcolor.RESET)
    print(" %s" % note)


# ---------------------------------------------------------------------------
# --pvio: paravirtual I/O rings (virtio, VMware pvscsi, Hyper-V VMBus).
# The ring arithmetic and the verdicts live in pvring.py.
# ---------------------------------------------------------------------------

VIRTIO_IDS = {1: "net", 2: "block", 3: "console", 4: "rng", 5: "balloon",
              8: "scsi", 9: "9p", 26: "fs"}
VIRTIO_BLOCK, VIRTIO_SCSI = 2, 8
VIRTIO_F_VERSION_1 = 32
# Larger ages come from a request whose timer never started.
PV_AGE_LIMIT = 10 ** 6


def _pv_undecoded(what, module):
    return {"undecoded": "%s not decoded: load %s debuginfo with 'mod -s %s'"
                         % (what, module, module)}


def _pv_bus_devices(bus_symbol, bus_name):
    """
    'struct device' of every device on a bus, or None when the bus is not
    in the dump, or an _pv_undecoded() dict.  bus_type.p went away in RHEL
    9.5 and upstream 6.3; there the bus is found through bus_kset.
    """
    if not symbol_exists(bus_symbol):
        return None
    try:
        bus = readSymbol(bus_symbol)
    except Exception:
        return _pv_undecoded("the %s bus" % bus_name, bus_name)
    klist = None
    try:
        klist = bus.p.klist_devices
    except Exception:
        try:
            for kobj in readSUListFromHead(readSymbol("bus_kset").list, "entry",
                                           "struct kobject"):
                if str(kobj.name) == bus_name:
                    kset = container_of(kobj, "struct kset", "kobj")
                    klist = container_of(kset, "struct subsys_private",
                                         "subsys").klist_devices
                    break
        except Exception:
            klist = None
    if klist is None:
        return _pv_undecoded("the %s bus" % bus_name, bus_name)
    devs = []
    try:
        from LinuxDump.kobjects import klistAll
        knodes = klistAll(klist)
    except Exception:
        knodes = readSUListFromHead(klist.k_list, "n_node", "struct klist_node")
    for knode in knodes:
        try:
            devs.append(container_of(knode, "struct device_private",
                                     "knode_bus").device)
        except Exception:
            continue
    return devs


def _pv_queue_ages():
    """
    (ages, queuedata): request_queue address -> {'active', 'timeout',
    'softirq', 'unknown', 'oldest', 'hctx': {queue_num: oldest}}, and
    queue->queuedata -> queue address (virtio_blk sets it to its struct
    virtio_blk, which finds the disk without the module's debuginfo).

    The age is measured from dispatch, jiffies - (deadline - timeout): the
    timer the host has to beat.  start_time_ns is 0 for passthrough
    requests and, on RHEL8, without iostats, which would read as an age of
    the whole uptime.  'softirq' requests were completed by the device and
    wait for the guest's completion softirq.
    """
    ages, queuedata = {}, {}
    try:
        jiffies = int(readSymbol("jiffies"))
        hz = get_hz()
    except Exception:
        return ages, queuedata
    has_hctx = member_offset("struct request", "mq_hctx") >= 0
    try:
        queues = get_all_request_queues("")
    except Exception:
        queues = []
    for q in queues:
        try:
            if q.queuedata:
                queuedata[int(q.queuedata)] = int(q)
        except Exception:
            pass
        try:
            requests = get_queue_requests(q)
        except Exception:
            continue
        for req in requests:
            try:
                state = str(req._reqinfo_.state)
                qaddr = int(req.q)
            except Exception:
                continue
            if state not in ("active", "timeout", "softirq"):
                continue
            e = ages.setdefault(qaddr, {"active": 0, "timeout": 0,
                                        "softirq": 0, "unknown": 0,
                                        "oldest": None, "hctx": {}})
            e[state] += 1
            if state == "softirq":
                continue
            age = None
            try:
                deadline, timeout = int(req.deadline), int(req.timeout)
                if deadline and timeout:
                    age = ((jiffies - deadline + timeout) & 0xffffffffffffffff) \
                        / float(hz)
                    if age > PV_AGE_LIMIT:
                        age = None
            except Exception:
                age = None
            if age is None:
                e["unknown"] += 1
                continue
            if e["oldest"] is None or age > e["oldest"]:
                e["oldest"] = age
            if has_hctx:
                try:
                    n = int(req.mq_hctx.queue_num)
                    if age > e["hctx"].get(n, -1):
                        e["hctx"][n] = age
                except Exception:
                    pass
    return ages, queuedata


def _pv_merge_ages(ages, queues, hctx=None):
    """
    The ages of request queues merged; with hctx, only the requests of
    that hardware queue (virtio-blk maps hardware queue N to vq N).
    """
    out = {"active": 0, "timeout": 0, "softirq": 0, "unknown": 0,
           "oldest": None}
    for q in queues:
        e = ages.get(int(q))
        if not e:
            continue
        for k in ("active", "timeout", "softirq", "unknown"):
            out[k] += e[k]
        oldest = e["hctx"].get(hctx) if hctx is not None and e["hctx"] \
            else e["oldest"]
        if oldest is not None and (out["oldest"] is None
                                   or oldest > out["oldest"]):
            out["oldest"] = oldest
    return out


def _pv_shost_queues(shost):
    queues = []
    try:
        for sdev in readSUListFromHead(shost.__devices, "siblings",
                                       "struct scsi_device"):
            queues.append(int(sdev.request_queue))
            if len(queues) > 4096:
                break
    except Exception:
        pass
    return queues


def _pv_scsi_hosts():
    """[(shost, proc_name)]; pykdump knows the shost_class layouts."""
    hosts = []
    try:
        from LinuxDump.scsi import get_scsi_hosts
        for shost in get_scsi_hosts() or []:
            try:
                hosts.append((shost, str(shost.hostt.proc_name)))
            except Exception:
                continue
    except Exception:
        pass
    return hosts


def _pv_big_endian():
    try:
        for line in exec_crash_command("sys").splitlines():
            if line.strip().startswith("MACHINE:"):
                machine = line.split(":", 1)[1].split()[0]
                return machine.startswith("s390") or machine == "ppc64"
    except Exception:
        pass
    return False


def _pv_virtio_rows(ages, queuedata):
    """Rows for every virtqueue, or None when virtio is not in the dump."""
    devs = _pv_bus_devices("virtio_bus", "virtio")
    if devs is None or isinstance(devs, dict):
        return devs if devs is None else [devs]
    rows = []
    vdev_off = member_offset("struct virtio_device", "dev")
    vq_off = member_offset("struct vring_virtqueue", "vq")
    has_split = member_offset("struct vring_virtqueue", "split") >= 0
    has_packed = member_offset("struct vring_virtqueue", "packed_ring") >= 0
    has_layout = member_offset("struct vring_virtqueue", "layout") >= 0
    big_endian = _pv_big_endian()
    for dev in devs:
        try:
            vdev = readSU("struct virtio_device", int(dev) - vdev_off)
            dev_id = int(vdev.id.device)
            name = str(dev.kobj.name)
            driver = str(dev.driver.name) if dev.driver else "-"
        except Exception:
            continue
        # VIRTIO 1.0 rings are little-endian; legacy ones are guest-endian.
        swap = False
        try:
            swap = big_endian and bool((int(vdev.features)
                                        >> VIRTIO_F_VERSION_1) & 1)
        except Exception:
            pass
        disk, queues = "", []
        try:
            if dev_id == VIRTIO_BLOCK:
                qaddr = queuedata.get(int(vdev.priv))
                if qaddr:
                    queues = [qaddr]
                    try:
                        import LinuxDump.block as lb
                        disk = str(lb.rq_names.get(qaddr, ""))
                    except Exception:
                        pass
            elif dev_id == VIRTIO_SCSI:
                shost = readSU("struct Scsi_Host", int(vdev.priv))
                disk = "host%d" % int(shost.host_no)
                queues = _pv_shost_queues(shost)
        except Exception:
            pass
        try:
            vqs = list(readSUListFromHead(vdev.vqs, "list", "struct virtqueue"))
        except Exception:
            vqs = []
        for vq in vqs:
            row = {"dev": name, "driver": driver, "disk": disk,
                   "kind": VIRTIO_IDS.get(dev_id, str(dev_id)),
                   "queue": "?", "num": -1, "avail": -1, "used": -1,
                   "last_used": -1, "counts": None, "age": None,
                   "state": "NOT DECODED", "note": "",
                   "addr": int(vq) - vq_off if vq_off >= 0 else None,
                   "vq": int(vq)}
            try:
                row["queue"] = str(vq.name)
                if dev_id == VIRTIO_BLOCK and queues:
                    row["age"] = _pv_merge_ages(ages, queues, int(vq.index))
                elif queues:
                    row["age"] = _pv_merge_ages(ages, queues)
            except Exception:
                pass
            try:
                if vq_off < 0:
                    raise KeyError("struct vring_virtqueue")
                vvq = readSU("struct vring_virtqueue", int(vq) - vq_off)
                if (has_packed and bool(vvq.packed_ring)) or \
                        (has_layout and int(vvq.layout) in (1, 3)):
                    row["note"] = "packed ring; not decoded"
                    rows.append(row)
                    continue
                vring = vvq.split.vring if has_split else vvq.vring
                avail, used = int(vring.avail.idx), int(vring.used.idx)
                if swap:
                    avail, used = pvring.swap16(avail), pvring.swap16(used)
                row["num"] = int(vring.num)
                row["avail"], row["used"] = avail, used
                row["last_used"] = int(vvq.last_used_idx) & 0xffff
                row["counts"] = pvring.virtio_split(
                    avail, used, row["last_used"], int(vvq.num_added))
                row["state"], row["note"] = pvring.verdict(
                    row["counts"], row["age"]["oldest"] if row["age"] else None,
                    broken=bool(vvq.broken),
                    request_queue=pvring.is_request_queue(row["queue"]),
                    polled=row["queue"].startswith("req_poll"))
            except Exception:
                row["note"] = ("not decoded: load virtio_ring debuginfo with "
                               "'mod -s virtio_ring' (built in on most RHEL8/9)")
            rows.append(row)
    return rows


def _pv_pvscsi_rows(ages, hosts):
    rows = []
    hostdata_off = member_offset("struct Scsi_Host", "hostdata")
    for shost, proc_name in hosts:
        if proc_name != "vmw_pvscsi":
            continue
        row = {"host": "host%d" % int(shost.host_no), "rs": None,
               "counts": None, "age": _pv_merge_ages(ages, _pv_shost_queues(shost)),
               "state": "NOT DECODED", "note": "", "addr": 0}
        try:
            adapter = readSU("struct pvscsi_adapter",
                             int(shost) + hostdata_off)
            rs = adapter.rings_state
            row["addr"] = int(rs)
            row["rs"] = (int(rs.reqProdIdx), int(rs.reqConsIdx),
                         int(rs.cmpProdIdx), int(rs.cmpConsIdx),
                         int(rs.reqCallThreshold))
            row["counts"] = pvring.pvscsi(*row["rs"][:4])
            row["state"], row["note"] = pvring.verdict(row["counts"],
                                                       row["age"]["oldest"])
        except Exception:
            row["note"] = ("not decoded: load vmw_pvscsi debuginfo with "
                           "'mod -s vmw_pvscsi'")
        rows.append(row)
    return rows


def _pv_vmbus_rows(ages):
    """
    Rows for every VMBus channel, or None when VMBus is not in the dump.

    The host reads a storvsc request off the outbound ring as soon as it
    arrives and keeps it until it sends the completion, so a stalled backend
    leaves both rings empty: the requests the host holds are the device's
    num_outstanding_req (for all its channels), shown on the primary channel.
    Outbound bytes are only what the host has not read yet.
    """
    if not symbol_exists("vmbus_connection"):
        return None
    try:
        primaries = list(readSUListFromHead(readSymbol("vmbus_connection").chn_list,
                                            "listentry", "struct vmbus_channel"))
    except Exception:
        return [_pv_undecoded("VMBus", "hv_vmbus")]
    rows = []
    for primary in primaries:
        try:
            subs = list(readSUListFromHead(primary.sc_list, "sc_list",
                                           "struct vmbus_channel"))
        except Exception:
            subs = []
        driver, age, outstanding, note = "-", None, None, ""
        try:
            hv_dev = primary.device_obj
            if hv_dev and hv_dev.device.driver:
                driver = str(hv_dev.device.driver.name)
            if driver == "hv_storvsc":
                stor = readSU("struct storvsc_device",
                              int(hv_dev.device.driver_data))
                outstanding = int(stor.num_outstanding_req.counter)
                age = _pv_merge_ages(ages, _pv_shost_queues(stor.host))
        except Exception:
            if driver == "hv_storvsc":
                note = ("requests at the host not decoded: load hv_storvsc "
                        "debuginfo with 'mod -s hv_storvsc'")
        for index, ch in enumerate([primary] + subs):
            row = {"driver": driver, "sub": index, "addr": int(ch),
                   "out": None, "in": None, "mask": -1, "counts": None,
                   "outstanding": outstanding if index == 0 else None,
                   "age": age, "state": "NOT DECODED", "note": note}
            try:
                o, i = ch.outbound, ch.inbound
                row["out"] = (int(o.ring_buffer.write_index),
                              int(o.ring_buffer.read_index),
                              int(o.ring_datasize))
                row["in"] = (int(i.ring_buffer.write_index),
                             int(i.ring_buffer.read_index),
                             int(i.ring_datasize))
                row["mask"] = int(i.ring_buffer.interrupt_mask)
                row["counts"] = pvring.vmbus(*(row["out"] + row["in"]))
                counts = {"host": 0, "guest": row["counts"]["guest"], "kick": 0}
                if index == 0 and outstanding is not None:
                    counts["host"] = outstanding
                oldest = age["oldest"] if age else None
                if bool(ch.rescind):
                    row["state"], row["note"] = "BROKEN", "channel rescinded"
                elif driver == "hv_storvsc":
                    row["state"], row["note"] = pvring.verdict(
                        counts, oldest, guest_unit="byte(s)")
                    if note:
                        row["note"] = note
                else:
                    row["state"] = "IDLE" if not any(row["counts"].values()) \
                        else "IN FLIGHT"
                    row["note"] = ""
            except Exception:
                row["note"] = ("ring not decoded: load hv_vmbus debuginfo "
                               "with 'mod -s hv_vmbus'")
            rows.append(row)
    return rows


def _pv_print_state(state, note):
    color = (crashcolor.LIGHTRED if state in pvring.PROBLEMS[:3]
             else crashcolor.YELLOW if state in pvring.PROBLEMS
             else crashcolor.RESET)
    crashcolor.set_color(color)
    print("%-20s" % state, end="")
    crashcolor.set_color(crashcolor.RESET)
    print(" %s" % note)


def _pv_age_cols(age):
    if not age:
        return "%8s %4s %4s" % ("-", "-", "-")
    return "%8s %4d %4d" % (pvring.age_text(age["oldest"]),
                            age["active"] + age["timeout"], age["timeout"])


def show_pvio(options):
    """
    Paravirtual I/O rings: requests the guest posted that the host has not
    completed, completions the guest has not processed, and the age of the
    oldest request the device holds, for virtio, VMware pvscsi and Hyper-V
    VMBus (storvsc, netvsc).  Answers whether stalled I/O is the host's or
    the guest's side.
    """
    ages, queuedata = _pv_queue_ages()
    hosts = _pv_scsi_hosts()
    virtio = _pv_virtio_rows(ages, queuedata)
    pvscsi_rows = _pv_pvscsi_rows(ages, hosts)
    vmbus = _pv_vmbus_rows(ages)

    undecoded = [r["undecoded"] for r in (virtio or []) + (vmbus or [])
                 if "undecoded" in r]
    virtio = [r for r in virtio or [] if "undecoded" not in r] \
        if virtio is not None else None
    vmbus = [r for r in vmbus or [] if "undecoded" not in r] \
        if vmbus is not None else None

    findings = []
    for r in virtio or []:
        findings.append((r["state"], "%s (%s%s) %s" % (
            r["dev"], r["driver"], " " + r["disk"] if r["disk"] else "",
            r["queue"]), r["note"], r["age"]))
    for r in pvscsi_rows:
        findings.append((r["state"], "%s (vmw_pvscsi)" % r["host"], r["note"],
                         r["age"]))
    for r in vmbus or []:
        findings.append((r["state"], "VMBus %s channel %d" % (r["driver"],
                                                             r["sub"]),
                         r["note"], r["age"]))
    answer = pvring.worst([f[0] for f in findings])
    not_decoded = len([f for f in findings if f[0] == "NOT DECODED"]) \
        + len(undecoded)
    no_age = len([f for f in findings if f[0] == "IN FLIGHT"
                  and (not f[3] or f[3]["oldest"] is None)])

    crashcolor.set_color(crashcolor.LIGHTCYAN)
    print("Paravirtual I/O rings")
    print("=====================")
    crashcolor.set_color(crashcolor.RESET)
    print("Answer : ", end="")
    if answer in pvring.PROBLEMS:
        problems = [f for f in findings if f[0] == answer]
        _pv_print_state(answer, "%s: %s" % (problems[0][1], problems[0][2]))
        for state, where, note, age in findings:
            if state in pvring.PROBLEMS and (where, note) != \
                    (problems[0][1], problems[0][2]):
                print("         %-20s %s: %s" % (state, where, note))
    elif not findings and not undecoded:
        print("no virtio, pvscsi or VMBus device in this dump")
    elif not [f for f in findings if f[0] != "NOT DECODED"]:
        _pv_print_state("NOT DECODED", "no ring could be read; see below")
    else:
        text = "no decoded ring holds an aged request"
        gaps = []
        if not_decoded:
            gaps.append("%d not decoded" % not_decoded)
        if no_age:
            gaps.append("%d in flight with no request age" % no_age)
        print("%s  %s%s" % (answer, text,
                            " (%s)" % ", ".join(gaps) if gaps else ""))
    for text in undecoded:
        print("         %s" % text)

    if virtio:
        print("\nvirtio (split ring: AVAIL posted by the guest, USED completed "
              "by the host, LAST guest has processed up to)")
        print("  %-9s %-12s %-6s %-10s %5s %6s %6s %6s %5s %5s %4s %8s %4s %4s  %s"
              % ("DEVICE", "DRIVER", "DISK", "QUEUE", "SIZE", "AVAIL", "USED",
                 "LAST", "HOST", "GUEST", "KICK", "OLDEST", "REQS", "TMO",
                 "STATE"))
        for r in virtio:
            if r["counts"] is None:
                print("  %-9s %-12s %-6s %-10s  %s"
                      % (r["dev"], r["driver"][:12], r["disk"][:6],
                         r["queue"][:10], r["note"]))
                continue
            c = r["counts"]
            print("  %-9s %-12s %-6s %-10s %5d %6d %6d %6d %5d %5d %4d %s  "
                  % (r["dev"], r["driver"][:12], r["disk"][:6], r["queue"][:10],
                     r["num"], r["avail"], r["used"], r["last_used"],
                     c["host"], c["guest"], c["kick"], _pv_age_cols(r["age"])),
                  end="")
            _pv_print_state(r["state"], "" if r["state"] in ("IDLE", "n/a")
                            else r["note"])
    if pvscsi_rows:
        print("\nVMware pvscsi (rings_state: REQ produced by the guest and "
              "consumed by the host, CMP the other way)")
        print("  %-7s %10s %10s %10s %10s %4s %5s %8s %5s %8s %4s %4s  %s"
              % ("HOST", "REQ_PROD", "REQ_CONS", "CMP_PROD", "CMP_CONS",
                 "THR", "HOST", "NOTTAKEN", "GUEST", "OLDEST", "REQS", "TMO",
                 "STATE"))
        for r in pvscsi_rows:
            if not r["rs"]:
                print("  %-7s %s" % (r["host"], r["note"]))
                continue
            c = r["counts"]
            print("  %-7s %10d %10d %10d %10d %4d %5d %8d %5d %s  "
                  % ((r["host"],) + r["rs"] + (c["host"], c["not_taken"],
                                                c["guest"],
                                                _pv_age_cols(r["age"]))),
                  end="")
            _pv_print_state(r["state"], "" if r["state"] == "IDLE"
                            else r["note"])
    if vmbus:
        print("\nHyper-V VMBus (OUT guest->host, IN host->guest, in bytes; "
              "OUTST requests the host holds; MASK=1: guest draining IN)")
        print("  %-12s %3s %10s %10s %7s %10s %10s %7s %4s %5s %8s %4s %4s  %s"
              % ("DRIVER", "SUB", "OUT_WRITE", "OUT_READ", "UNREAD",
                 "IN_WRITE", "IN_READ", "PENDING", "MASK", "OUTST", "OLDEST",
                 "REQS", "TMO", "STATE"))
        for r in vmbus:
            if not r["out"]:
                print("  %-12s %3d %s" % (r["driver"][:12], r["sub"], r["note"]))
                continue
            c = r["counts"]
            print("  %-12s %3d %10d %10d %7d %10d %10d %7d %4d %5s %s  "
                  % (r["driver"][:12], r["sub"], r["out"][0], r["out"][1],
                     c["host"], r["in"][0], r["in"][1], c["guest"], r["mask"],
                     "-" if r["outstanding"] is None else str(r["outstanding"]),
                     _pv_age_cols(r["age"])), end="")
            _pv_print_state(r["state"], "" if r["state"] in ("IDLE", "IN FLIGHT")
                            else r["note"])

    print("\nNotes")
    print("  - OLDEST/REQS/TMO: the oldest block request the device holds, "
          "aged from dispatch (jiffies - deadline + timeout),")
    print("    how many it holds ('active' or 'timeout') and how many timed "
          "out; per queue for virtio-blk, per device otherwise")
    print("  - HOST SLOW at %.0fs, HOST STALLED at %.0fs; when both sides hold "
          "entries the host is named; receive and event queues are not judged"
          % (pvring.SLOW_SEC, pvring.STALL_SEC))
    if pvscsi_rows:
        print("  - pvscsi NOTTAKEN: posted but not yet picked up by the "
              "device, which may wait for THR requests before looking")
    if options.show_details:
        print("\nStructures (-d)")
        for r in virtio or []:
            if r["addr"] is not None:
                print("  struct vring_virtqueue 0x%x   # %s %s"
                      % (r["addr"], r["dev"], r["queue"]))
            else:
                print("  struct virtqueue 0x%x   # %s %s (vring_virtqueue "
                      "unknown)" % (r["vq"], r["dev"], r["queue"]))
        for r in pvscsi_rows:
            if r["addr"]:
                print("  struct PVSCSIRingsState 0x%x   # %s"
                      % (r["addr"], r["host"]))
        for r in vmbus or []:
            print("  struct vmbus_channel.outbound,inbound 0x%x   # %s %d"
                  % (r["addr"], r["driver"], r["sub"]))


def devinfo():
    op = OptionParser()
    op.add_option("-b", "--block",
                  action="store_true",
                  dest="show_block",
                  default=False,
                  help="Block device majors and every disk: size, driver, "
                       "queue type, hardware queues, scheduler (-d adds "
                       "queue limits and stopped hardware queues)")

    op.add_option("-c", "--char",
                  action="store_true",
                  dest="show_char",
                  default=False,
                  help="Character device regions and their operations")

    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show detailed information")

    op.add_option("-i", "--iotlb", dest="show_iotlb", default=False,
                  action="store_true",
                  help="swiotlb bounce buffers: size and use (-d lists the "
                       "slots in use)")

    op.add_option("-q", "--requests", dest="show_requests", default=False,
                  action="store_true",
                  help="Block requests queued or in flight, oldest first, "
                       "and per device (-d adds hardware queue and tag)")

    op.add_option("-s", "--status", dest="show_status", default=False,
                  action="store_true",
                  help="Storage status: SCSI host and device state, busy, "
                       "failed, blocked and error counts, FC remote ports, "
                       "and requests held per disk, on every RHEL release "
                       "(-d lists idle devices too)")

    op.add_option("-p", "--pvio", dest="show_pvio", default=False,
                  action="store_true",
                  help="Paravirtual I/O rings (virtio, pvscsi, Hyper-V "
                       "VMBus): requests the host has not completed and "
                       "completions the guest has not processed")

    (o, args) = op.parse_args()

    if not (o.show_block or o.show_char or o.show_iotlb or o.show_requests
            or o.show_status or o.show_pvio):
        op.print_help()
        return

    if o.show_status:
        show_status(o)

    if o.show_block:
        show_blkdevs(o)

    if o.show_char:
        show_chrdevs(o)

    if o.show_iotlb:
        show_iotlb(o)

    if o.show_requests:
        show_requests(o)

    if o.show_pvio:
        show_pvio(o)


if ( __name__ == '__main__'):
    devinfo()
