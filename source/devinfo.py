"""
'devinfo' command: block/char device, IOMMU and request information.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump import Dev
from LinuxDump.block import *

import sys
import operator

import crashcolor
import pvring

def decode_devt(dev):
    if (dev >>16):
        # New-style
        major = dev >> 20
        minor = dev ^ (major<<20)
    else:
        # Old-style
        major = dev >>8
        minor = dev & 0xff
    return (int(major), int(minor))


def show_blkdevs_details(options, gendisk):
    request_queue = gendisk.queue
    nr_hw_queues = request_queue.nr_hw_queues
    print("\tnr_hw_queues : %d" % (nr_hw_queues))
    for idx in range(0, nr_hw_queues):
       blk_mq_hw_ctx = request_queue.queue_hw_ctx[idx]
       blk_mq_tags = blk_mq_hw_ctx.tags
       print("\t\tqueue_hw_ctx[%d].tags.nr_tags = %d" % (idx, blk_mq_tags.nr_tags))

    pass


def show_blkdevs(options):
    pa = readSymbol('major_names')
    print ("BLKDEV        NAME")
    for major, s in enumerate(pa):
        if (s == 0):
            continue

        name = s.name
        print (" %3d     %-15s" %  (major, name))

    if symbol_exists("bdev_map"):
        # It doesn't problematic case the blkext device with minor 0
        # does not get added to the bdev_map. Red Hat BZ#1739140
        # Thanks John Pittman for share this info.
        dev_len = len(pa)
        bdev_map = readSymbol("bdev_map")
        print("%5s:%5s(%5s)%-17s  %-18s %-18s" %
              ("MAJOR", "MINOR", "COUNT", " NAME", "gendisk", "request_queue"))
        for i in range(0, dev_len):
            addr = pa[i]
            if addr == 0:
                continue
            blk_major_name = readSU("struct blk_major_name", addr)
            major = blk_major_name.major
            probe = bdev_map.probes[major if i == major else i]
            probe_list = []
            while probe:
                major, minor = decode_devt(probe.dev)
                if major == 0:
                    break
                if probe.data == 0:
                    break
                probe_list.append(probe)
                probe = probe.next

            for i in range(len(probe_list) - 1, -1, -1):
                probe = probe_list[i]
                major, minor = decode_devt(probe.dev)
                gendisk_addr = probe.data
                gendisk = readSU('struct gendisk', gendisk_addr)
                if (gendisk == 0):
                    break

                name = gendisk.disk_name
                print ("%5d:%5d(%5d) %-17s 0x%16x 0x%16x" %
                       (major, minor, gendisk.minors, name, gendisk, gendisk.queue))

                show_blkdevs_details(options, gendisk)

    elif (symbol_exists('all_bdevs')):
        print("%5s:%5s(%5s)%-17s  %-18s %-18s" %
              ("MAJOR", "MINOR", "COUNT", " NAME", "gendisk", "request_queue"))
        for bd in readSUListFromHead(sym2addr('all_bdevs'),
                                     'bd_list', 'struct block_device'):
            major, minor = decode_devt(bd.bd_dev)
            gendisk_addr = bd.bd_disk
            gendisk = readSU('struct gendisk', gendisk_addr)
            name = ""
            if (gendisk == 0):
                continue

            name = gendisk.disk_name
            print ("%5d:%5d(%5d) %-17s 0x%16x 0x%16x" %
                   (major, minor, gendisk.minors, name, gendisk, gendisk.queue))
            print ("  %3d:%3d     %-10s" % (major, minor, name))

            show_blkdevs_details(options, gendisk)


def show_chrdevs():
    pa = readSymbol('chrdevs');
    print ('CHRDEV     NAME            OPERATIONS')

    if (struct_exists('char_device_struct')):
        for addr in pa:
            while (addr):
                s = readSU('struct char_device_struct', addr)
                major = s.major
                name = s.name
                addr = s.next
                print ("%3d      %-15s" %(major, name))
    else:
        for major, s in enumerate(pa):
            if (s == 0):
                continue
            cdev_addr = s.cdev
            ops = 0
            if (cdev_addr != 0):
                cdev = readSU('struct cdev', cdev_addr)
                ops = cdev.ops
            name = s.name
            print (" %3d     %-15s   0x%016x  <%s>" % \
                   (major, name, ops, addr2sym(ops)))


def show_iotlb(options):
    io_tlb_list = readSymbol("io_tlb_list")
    io_tlb_nslabs = readSymbol("io_tlb_nslabs")
    io_tlb_used = readSymbol("io_tlb_used")
    io_tlb_index = readSymbol("io_tlb_index")
    print("io_tlb_list = 0x%x" % (io_tlb_list))
    print("io_tlb_nslabs = %d" % (io_tlb_nslabs))
    print("io_tlb_used = %d" % (io_tlb_used))
    print("io_tlb_index = %d" % (io_tlb_index))
    print("io_tlb_list[%d] = %d" % (io_tlb_index, io_tlb_list[io_tlb_index]))

    if options.show_details:
        for i in range(0, io_tlb_nslabs):
            print("io_tlb_list[%d] = %d" % (i, io_tlb_list[i]))


def show_requests(options):
    filter = ""
    rq_list_dict = {}
    for rq in get_all_request_queues(filter):
        for request in get_queue_requests(rq):
            reqinfo = request._reqinfo_
            rq_list_dict[request] = reqinfo.rq_alloc


    sorted_rq_list = sorted(rq_list_dict.items(),
            key=operator.itemgetter(1), reverse=True)
    for request, _ in sorted_rq_list:
        rq = request.q
        reqinfo = request._reqinfo_
        dev_name = rq_names[rq]
        try:
            hd_struct = request.part
            dev_name = hd_struct.__dev.kobj.name
        except:
            pass

        rq_alloc = reqinfo.rq_alloc
        alloc_time = "%.3f" % rq_alloc
        try:
            if rq_alloc < 0:
                alloc_time = "%.3f sec ago" % (-rq_alloc)
        except:
            pass

        if rq_alloc  < -5:
            if rq_alloc > -10:
                crashcolor.set_color(crashcolor.GREEN)
            elif rq_alloc > -20:
                crashcolor.set_color(crashcolor.MAGENTA)
            elif rq_alloc > -50:
                crashcolor.set_color(crashcolor.BLUE)
            else:
                crashcolor.set_color(crashcolor.RED)
        else:
            crashcolor.set_color(crashcolor.RESET)

        print("0x%x %7s %5s  allocated  %s" % (request, reqinfo.state, dev_name, alloc_time))
        crashcolor.set_color(crashcolor.RESET)


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
                  help="Show block device list")

    op.add_option("-c", "--char",
                  action="store_true",
                  dest="show_char",
                  default=False,
                  help="Show character device list")

    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show detailed information")

    op.add_option("-i", "--iotlb", dest="show_iotlb", default=False,
                  action="store_true",
                  help="Show IOTLB data")

    op.add_option("-q", "--requests", dest="show_requests", default=False,
                  action="store_true",
                  help="Show requests list")

    op.add_option("-p", "--pvio", dest="show_pvio", default=False,
                  action="store_true",
                  help="Paravirtual I/O rings (virtio, pvscsi, Hyper-V "
                       "VMBus): requests the host has not completed and "
                       "completions the guest has not processed")

    (o, args) = op.parse_args()

    if o.show_block:
        show_blkdevs(o)

    if o.show_char:
        show_chrdevs()

    if o.show_iotlb:
        show_iotlb(o)

    if o.show_requests:
        show_requests(o)

    if o.show_pvio:
        show_pvio(o)


if ( __name__ == '__main__'):
    devinfo()
