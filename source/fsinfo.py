"""
'fsinfo' command: mounted filesystem details, freeze state and dumpe2fs-style output.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import Tasks
import sys
import heapq
import operator
import re

import crashcolor


sysinfo = {}
sys_str = ""
ver_magic = 0
VER_MAGIC_3_3 = 303 # version 3.3


machine_symbols = {}
minus_one_addr = 0
page_size = 4096

def get_machine_symbol(symbol):
    global machine_symbols
    global minus_one_addr
    global page_size

    try:
        if len(machine_symbols) == 0:
            help_s_out = exec_crash_command("help -m")
            lines = help_s_out.splitlines()
            for line in lines:
                words = line.split(":")
                key = words[0].strip()
                value = words[1].strip()
                machine_symbols[key] = value
                if key == "bits":
                    minus_one_addr = (1 << int(value)) - 1
                if key == "pagesize":
                    page_size = int(value)

        if symbol in machine_symbols:
            return machine_symbols[symbol]

    except Exception as e:
        pass

    return ""

def get_system_info():
    global sysinfo
    global sys_str
    global ver_magic

    if (len(sysinfo) > 0):
        return

    sys_str = exec_crash_command("sys")
    resultlines = sys_str.splitlines()
    for line in resultlines:
        words = line.split(":")
        sysinfo[words[0].strip()] = line[len(words[0]) + 2:].strip()

    release_array = sysinfo["RELEASE"].split(".")
    ver_major = int(release_array[0])
    ver_minor = int(release_array[1])
    ver_magic = ver_major * 100 + ver_minor


def get_page_shift():
    resultline = exec_crash_command("ptob 1")
    if len(resultline) == 0:
        return 0

    words = resultline.split()
    if len(words) < 2:
        return 0

    value = int(words[1], 16)
    idx = 0
    while (value > 0):
        value = value >> 1
        idx = idx + 1

    return idx - 1


def dentry_to_filename (dentry) :
    if (dentry == 0):
        return "<>"

    try:
        crashout = exec_crash_command ("files -d {:#x}".format(dentry))
        # DENTRY INODE SUPERBLK TYPE PATH, and PATH is missing whenever the
        # dentry has no name to print. Splitting on the last word of the whole
        # output returns the TYPE column in that case - 'REG', 'FIFO', 'SOCK' -
        # which then reads as a filename. Go by column instead of by position.
        last_line = crashout.strip().splitlines()[-1]
        columns = last_line.split(None, 4)      # PATH may contain spaces
        if len(columns) < 5:
            return "<blank>"
        return columns[4].strip()
    except:
        return "<invalid>"


def get_vfsmount_from_sb(sb):
    if (sb == 0):
        return None

    try:
        crashout_list = exec_crash_command("mount")
        for mount_line in crashout_list.splitlines():
            mount_details = mount_line.split()
            if (mount_details[1] == ("%x" % sb)):
                if (ver_magic >= VER_MAGIC_3_3): # 3.3 or higher
                    mount = readSU("struct mount", int(mount_details[0], 16))
                    return mount.mnt
                else:
                    return readSU("struct vfsmount", int(mount_details[0], 16))
    except:
        return None

    return None 


def get_mount_points(sb):
    """
    Where a superblock is mounted, from the 'mount' table.

    dentry_to_filename(sb.s_root) answers '<blank>' whenever the root
    dentry carries no name of its own - tmpfs in particular - so ask crash
    instead. A superblock appears once per mount, so a bind-mounted
    filesystem yields several paths.
    """
    points = []
    try:
        for line in exec_crash_command("mount").splitlines():
            words = line.split()
            if len(words) < 5:
                continue
            if words[1] == ("%x" % sb):
                points.append(words[4])
    except Exception:
        pass

    return points


def get_mount_option(mnt_flags):
    try:
        return {
            0x01: "nosuid",         # "MNT_NOSUID",
            0x02: "nodev",          # "MNT_NODEV",
            0x04: "noexec",         # "MNT_NOEXEC",
            0x08: "noatime",        # "MNT_NOATIME",
            0x10: "nodiratime",     # "MNT_NODIRATIME",
            0x20: "",               # "MNT_RELATIME",
            0x40: "ro",             # "MNT_READONLY",

    # Below looks too much information, so, not visible for now
    #        0x100: "SHRINKABLE",
    #        0x200: "WRITE_HOLD",
    #        0x1000: "SHARED",
    #        0x2000: "UNBINDABLE",

            0x800000: "locked",     # MNT_LOCKED
            0x8000000: "umount",    # MNT_UMOUNT
        }.get(mnt_flags, "")
    except:
        return ""


def get_mount_options(mnt_flags):
    result = ""
    for x in range(0, 64):
        option = get_mount_option((mnt_flags & (1 << x)))
        if (option != "" and result != ""):
            result = result + ","
        result = result + option

    return result

_FREEZE_INFO = {
    0:  ("SB_UNFROZEN",        "normal — filesystem is fully operational"),
    1:  ("SB_FREEZE_WRITE",    "new writes blocked; in-flight writes still running"),
    2:  ("SB_FREEZE_PAGEFAULT","page faults to this FS also blocked"),
    3:  ("SB_FREEZE_FS",       "FS-level operations blocked; journal commits draining"),
    4:  ("SB_FREEZE_COMPLETE", "completely frozen — snapshot/quiesce point reached"),
    -1: ("UNRECOGNIZED STATE", ""),
}

def get_frozen_str(frozen_type):
    return _FREEZE_INFO.get(frozen_type, ("??", ""))[0]

def get_frozen_desc(frozen_type):
    return _FREEZE_INFO.get(frozen_type, ("??", ""))[1]


# Tasks in D-state with these frames likely caused or are involved in the freeze
_FREEZER_FRAMES = ("freeze_super", "thaw_super", "sync_filesystem",
                   "freeze_bdev", "thaw_bdev")


MINORBITS = 20
MINORMASK = ((1 << MINORBITS) - 1)

def get_dev_no(super_block):
    major = super_block.s_dev >> MINORBITS
    minor = super_block.s_dev & MINORMASK

    return major, minor


def list_empty(list):
    return list.next.next == list.next


def _count_wait_list(wait):
    """Return (count, has_vmtoolsd, [(comm, pid), ...]) for a wait_queue_head."""
    tasks = []
    has_vmtoolsd = False
    try:
        head_list = _wqhead_list(wait)
        for task in _wq_entries(head_list):
            comm = str(task.comm)
            pid  = int(task.pid)
            tasks.append((comm, pid))
            if comm == "vmtoolsd":
                has_vmtoolsd = True
    except Exception:
        pass
    return len(tasks), has_vmtoolsd, tasks


def find_freezer_tasks():
    """
    Heuristic: walk all tasks and return those whose kernel stack
    contains a freeze-related frame (freeze_super, thaw_super, etc.).
    """
    freezers = []
    try:
        tt = Tasks.TaskTable()
        for t in tt.allThreads():
            try:
                bt = exec_crash_command("bt %d" % t.pid)
                if any(f in bt for f in _FREEZER_FRAMES):
                    freezers.append((str(t.comm), int(t.pid)))
            except Exception:
                continue
    except Exception:
        pass
    return freezers


_RW_SEM_LEVEL_NAMES = {
    0: "SB_FREEZE_WRITE    ",
    1: "SB_FREEZE_PAGEFAULT",
    2: "SB_FREEZE_FS       ",
}


def show_rw_sem_waiters(sb):
    """
    Show tasks queued on each sb->s_writers.rw_sem[i].waiters (readers
    blocked because a freeze writer holds the semaphore) and the current
    writer task (freeze initiator) held in rw_sem[i].writer.task.
    Only called when -d is given.
    """
    if member_offset('struct super_block', 's_writers') < 0:
        return

    try:
        rw_sem = sb.s_writers.rw_sem
    except Exception:
        return

    SB_FREEZE_LEVELS = 3
    printed_header = False

    for i in range(SB_FREEZE_LEVELS):
        level_name = _RW_SEM_LEVEL_NAMES.get(i, "level %d" % i)
        try:
            sem = rw_sem[i]
        except Exception:
            continue

        # Writer task waiting to complete the freeze at this level
        try:
            writer_task_ptr = sem.writer.task
            if writer_task_ptr and int(writer_task_ptr) != 0:
                writer_task = readSU("struct task_struct", int(writer_task_ptr))
                if not printed_header:
                    print("\t--- rw_sem waiters ---")
                    printed_header = True
                print("\t  [%s] writer (freeze initiator): %s (%d)" % (
                    level_name, writer_task.comm, writer_task.pid))
        except Exception:
            pass

        # Readers blocked because the semaphore is held for freezing
        try:
            waiters = sem.waiters
            head_list = _wqhead_list(waiters)
            found_any = False
            for task in _wq_entries(head_list):
                if not printed_header:
                    print("\t--- rw_sem waiters ---")
                    printed_header = True
                if not found_any:
                    print("\t  [%s] readers blocked:" % level_name)
                    found_any = True
                print("\t      %s (%d)" % (task.comm, task.pid))
        except Exception:
            pass

    if printed_header:
        print("")


def show_freeze_wait_tasks(options, sb):
    # 'wait' was removed in newer kernels — guard with member_offset
    try:
        if member_offset('struct sb_writers', 'wait') >= 0:
            show_wait_list(options, sb.s_writers.wait, "WAIT TASKS")
    except Exception:
        pass
    try:
        show_wait_list(options, sb.s_writers.wait_unfrozen, "WAIT_UNFROZEN TASKS")
    except Exception:
        pass
    show_rw_sem_waiters(sb)


def _wqhead_list(wait):
    """
    Return the list_head of a wait_queue_head_t regardless of kernel version.
    Older kernels use .task_list; newer kernels use .head.
    """
    try:
        return wait.head        # 4.13+
    except Exception:
        return wait.task_list   # pre-4.13


def _wq_entries(wait_head_list):
    """
    Iterate wait_queue entries regardless of kernel version.
    Older: struct __wait_queue  / .task_list member
    Newer: struct wait_queue_entry / .entry member
    Yields task_struct objects.
    """
    # Try newer kernel struct first
    for struct_name, member_name in (
        ("struct wait_queue_entry", "entry"),
        ("struct __wait_queue",     "task_list"),
    ):
        try:
            for wq in readSUListFromHead(wait_head_list, member_name, struct_name):
                try:
                    task = readSU("struct task_struct", wq.private)
                    yield task
                except Exception:
                    continue
            return   # successfully iterated — done
        except Exception:
            continue


def show_wait_list(options, wait, wait_name):
    head_list = _wqhead_list(wait)
    if not list_empty(head_list):
        print("\t%s" % wait_name)

    for task in _wq_entries(head_list):
        print("\t%s (%d)" % (task.comm, task.pid))

    if not list_empty(head_list):
        print()


_WRITE_PATH_FRAMES = (
    'vfs_write', '__sb_start_write', 'generic_file_write_iter',
    'do_sync_write', 'generic_perform_write', 'iomap_file_buffered_write',
    'ext4_file_write_iter', 'xfs_file_write_iter', 'btrfs_file_write_iter',
    'nfs_file_write', 'aio_write', 'io_write',
)


def _find_blocking_writers(sb, initiator_pid):
    """
    Find tasks that may hold the percpu_rw_semaphore read lock on this
    superblock, preventing freeze_super from draining.

    Strategy: scan all threads for those that
      (a) have at least one file open on this superblock, AND
      (b) are in D state OR have a write-path frame in their bt.
    """
    sb_addr = int(sb)
    candidates = []

    try:
        tt = Tasks.TaskTable()
        for t in tt.allThreads():
            if int(t.pid) == initiator_pid:
                continue
            try:
                # Quick check: task must have files on this superblock
                has_sb_file = False
                try:
                    fdt = t.files.fdt
                    for i in range(min(int(fdt.max_fds), 256)):
                        try:
                            fp = int(fdt.fd[i])
                            if fp == 0:
                                continue
                            f = readSU("struct file", fp)
                            if int(f.f_inode.i_sb) == sb_addr:
                                has_sb_file = True
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

                if not has_sb_file:
                    continue

                bt = exec_crash_command("bt %d" % t.pid)
                ps_line = exec_crash_command("ps -m %d" % t.pid)
                is_dstate    = "[UN]" in ps_line
                has_write_frame = any(f in bt for f in _WRITE_PATH_FRAMES)

                if is_dstate or has_write_frame:
                    candidates.append((str(t.comm), int(t.pid),
                                       bt, is_dstate, has_write_frame))
            except Exception:
                continue
    except Exception:
        pass

    return candidates


def _collect_rw_sem_info(sb):
    """
    Return a dict with freeze initiator and blocked readers per level.
    { level_idx: {'initiator': (comm, pid) | None,
                  'blocked':   [(comm, pid), ...] } }
    """
    result = {}
    SB_FREEZE_LEVELS = 3
    try:
        rw_sem = sb.s_writers.rw_sem
    except Exception:
        return result

    for i in range(SB_FREEZE_LEVELS):
        entry = {'initiator': None, 'blocked': []}
        try:
            sem = rw_sem[i]
            try:
                tp = sem.writer.task
                if tp and int(tp) != 0:
                    t = readSU("struct task_struct", int(tp))
                    entry['initiator'] = (str(t.comm), int(t.pid))
            except Exception:
                pass
            try:
                head_list = _wqhead_list(sem.waiters)
                for task in _wq_entries(head_list):
                    entry['blocked'].append((str(task.comm), int(task.pid)))
            except Exception:
                pass
        except Exception:
            pass
        result[i] = entry
    return result


def detect_frozen_fs_deadlocks(sb_list, options=None):
    """
    Analyse frozen super_blocks for deadlock patterns and print a report.

    Pattern 1 — Self-deadlock:
      The freeze initiator (rw_sem[i].writer.task) also appears in the
      blocked-readers list of the same or a lower freeze level, meaning
      the process froze the FS and then tried to write to it.

    Pattern 2 — Stalled freeze:
      The freeze initiator is in UN (D) state but the freeze level is
      below SB_FREEZE_COMPLETE, meaning it is waiting for in-flight
      writers to drain — but one of those writers may be stuck too.
    """
    issues = []

    for frozen, mount_path, fs_id, sb in sb_list:
        if frozen <= 0:
            continue

        rw_info = _collect_rw_sem_info(sb)
        if not rw_info:
            continue

        # Collect all initiator PIDs and all blocked PIDs across levels
        initiators = {}   # pid -> (comm, level_idx)
        blocked_pids = set()

        for lvl, data in rw_info.items():
            if data['initiator']:
                comm, pid = data['initiator']
                initiators[pid] = (comm, lvl)
            for comm, pid in data['blocked']:
                blocked_pids.add((pid, comm))

        # Pattern 1: initiator is also in the blocked set
        for pid, (comm, lvl) in initiators.items():
            if pid in {p for p, _ in blocked_pids}:
                issues.append({
                    'type': 'SELF_DEADLOCK',
                    'fs': "%s (%s)" % (mount_path, fs_id),
                    'frozen': _FREEZE_INFO.get(frozen, ("??",""))[0],
                    'pid': pid, 'comm': comm,
                    'msg': (
                        "%s (PID %d) froze the filesystem then blocked trying "
                        "to write to it — classic snapshot quiesce self-deadlock."
                        % (comm, pid)),
                })

        # Pattern 2: initiator is in UN state (stalled freeze)
        for pid, (comm, lvl) in initiators.items():
            if pid in {p for p, _ in blocked_pids}:
                continue   # already reported as self-deadlock
            try:
                bt_out = exec_crash_command("ps -m %d" % pid)
                if "[UN]" in bt_out:
                    issues.append({
                        'type': 'STALLED_FREEZE',
                        'fs': "%s (%s)" % (mount_path, fs_id),
                        'frozen': _FREEZE_INFO.get(frozen, ("??",""))[0],
                        'pid': pid, 'comm': comm,
                        'sb': sb,
                        'msg': (
                            "%s (PID %d) is the freeze initiator and is itself "
                            "in D state — the freeze cannot complete because a "
                            "required in-flight writer is stuck."
                            % (comm, pid)),
                    })
            except Exception:
                pass

    if not issues:
        print("  No frozen-filesystem deadlock detected.")
        return

    crashcolor.set_color(crashcolor.LIGHTRED)
    print("=" * 60)
    print("FROZEN FILESYSTEM DEADLOCK ANALYSIS")
    print("=" * 60)
    crashcolor.set_color(crashcolor.RESET)

    for issue in issues:
        tag = "[%s]" % issue['type']
        crashcolor.set_color(crashcolor.LIGHTRED if issue['type'] == 'SELF_DEADLOCK'
                             else crashcolor.YELLOW)
        print("\n%s  %s  (state: %s)" % (tag, issue['fs'], issue['frozen']))
        crashcolor.set_color(crashcolor.RESET)
        print("  " + issue['msg'])

        if issue['type'] == 'STALLED_FREEZE' and options and options.show_details:
            pid = issue['pid']
            comm = issue['comm']

            # Show the freeze initiator's backtrace
            print("\n  Backtrace of freeze initiator %s (%d):" % (comm, pid))
            try:
                bt = exec_crash_command("bt %d" % pid)
                for line in bt.splitlines():
                    print("    %s" % line)
            except Exception as e:
                print("    (bt failed: %s)" % e)

            # Find tasks that may be blocking the freeze
            print("\n  Searching for blocking writers on this FS "
                  "(tasks with open files + write-path frames) ...")
            try:
                candidates = _find_blocking_writers(issue['sb'], pid)
                if candidates:
                    for c_comm, c_pid, c_bt, c_dstate, c_write in candidates:
                        state_tag = "[D-state]" if c_dstate else "[write-path]"
                        crashcolor.set_color(crashcolor.LIGHTRED if c_dstate
                                             else crashcolor.YELLOW)
                        print("\n  %s  %s (PID %d)" % (state_tag, c_comm, c_pid))
                        crashcolor.set_color(crashcolor.RESET)
                        for line in c_bt.splitlines()[:20]:
                            print("      %s" % line)
                        if len(c_bt.splitlines()) > 20:
                            print("      ...")
                else:
                    print("  (no obvious blocking writers found — they may have "
                          "already released the lock or run on another CPU)")
            except Exception as e:
                print("  (scan failed: %s)" % e)

    if any(i['type'] == 'SELF_DEADLOCK' for i in issues):
        print("\n  Reference: https://access.redhat.com/solutions/7089292")
        print("  Workaround: set ignoreFrozenFileSystems=true and "
              "vmsvc.level=none in /etc/vmware-tools/tools.conf")
    print("")


# ---------------------------------------------------------------------------
# --frozen: is a filesystem freeze blocking this system, and who froze it?
# The classification and log parsing live in fsfreeze.py (shared with isos).
# ---------------------------------------------------------------------------

FROZEN_EXAMPLE_LIMIT = 4
FROZEN_DETAIL_LIMIT = 10

FREEZE_HOLDER_NAMES = ((1, "kernel"), (2, "userspace"))


def _frozen_superblocks():
    """[(frozen, mount_path, s_id, fstype, sb, holders)] for frozen sbs."""
    rows = []
    mountpoints = _sb_mountpoints()
    has_writers = member_offset('struct super_block', 's_writers') >= 0
    has_holders = member_offset('struct sb_writers', 'freeze_holders') >= 0
    for sb in readSUListFromHead(sym2addr("super_blocks"), "s_list",
                                 "struct super_block"):
        try:
            if has_writers:
                frozen = int(sb.s_writers.frozen)
            elif member_offset('struct super_block', 's_frozen') >= 0:
                frozen = int(sb.s_frozen)
            else:
                continue
        except Exception:
            continue
        if frozen <= 0:
            continue
        holders = None
        if has_holders:
            try:
                bits = int(sb.s_writers.freeze_holders)
                holders = ", ".join(n for b, n in FREEZE_HOLDER_NAMES
                                    if bits & b) or "none"
            except Exception:
                pass
        mount_path = mountpoints.get(int(sb))
        if mount_path is None:
            try:
                mount_path = dentry_to_filename(sb.s_root)
            except Exception:
                mount_path = "?"
        rows.append((frozen, mount_path, str(sb.s_id), str(sb.s_type.name),
                     sb, holders))
    return rows


def _sb_mountpoints():
    """superblock address -> mount point, from crash 'mount' (each sb's own
    root dentry is just '/')."""
    points = {}
    try:
        for line in exec_crash_command("mount").splitlines():
            w = line.split()
            if len(w) >= 5:
                try:
                    points.setdefault(int(w[1], 16), w[4])
                except ValueError:
                    continue
    except Exception:
        pass
    return points


def _thread_groups():
    """pid -> tgid, and tgid -> the thread-group leader's comm."""
    tgid_of, leader = {}, {}
    try:
        for t in Tasks.TaskTable().allThreads():
            try:
                pid, tgid = int(t.pid), int(t.tgid)
            except Exception:
                continue
            tgid_of[pid] = tgid
            if pid == tgid:
                leader[tgid] = str(t.comm)
    except Exception:
        pass
    return tgid_of, leader


def _ps_states():
    """pid -> (state, comm) from crash 'ps'."""
    states = {}
    try:
        for line in exec_crash_command("ps").splitlines():
            w = line.replace(">", " ", 1).split()
            if len(w) >= 9 and w[0].isdigit():
                states[int(w[0])] = (w[4], " ".join(w[8:]))
    except Exception:
        pass
    return states


def show_frozen_summary(options):
    """
    Answer whether a filesystem freeze is blocking the system: frozen
    superblocks, the tasks blocked behind a freeze (from 'foreach UN bt'
    frames, which find them on RHEL7, 8 and 9 alike, whichever wait list
    the kernel uses), tasks freezing or thawing now, the freeze agents
    (vmtoolsd, qemu-ga, hv_vss_daemon, fsfreeze) by thread-group leader,
    and hung-task reports in the kernel log whose stack is a freeze wait.
    """
    import btgroup
    import fsfreeze

    frozen = _frozen_superblocks()
    try:
        tasks = btgroup.parse_foreach_bt(exec_crash_command("foreach UN bt"))
    except Exception:
        tasks = []
    waiters = []
    freezers = []
    for pid, comm, frames, raw in tasks:
        kind, level = fsfreeze.classify(frames)
        if kind == "waiter":
            waiters.append((pid, comm, level, frames, raw))
        elif kind == "freezer":
            freezers.append((pid, comm, frames, raw, level))
    states = _ps_states()
    tgid_of, leader = _thread_groups()
    # Agents by their thread-group leader: glib names its threads, so a
    # blocked vmtoolsd thread need not be called vmtoolsd.
    agents = sorted((tgid, comm, states.get(tgid, ("?", ""))[0])
                    for tgid, comm in leader.items()
                    if comm in fsfreeze.AGENT_COMMS)
    if not leader:
        agents = sorted((pid, comm, st) for pid, (st, comm) in states.items()
                        if comm in fsfreeze.AGENT_COMMS)
    waiter_groups = {}
    for w in waiters:
        waiter_groups.setdefault(tgid_of.get(w[0], w[0]), []).append(w)
    freezer_groups = set(tgid_of.get(f[0], f[0]) for f in freezers)
    blocked_agents = [a for a in agents if a[0] in waiter_groups]
    try:
        log_lines = exec_crash_command("log").splitlines()
    except Exception:
        log_lines = []
    reports = fsfreeze.hung_reports(log_lines)
    blocked_reports = [r for r in reports if r["kind"] == "waiter"]
    log_end = None
    for line in reversed(log_lines):
        log_end = fsfreeze.line_time(line)
        if log_end:
            break

    thawing = [f for f in freezers if f[4] == "thaw"]
    if frozen and blocked_agents:
        status = "AGENT BLOCKED"
        text = ("freeze agent %s has a thread blocked behind the freeze; if "
                "it holds the freeze it cannot thaw (snapshot quiesce "
                "self-deadlock)" % ", ".join("%s(%d)" % (c, p)
                                            for p, c, s in blocked_agents))
    elif thawing:
        status = "THAW STUCK"
        text = ("%d task(s) are thawing and waiting (thaw_super needs "
                "s_umount, which a frozen writer may hold)" % len(thawing))
    elif freezers:
        status = "FREEZE STUCK"
        text = ("%d task(s) are freezing and waiting; a freeze waits for "
                "every writer to drain" % len(freezers))
    elif frozen and waiters:
        status = "FROZEN, BLOCKING"
        text = "%d task(s) wait for a thaw" % len(waiters)
    elif frozen:
        status = "FROZEN"
        text = "no task waits on it yet"
    elif waiters:
        status = "WAITING, NOT FROZEN"
        text = ("%d task(s) are in a freeze wait but no superblock is frozen "
                "(a thaw in progress?)" % len(waiters))
    elif blocked_reports:
        status = "EARLIER FREEZE"
        text = ("%d hung-task report(s) in the log were freeze waits; nothing "
                "is frozen now" % len(blocked_reports))
    else:
        status = "NO FREEZE"
        text = "nothing frozen, no task in a freeze wait"

    crashcolor.set_color(crashcolor.LIGHTCYAN)
    print("Filesystem freeze assessment")
    print("============================")
    crashcolor.set_color(crashcolor.RESET)
    print("Answer : ", end="")
    crashcolor.set_color(crashcolor.LIGHTRED if status in (
        "AGENT BLOCKED", "FREEZE STUCK", "THAW STUCK", "FROZEN, BLOCKING")
        else crashcolor.YELLOW if status != "NO FREEZE" else crashcolor.RESET)
    print(status, end="")
    crashcolor.set_color(crashcolor.RESET)
    print("  %s" % text)

    print("\nFrozen filesystems")
    if not frozen:
        print("  none")
    for level, mount_path, s_id, fstype, sb, holders in frozen:
        print("  %-20s %s (%s, %s)  sb 0x%x%s"
              % (get_frozen_str(level), mount_path, s_id, fstype, int(sb),
                 "  held by %s" % holders if holders else ""))

    print("\nTasks blocked by a freeze (from 'foreach UN bt')")
    if not waiters:
        print("  none")
    for level in ("write", "pagefault", "fs"):
        mine = [w for w in waiters if w[2] == level]
        if not mine:
            continue
        examples = ", ".join("%s(%d) in %s" % (c, p, fsfreeze.caller_of(f))
                             for p, c, l, f, r in mine[:FROZEN_EXAMPLE_LIMIT])
        more = len(mine) - FROZEN_EXAMPLE_LIMIT
        print("  %-10s %4d  %s%s" % (level, len(mine), examples,
                                     " +%d more" % more if more > 0 else ""))
    if waiters and len(frozen) > 1:
        print("  (the stack does not say which of the frozen filesystems)")

    if freezers:
        print("\nFreezing or thawing now")
        for pid, comm, frames, raw, what in freezers:
            print("  %s(%d) %s in %s" % (comm, pid, "thawing" if what == "thaw"
                                         else "freezing",
                                         fsfreeze.caller_of(frames)))

    print("\nFreeze agents")
    if not agents:
        print("  none running (vmtoolsd, qemu-ga, hv_vss_daemon, fsfreeze)")
    for pid, comm, st in agents:
        note = ""
        if pid in waiter_groups:
            note = "  BLOCKED behind the freeze: %s" % ", ".join(
                "%s(%d)" % (w[1], w[0]) for w in waiter_groups[pid][:3])
        elif pid in freezer_groups:
            note = "  freezing/thawing"
        print("  %-14s %6d  %-3s %s%s" % (comm, pid, st,
                                         fsfreeze.AGENT_COMMS[comm], note))

    print("\nKernel log")
    if not reports:
        print("  no hung-task reports")
    else:
        last = blocked_reports[-1] if blocked_reports else None
        age = fsfreeze.time_diff(last["time"], log_end) if last else None
        print("  %d hung-task report(s), %d of them freeze waits%s"
              % (len(reports), len(blocked_reports),
                 "; last %s before end of log" % fsfreeze.duration_text(age)
                 if age is not None else ""))

    if status == "AGENT BLOCKED" and any(c == "vmtoolsd"
                                         for p, c, s in blocked_agents):
        print("\nReference: https://access.redhat.com/solutions/7089292")
        print("Workaround: set ignoreFrozenFileSystems=true and vmsvc.level=none "
              "in /etc/vmware-tools/tools.conf")

    if options.show_details and (waiters or freezers):
        print("\nBacktraces (-d)")
        for pid, comm, level, frames, raw in waiters[:FROZEN_DETAIL_LIMIT]:
            print("\n  [%s wait]" % level)
            for line in raw:
                print("    " + line)
        for pid, comm, frames, raw, what in freezers[:FROZEN_DETAIL_LIMIT]:
            print("\n  [%sing]" % ("thaw" if what == "thaw" else "freez"))
            for line in raw:
                print("    " + line)
        if len(waiters) > FROZEN_DETAIL_LIMIT:
            print("\n  ... %d more blocked task(s)"
                  % (len(waiters) - FROZEN_DETAIL_LIMIT))
    elif waiters or freezers:
        print("\nUse -d with -z for the backtraces; 'fsinfo -d' for the "
              "per-level rw_sem waiters and the deadlock checks.")


def all_filesystem_info(options):
    get_system_info()
    fs_state_list = {}
    frozen_entries = []   # collect for summary
    frozen_sb_list = []   # (frozen_level, mount_path, fs_id, sb) for deadlock detection

    super_blocks = sym2addr("super_blocks")
    for sb in readSUListFromHead(super_blocks,
                                 "s_list",
                                 "struct super_block"):
        frozen = -1
        if member_offset('struct super_block', 's_writers') >= 0:
            frozen = sb.s_writers.frozen
        elif member_offset('struct super_block', 's_frozen') >= 0:
            frozen = sb.s_frozen

        frozen_str  = get_frozen_str(frozen)
        frozen_desc = get_frozen_desc(frozen)
        fs_state_list[frozen_str] = fs_state_list.get(frozen_str, 0) + 1

        vfsmnt = get_vfsmount_from_sb(sb)
        mnt_flags = 0
        if vfsmnt is not None:
            mnt_flags = vfsmnt.mnt_flags

        dev_major, dev_minor = get_dev_no(sb)
        mount_path = dentry_to_filename(sb.s_root)

        # Count waiting tasks and detect vmtoolsd involvement
        wait_count = vmtoolsd_waiting = 0
        wait_tasks = []
        if frozen != 0 and member_offset('struct super_block', 's_writers') >= 0:
            try:
                wc, hv, wt = _count_wait_list(sb.s_writers.wait_unfrozen)
                wait_count      += wc
                vmtoolsd_waiting = vmtoolsd_waiting or hv
                wait_tasks      += wt
                wc2, hv2, wt2 = _count_wait_list(sb.s_writers.wait)
                wait_count      += wc2
                vmtoolsd_waiting = vmtoolsd_waiting or hv2
                wait_tasks      += wt2
            except Exception:
                pass

        # Colour by freeze level
        if frozen_str == "SB_FREEZE_COMPLETE":
            crashcolor.set_color(crashcolor.LIGHTRED)
        elif frozen_str in ("SB_FREEZE_WRITE", "SB_FREEZE_PAGEFAULT",
                            "SB_FREEZE_FS"):
            crashcolor.set_color(crashcolor.LIGHTCYAN)

        wait_info = ""
        if wait_count > 0:
            wait_info = "  [%d task(s) blocked" % wait_count
            if vmtoolsd_waiting:
                wait_info += " incl. vmtoolsd ⚠"
            wait_info += "]"

        print("SB: 0x%14x  frozen=%-22s  %s (%s) [%s] (%s) on %d:%d%s" % (
              sb, frozen_str,
              mount_path, sb.s_id, sb.s_type.name,
              get_mount_options(mnt_flags),
              dev_major, dev_minor, wait_info))

        if frozen_desc and frozen != 0:
            print("    %s" % frozen_desc)

        if frozen != 0 and vmtoolsd_waiting:
            crashcolor.set_color(crashcolor.LIGHTRED)
            print("    *** vmtoolsd is blocked on this frozen FS — possible "
                  "snapshot quiesce deadlock (see solutions/7089292) ***")
            crashcolor.set_color(crashcolor.LIGHTCYAN)

        if options.show_details:
            show_freeze_wait_tasks(options, sb)
        elif wait_tasks:
            for comm, pid in wait_tasks:
                print("      waiting: %s (%d)" % (comm, pid))

        crashcolor.set_color(crashcolor.RESET)

        if frozen != 0:
            frozen_entries.append((frozen_str, mount_path, sb.s_id,
                                   wait_count, vmtoolsd_waiting))
            frozen_sb_list.append((frozen, mount_path, str(sb.s_id), sb))

    # Summary
    print("")
    print("=" * 60)
    print("Freeze state summary:")
    for frozen_str, count in sorted(fs_state_list.items(),
                                    key=lambda x: x[1], reverse=True):
        if frozen_str != "SB_UNFROZEN":
            crashcolor.set_color(crashcolor.LIGHTRED)
        print("  %25s : %d" % (frozen_str, count))
        crashcolor.set_color(crashcolor.RESET)

    if frozen_entries:
        print("")
        print("Frozen filesystems:")
        for fstate, mpath, sid, wcount, hv in frozen_entries:
            note = " [vmtoolsd blocked]" if hv else ""
            print("  %-22s  %s (%s)  %d waiter(s)%s" % (
                  fstate, mpath, sid, wcount, note))

        # Heuristic: show processes that may have triggered the freeze
        print("")
        print("Searching for freeze initiator (tasks with freeze frames) ...")
        freezers = find_freezer_tasks()
        if freezers:
            crashcolor.set_color(crashcolor.YELLOW)
            for comm, pid in freezers:
                print("  Possible freezer: %s (%d)" % (comm, pid))
            crashcolor.set_color(crashcolor.RESET)
        else:
            print("  (none found — freezer may have already exited)")

    # Always run deadlock detection when frozen filesystems exist
    if frozen_sb_list:
        print("")
        detect_frozen_fs_deadlocks(frozen_sb_list, options)


def find_pid_from_file(options):
    file_struct = readSU("struct file",
                         int(options.file_addr_for_pid, 16))
    d_inode = file_struct.f_path.dentry.d_inode;
    find_pid_from_inode(d_inode);


def find_pid_from_dentry(options):
    dentry = readSU("struct dentry",
                    int(options.dentry_addr_for_pid, 16))
    d_inode = dentry.d_inode;
    find_pid_from_inode(d_inode);


def find_pid_from_inode(d_inode):
    vfs_inode_offset = member_offset('struct proc_inode', 'vfs_inode');
    proc_inode = readSU("struct proc_inode", d_inode - vfs_inode_offset)
    pid_first = proc_inode.pid.tasks[0].first
    pids_offset = member_offset("struct task_struct", "pids");
    task_struct = readSU("struct task_struct", pid_first - pids_offset);

    crashout = exec_crash_command(
        "struct task_struct.pid,comm,files {:#x} -d".format(task_struct))
    print("struct task_struct.pid,comm,files %x\n%s" %
          (task_struct, crashout))

    return

O_RDONLY = 0x0
O_WRONLY = 0x1
O_RDWR = 0x2
O_ACCMODE = 0x3
O_CREATE = 0x40
O_EXCL = 0x80
O_NOCTTY = 0x100
O_TRUNC = 0x200
O_APPEND = 0x400
O_NONBLOCK = 0x800
O_DSYNC = 0x1000
FASYNC = 0x2000
O_DIRECT = 0x4000
O_LARGEFILE = 0x8000

def get_file_open_mode_str(f_mode):
    result_str = ""
    if ((f_mode & 0x03) == O_RDONLY):
        result_str = result_str + "Read-Only"
    if ((f_mode & 0x03) == O_WRONLY):
        result_str = result_str + "Write-Only"
    if ((f_mode & 0x03) == O_RDWR):
        result_str = result_str + "Read/Write"

    if ((f_mode & O_CREATE) == O_CREATE):
        result_str = result_str + ", O_CREATE"
    if ((f_mode & O_EXCL) == O_EXCL):
        result_str = result_str + ", O_EXCL"
    if ((f_mode & O_NOCTTY) == O_NOCTTY):
        result_str = result_str + ", O_NOCTTY"
    if ((f_mode & O_TRUNC) == O_TRUNC):
        result_str = result_str + ", O_TRUNC"
    if ((f_mode & O_APPEND) == O_APPEND):
        result_str = result_str + ", O_APPEND"
    if ((f_mode & O_NONBLOCK) == O_NONBLOCK):
        result_str = result_str + ", O_NONBLOCK"
    if ((f_mode & O_DSYNC) == O_DSYNC):
        result_str = result_str + ", O_DSYNC"
    if ((f_mode & FASYNC) == FASYNC):
        result_str = result_str + ", FASYNC"
    if ((f_mode & O_DIRECT) == O_DIRECT):
        result_str = result_str + ", O_DIRECT"
    if ((f_mode & O_LARGEFILE) == O_LARGEFILE):
        result_str = result_str + ", O_LARGEFILE"

    return result_str


def get_first_dentry_addr(inode):
    """
    Address of the first dentry aliasing this inode, or 0 if it has none.

    'struct inode.i_dentry' became an hlist in 3.6, and the dentry side of
    the link moved into the 'd_u' union at the same time. Both layouts turn
    up in the dumps we get, so tell them apart at runtime.
    """
    dentry_offset = member_offset('struct dentry', 'd_u')
    if dentry_offset < 0:
        dentry_offset = member_offset('struct dentry',
                                      'd_alias')
    i_dentry_size = member_size("struct inode", "i_dentry")
    hlist_head_sz = struct_size("struct hlist_head")
    if i_dentry_size == hlist_head_sz:
        dentry_addr = inode.i_dentry.first - dentry_offset
    else:
        dentry_addr = inode.i_dentry.next - dentry_offset

    if dentry_addr == -dentry_offset: # The head pointer was NULL
        return 0

    return dentry_addr


def show_inode_details(options):
    inode = readSU("struct inode", int(options.inode, 16))
    dentry_addr = get_first_dentry_addr(inode)

    if dentry_addr != 0: # No dentry for this inode
        dentry = readSU('struct dentry', dentry_addr)
        try:
            dentry_details = exec_crash_command("files -d 0x%x" % (dentry))
        except:
            dentry_details = ""
        print(dentry_details)
    elif inode.i_mapping != 0:
        i_mapping = inode.i_mapping
        print("inode = 0x%x, mapping = 0x%x, page flags = 0x%x" %
              (inode, i_mapping, i_mapping.flags))
        if inode.i_sb.s_bdi != 0:
            bdi = inode.i_sb.s_bdi
            try:
                dev_name = bdi.name
            except:
                dev_name = bdi.dev_name
            if dev_name != "" and bdi.dev != 0:
                dev_kobj_name = bdi.dev.kobj.name
            else:
                dev_kobj_name = ""

            print("\tbacking_dev_info 0x%x : %s %s" %
                  (bdi, dev_name, dev_kobj_name))
        print("")

    print("%s" % (get_inode_details(inode)))
    print("")


def size_to_human_readable(byte_size):
    result = "%d bytes" % (byte_size)
    conv_size = int(byte_size/1024/1024/1024) # GiB
    if conv_size > 0:
        return result + (" (%d GB)" % conv_size)

    conv_size = int(byte_size/1024/1024) # MiB
    if conv_size > 0:
        return result + (" (%d MB)" % conv_size)

    conv_size = int(byte_size/1024) # KiB
    if conv_size > 0:
        return result + (" (%d KB)" % conv_size)

    return result

def get_inode_details(inode):
    try:
        i_uid = inode.i_uid.val
        i_gid = inode.i_gid.val
    except:
        i_uid = inode.i_uid
        i_gid = inode.i_gid

    return "file size = %s, ino = %d, link count = %d\n\tuid = %d, gid = %d" %\
          (size_to_human_readable(inode.i_size), inode.i_ino, inode.i_nlink, i_uid, i_gid)


def _show_sb_freeze_state(sb):
    """Print freeze state of the superblock only when it is not SB_UNFROZEN."""
    frozen = -1
    try:
        if member_offset('struct super_block', 's_writers') >= 0:
            frozen = sb.s_writers.frozen
        elif member_offset('struct super_block', 's_frozen') >= 0:
            frozen = sb.s_frozen
    except Exception:
        return

    if frozen <= 0:
        return

    frozen_str  = get_frozen_str(frozen)
    frozen_desc = get_frozen_desc(frozen)

    print("== Freeze State ==")
    crashcolor.set_color(crashcolor.LIGHTRED if frozen_str == "SB_FREEZE_COMPLETE"
                         else crashcolor.LIGHTCYAN)
    print("  %s" % frozen_str)
    crashcolor.set_color(crashcolor.RESET)
    if frozen_desc:
        print("  %s" % frozen_desc)
    print("")


def show_file_details(options):
    file = readSU("struct file", int(options.file, 16))
    dentry_details = exec_crash_command("files -d 0x%x" % (file.f_path.dentry))
    print("== File Info ==")
    print(dentry_details)

    if " SOCK " in dentry_details:
        print("struct socket 0x%x" % file.private_data)

    f_op_sym = exec_crash_command("sym %x" % (file.f_op))
    print("file operations = %s" % (f_op_sym), end='')
    mount_details = exec_crash_command("mount").splitlines()
    mount_str = "%x" % (file.f_path.dentry.d_sb)
    print("file open mode = %s (0x%x)" % (get_file_open_mode_str(file.f_flags), file.f_flags))
    if member_offset("struct file", "f_inode") < 0:
        f_inode = file.f_path.dentry.d_inode
    else:
        f_inode = file.f_inode
    print("%s" % (get_inode_details(f_inode)))
    print("")
    found = False
    for mount_line in mount_details:
        words = mount_line.split()
        if words[1] == mount_str:
            if found == False:
                print("== Mount Info ==")
            print(mount_line)
            found = True

    _show_sb_freeze_state(file.f_path.dentry.d_sb)


def show_open_files(options):
    open_files_dict = {}

    all_procs = exec_crash_command("foreach files").split("PID: ")
    total_files = 0
    for one_proc in all_procs:
        all_files = one_proc.splitlines()
        if len(all_files) >= 3:
            if all_files[2] == "No open files":
                continue
            file_cnt = len(all_files) - 2
            total_files = total_files + file_cnt
            open_files_dict[all_files[0].split()[2]] = file_cnt

    sorted_open_files = sorted(open_files_dict.items(),
                               key=operator.itemgetter(1), reverse=not options.all)
    print("=" * 70)
    print("%14s %-s" % ("[ Open files ]", "[ task_struct  ] (comm)"))
    print("=" * 70)
    min_number = 10
    if (options.all):
        min_number = len(sorted_open_files) - 1

    print_count = min(len(sorted_open_files) - 1, min_number)

    for i in range(0, print_count):
        task = readSU("struct task_struct", int(sorted_open_files[i][0], 16))
        print("%14s  %-s (%s)" %
                (sorted_open_files[i][1],
                 sorted_open_files[i][0],
                 task.comm))

    if print_count < len(sorted_open_files) - 1:
        print("\t<...>")
    print("=" * 70)
    print("\tTotal open files = %s" % (f"{total_files:,}"))
    try:
        files_stat = readSymbol("files_stat")
        print("\n\tnr_files      = %s" % (f"{files_stat.nr_files:,}"))
        print("\tnr_free_files = %s" % (f"{files_stat.nr_free_files:,}"))
        print("\tmax_files     = %s" % (f"{files_stat.max_files:,}"))
    except Exception as e:
        print(e)
        pass


def show_open_file_size(options):
    all_files = exec_crash_command("foreach files").splitlines()
    for one_file in all_files:
        if one_file.find(" REG ") < 0:
            continue

        entries = one_file.split()
        options.file = entries[1]
        show_file_details(options)


def show_slab_dentry(options):
    try:
        result_lines = exec_crash_command("kmem -S dentry").splitlines()
        sb_dict = {}
        slab_coming = False
        for line in result_lines:
            words = line.split()
            if len(words) == 0:
                continue
            if words[0] == "SLAB":
                slab_coming = True
            elif slab_coming == True:
                slab_coming = False
                slab_lines = exec_crash_command("kmem -S 0x%s" % words[0])
                for slab_line in slab_lines.splitlines():
                    slab_line = slab_line.strip()
                    dentry_addr = 0
                    if slab_line.startswith("["):
                        dentry_addr = int(slab_line[1:-1], 16)

                    if dentry_addr > 0:
                        dentry = readSU("struct dentry", dentry_addr)
                        if dentry.d_sb not in sb_dict:
                            sb_dict[dentry.d_sb] = 0
                        sb_dict[dentry.d_sb] = sb_dict[dentry.d_sb] + 1
                        if options.show_details:
                            print("0x%x %s" % (dentry_addr, dentry_to_filename(dentry_addr)))

        print("\nsuberblock usage summary")
        print("=" * 30)
        print("%16s %8s %s" % ("super_block", "count", "root"))
        print("-" * 30)
        sorted_sb_dict = sorted(sb_dict.items(),
                                key=operator.itemgetter(1), reverse=True)
        total_count = 0
        for sb, count in sorted_sb_dict:
            try:
                print("0x%x %5d %s" %
                      (sb, count, dentry_to_filename(sb.s_root)))
            except:
                pass

            total_count = total_count + count
        print("-" * 40)
        print("Total allocated object count = %d" % (total_count))
        print("=" * 40)
    except Exception as e:
        print(e)
        pass


def show_caches(options):
    shrinker_list = readSymbol("shrinker_list")
    if shrinker_list == None or shrinker_list == 0:
        return

    sb_offset = member_offset("struct super_block", "s_shrink")
    if sb_offset < 0:
        return

    total_dentry_unused = 0
    total_inodes_unused = 0
    prune_super = sym2addr("prune_super")

    print("=" * 60)
    print("%18s %10s %10s %s" %\
          ("super_block", "dentries", "inodes", "path"))
    print("-" * 60)
    for shrinker in readSUListFromHead(shrinker_list,
                                       "list",
                                       "struct shrinker"):
        # Only concerns about normal super_block
        if shrinker.shrink != prune_super:
            continue

        sb = readSU("struct super_block", shrinker - sb_offset)
        dentry_unused = sb.s_nr_dentry_unused
        inodes_unused = sb.s_nr_inodes_unused
        if dentry_unused == 0 and inodes_unused == 0:
            continue
        total_dentry_unused = total_dentry_unused + dentry_unused
        total_inodes_unused = total_inodes_unused + inodes_unused

        print("0x%x %10d %10d %s" %\
              (sb, dentry_unused, inodes_unused,
               dentry_to_filename(sb.s_root)))

    print("-" * 60)
    print("%18s %10d %10d" %\
          ("Total", total_dentry_unused, total_inodes_unused))


def show_ext4_inode_cache_details(options, address):
    ext4_inode_info = readSU("struct ext4_inode_info", int(address, 16))
    options.inode = "%x" % ext4_inode_info.vfs_inode
    show_inode_details(options)


def show_ext4_inode_cache(options):
    try:
        slab_coming = False
        lines = exec_crash_command("kmem -S ext4_inode_cache")
        for line in lines.splitlines():
            words = line.split()
            if words[0] == "SLAB":
                slab_coming = True
            elif slab_coming == True:
                slab_coming = False
                slab_lines = exec_crash_command("kmem -S 0x%s" % words[0])
                for slab_line in slab_lines.splitlines():
                    slab_line = slab_line.strip()
                    if slab_line.startswith("["):
                        slab_line = slab_line[1:-1]
                        show_ext4_inode_cache_details(options, slab_line)
    except:
        pass


def show_cached_details(options):
    ext4_inode_cachep = readSymbol("ext4_inode_cachep")
    if ext4_inode_cachep != None and ext4_inode_cachep != 0:
        show_ext4_inode_cache(options)


I_FREEING = (1 << 5)
I_WILL_FREE = (1 << 4)
I_NEW = (1 << 3)
I_SKIP_STATE = I_FREEING | I_WILL_FREE | I_NEW

I_DIRTY_SYNC = (1 << 0)
I_DIRTY_DATASYNC = (1 << 1)
I_DIRTY_PAGES = (1 << 2)
I_DIRTY = I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES
I_SYNC = (1 << 7)

MS_BORN = (1 << 29)

S_IFMT   = 0o170000
S_IFSOCK = 0o140000
S_IFLNK  = 0o120000
S_IFREG  = 0o100000
S_IFBLK  = 0o060000
S_IFDIR  = 0o040000
S_IFCHR  = 0o020000
S_IFIFO  = 0o010000

INODE_TYPE_NAMES = [
    (S_IFREG,  "regular file"),
    (S_IFDIR,  "directory"),
    (S_IFLNK,  "symlink"),
    (S_IFBLK,  "block device"),
    (S_IFCHR,  "char device"),
    (S_IFIFO,  "fifo"),
    (S_IFSOCK, "socket"),
]

page_caches = {}
wb_caches = {}


def pages_to_str(pages):
    page_bytes = pages * page_size
    result_str = ""
    if page_bytes > 1024*1024*1024:
        result_str = "%d GB" % (page_bytes/1024/1024/1024)
    elif page_bytes > 1024*1024:
        result_str = "%d MB" % (page_bytes/1024/1024)
    elif page_bytes > 1024:
        result_str = "%d KB" % (page_bytes/1024)
    else:
        result_str = "%d B" % (page_bytes)

    return result_str


#
# There's a little bit of differece between the calculated totla
# and the output of kmem -i (CACHED).
def get_memory_bar(percentage, width=20):
    """
    Generate ASCII bar chart for memory usage percentage with 4 gradual shading levels
    """
    if percentage < 0:
        percentage = 0
    if percentage > 100:
        percentage = 100

    # Calculate exact filled width (as float to get fractional part)
    exact_filled = (percentage / 100.0) * width
    filled_count = int(exact_filled)
    fraction = exact_filled - filled_count

    # Shading characters for gradual fill
    empty_char = '░'   # Light shade for empty
    light_char = '▒'   # Medium shade for 0-33% fill
    medium_char = '▓'  # Heavy shade for 33-66% fill
    full_char = '█'    # Full block for 100% fill

    # Build the bar with gradual shading
    bar_chars = []

    # Add fully filled characters
    bar_chars.extend([full_char] * filled_count)

    # Add fractional character if there's remaining space
    if filled_count < width:
        if fraction >= 0.66:
            bar_chars.append(full_char)    # 66-100% shows as full (almost complete)
        elif fraction >= 0.33:
            bar_chars.append(medium_char)  # 33-66% shows as heavy shade
        elif fraction > 0:
            bar_chars.append(light_char)   # 1-33% shows as medium shade
        else:
            bar_chars.append(empty_char)   # Exactly 0 shows as empty

    # Fill remaining with empty characters
    remaining = width - len(bar_chars)
    bar_chars.extend([empty_char] * remaining)

    bar = '[' + ''.join(bar_chars) + ']'

    # Add color coding based on usage level
    if percentage >= 90:
        crashcolor.set_color(crashcolor.RED)
    elif percentage >= 70:
        crashcolor.set_color(crashcolor.YELLOW)
    elif percentage >= 50:
        crashcolor.set_color(crashcolor.CYAN)
    else:
        crashcolor.set_color(crashcolor.GREEN)

    return bar


def show_page_caches(options):
    global page_caches
    global wb_caches
    page_caches = {}
    wb_caches = {}
    super_blocks = readSymbol("super_blocks")
    for sb in readSUListFromHead(super_blocks,
                                 "s_list",
                                 "struct super_block"):
        try:
            if sb.s_instances.pprev == 0:
                continue
        except:
            pass

        if sb.s_root != 0 and (sb.s_flags & MS_BORN) != 0:
            show_pagecache_sb(sb, options)


    sorted_sb_dict = sorted(page_caches.items(),
                            key=operator.itemgetter(1), reverse=True)

    # Calculate total first for percentage calculation
    total_count = 0
    for sb, count in sorted_sb_dict:
        total_count = total_count + count

    exclude_count = 0
    print("=" * 80)
    print("%18s %8s %7s %6s  %-22s %s" %
          ("super_block", "pages", "bytes", "%", "Usage Bar", "root"))
    print("-" * 80)
    for sb, count in sorted_sb_dict:
        try:
            filename = dentry_to_filename(sb.s_root)
            if filename == "<blank>" or filename == "/dev/":
                exclude_count = exclude_count + count
                s_op_name = addr2sym(sb.s_op)
                if s_op_name == "shmem_ops":
                    filename = "shared memory"

            page_bytes = pages_to_str(count)
            percentage = (count * 100.0 / total_count) if total_count > 0 else 0
            bar = get_memory_bar(percentage, width=20)

            print("0x%16x %8d %7s %5.1f%%  %-22s %s" %
                  (sb, count, page_bytes, percentage, bar, filename[:20]))
            crashcolor.set_color(crashcolor.RESET)
        except:
            pass

    print("-" * 80)
    print("Total number of page caches = %d (%s)" %
          (total_count, pages_to_str(total_count)))
    pages_without_dev = (total_count - exclude_count)
    print("   (exclude /dev/ and unnamed root) = %d (%s)" %
          (pages_without_dev, pages_to_str(pages_without_dev)))
    print("=" * 80)


FS_HAS_WBLIST=131072

def show_pagecache_sb(sb, options):
    global page_caches
    global wb_caches

    count = 0
    if (sb.s_type.fs_flags & FS_HAS_WBLIST) == FS_HAS_WBLIST:
        if addr2sym(sb.s_type) == "xfs_fs_type":
            for wb_node in readSUListFromHead(sb.s_inodes_wb,
                                            "next",
                                            "struct list_head",
                                            maxel=5000000):
                offset = member_offset("struct xfs_inode", "i_wblist")
                xfs_inode = readSU("struct xfs_inode", wb_node - offset)
                count = count + xfs_inode.i_vnode.i_mapping.nrpages

    wb_caches[sb] = count

    for inode in readSUListFromHead(sb.s_inodes,
                                    "i_sb_list",
                                    "struct inode",
                                   maxel=50000000):
        mapping = inode.i_mapping
        if mapping.nrpages == 0 or (inode.i_state & I_SKIP_STATE) != 0:
            continue

        if sb not in page_caches:
            page_caches[sb] = 0
        page_caches[sb] = page_caches[sb] + mapping.nrpages

        if options.show_details:
            options.inode = "%x" % inode
            print("-" * 10)
            print("CACHED_PAGES : %d" % (mapping.nrpages))
            show_inode_details(options)


def get_inode_type_name(i_mode):
    fmt = i_mode & S_IFMT
    for mask, name in INODE_TYPE_NAMES:
        if fmt == mask:
            return name

    return "other (0%o)" % fmt


# Cached pages per inode, in buckets. The question this answers is whether a
# filesystem's cache is held by a handful of large files or by a swarm of
# small ones - which needs orders of magnitude, not even steps.
PAGE_BUCKETS = [
    (1,      "1 page"),
    (4,      "2 - 4"),
    (16,     "5 - 16"),
    (64,     "17 - 64"),
    (256,    "65 - 256"),
    (1024,   "257 - 1K"),
    (4096,   "1K - 4K"),
    (16384,  "4K - 16K"),
    (65536,  "16K - 64K"),
    (262144, "64K - 256K"),
    (None,   "over 256K"),
]


def get_page_bucket(pages):
    for idx, (limit, label) in enumerate(PAGE_BUCKETS):
        if limit is None or pages <= limit:
            return idx

    return len(PAGE_BUCKETS) - 1


def get_inode_filename(inode):
    """
    Best-effort path for an inode, through its first dentry.

    This runs a crash command per call, so it is only used for the handful
    of inodes actually being listed - never for every inode on the
    filesystem.
    """
    try:
        dentry_addr = get_first_dentry_addr(inode)
        if dentry_addr == 0:
            return "<no dentry>"

        return dentry_to_filename(readSU('struct dentry', dentry_addr))
    except Exception:
        return "<unknown>"


# A dentry chain deeper than this in a crash dump is a corrupt d_parent
# pointer, not a real path.
MAX_DENTRY_DEPTH = 64


def get_dentry_path(dentry, cache):
    """
    Path of a dentry within its own filesystem, by walking d_parent.

    This reads struct fields directly rather than going through
    'files -d' like dentry_to_filename(), because the breakdown resolves a
    path for every cached inode instead of just the few being listed.
    Ancestors are memoised in 'cache', so thousands of files sharing a
    handful of directories cost a handful of walks.

    The path is relative to the filesystem root, so it carries no mount
    point - which is the useful form here, since every inode being
    grouped belongs to the same superblock anyway.
    """
    chain = []
    seen = set()
    base = "/"
    cur = dentry

    for _ in range(MAX_DENTRY_DEPTH):
        addr = int(cur)
        if addr == 0:
            base = "..."        # ran off the chain before reaching a root
            break
        if addr in cache:
            base = cache[addr]
            break
        if addr in seen:        # d_parent ring; the dump is inconsistent
            base = "..."
            break
        seen.add(addr)

        parent = cur.d_parent
        if int(parent) == addr or int(parent) == 0:   # filesystem root
            cache[addr] = "/"
            break

        try:
            chain.append((addr, cur.d_name.name.string_()))
        except Exception:
            chain.append((addr, "<?>"))

        cur = parent
    else:
        base = "..."            # hit the depth cap, path is truncated

    path = base
    for addr, name in reversed(chain):
        path = path + name if path.endswith("/") else path + "/" + name
        cache[addr] = path

    return path


def get_inode_path(inode, cache):
    try:
        dentry_addr = get_first_dentry_addr(inode)
        if dentry_addr == 0:
            return ""

        return get_dentry_path(readSU('struct dentry', dentry_addr), cache)
    except Exception:
        return ""


def is_internal_shmem_sb(sb):
    """
    True if 'sb' is the kernel-internal shmem mount.

    shmem_file_setup() hands out inodes from a tmpfs that is kern_mount()ed,
    so it belongs to no namespace and appears in no mount table. Anonymous
    shared mappings (MAP_SHARED|MAP_ANONYMOUS), memfd_create(), SysV shared
    memory and DRM/GEM objects all live on it. Those inodes are unlinked by
    construction - they were never in a directory to begin with - and are
    held by mappings rather than by a path or an fd, which is why every
    name-based and fd-based lookup comes up empty for them.
    """
    for name in ("shm_mnt", "shmem_mnt"):
        try:
            mnt = readSymbol(name)
            if mnt is None or int(mnt) == 0:
                continue
        except Exception:
            continue

        try:
            mnt_sb = mnt.mnt_sb
        except Exception:
            # readSymbol gave back the bare pointer value rather than
            # dereferencing it, so do that ourselves
            try:
                mnt_sb = readSU("struct vfsmount", int(mnt)).mnt_sb
            except Exception:
                continue

        try:
            if int(mnt_sb) == int(sb):
                return True
        except Exception:
            continue

    return False


def get_i_mmap_root(inode):
    """
    Root rb_node of an inode's VMA interval tree: the mappings of this file.

    Returns 0 when nothing maps it, or None when the layout is not one we
    recognise - 'i_mmap' was a prio_tree_root before 3.9, a rb_root until
    4.14 and a rb_root_cached since. None means 'cannot tell', which must
    not be reported as 'not mapped'.
    """
    try:
        i_mmap = inode.i_mapping.i_mmap
    except Exception:
        return None

    try:
        return int(i_mmap.rb_root.rb_node)     # rb_root_cached, 4.14+
    except Exception:
        pass

    try:
        return int(i_mmap.rb_node)             # plain rb_root
    except Exception:
        return None


def get_mm_owners():
    """
    Map 'struct mm_struct' address -> 'comm (pid)', built once.

    Every thread of a process shares one mm, so prefer the thread group
    leader: reporting an arbitrary thread would print a tid where the reader
    expects a pid, and 'ps' would not find it.
    """
    owners = {}

    try:
        threads = Tasks.TaskTable().allThreads()
    except Exception:
        return owners

    for t in threads:
        try:
            mm = int(t.mm)
            if mm == 0:
                continue
            is_leader = True
            try:
                is_leader = (int(t.pid) == int(t.tgid))
            except Exception:
                pass
            if mm not in owners or is_leader:
                owners[mm] = "%s (%d)" % (t.comm, t.pid)
        except Exception:
            continue

    return owners


MAX_MMAP_VMAS = 512

_vma_shared_offset = None

def get_vma_shared_offset():
    """
    Offset of the interval-tree node within 'struct vm_area_struct'.

    Resolved once: this runs for every cached inode, and a per-inode symbol
    lookup is exactly the kind of cost that makes the walk unusable on a
    filesystem with tens of thousands of inodes.
    """
    global _vma_shared_offset

    if _vma_shared_offset is None:
        offset = member_offset("struct vm_area_struct", "shared.rb")
        if offset < 0:
            # 'rb' is the first member of the 'shared' struct, so the offset
            # of the one is the offset of the other
            offset = member_offset("struct vm_area_struct", "shared")
        _vma_shared_offset = offset

    return _vma_shared_offset


def get_inode_mappers(inode, mm_owners):
    """
    Processes that have this inode mapped, by walking its VMA interval tree.

    'foreach files' only knows about the fd table, so a file that was mapped
    and then had its fd closed - the normal life of a memfd or a POSIX shm
    segment - is invisible to it. The mapping still pins every page.

    Returns (mappers, vma_count, truncated), where vma_count is None when the
    mappings could not be read at all. None is not the same as zero: it means
    'cannot tell', and reporting it as 'nothing maps this' would invent a
    finding.
    """
    if mm_owners is None:
        mm_owners = {}

    root = get_i_mmap_root(inode)
    if root is None:
        return set(), None, False
    if root == 0:
        return set(), 0, False

    vma_offset = get_vma_shared_offset()
    if vma_offset < 0:
        return set(), None, False

    mappers = set()
    pending = [root]
    seen = set()

    while pending and len(seen) < MAX_MMAP_VMAS:
        node_addr = pending.pop()
        if node_addr == 0 or node_addr in seen:
            continue
        seen.add(node_addr)

        try:
            node = readSU("struct rb_node", node_addr)
            pending.append(int(node.rb_left))
            pending.append(int(node.rb_right))
        except Exception:
            continue

        try:
            vma = readSU("struct vm_area_struct", node_addr - vma_offset)
            mm = int(vma.vm_mm)
        except Exception:
            continue

        mappers.add(mm_owners.get(mm, "<mm %#x, no task>" % mm))

    # Real nodes still queued means the cap stopped us short, so the mapper
    # list for this inode is incomplete. NULL children do not count.
    truncated = any(node_addr != 0 for node_addr in pending)

    return mappers, len(seen), truncated


def get_inode_holders():
    """
    Map inode address -> set of (pid, comm), from 'foreach files'.

    This covers the fd table and nothing else, so an absent inode does not
    mean an unheld one - see get_inode_mappers() for the other half. One
    crash command for the whole system rather than one per inode, so the
    cost does not grow with the filesystem.
    """
    holders = {}
    pid = 0
    comm = ""

    try:
        output = exec_crash_command("foreach files")
    except Exception:
        return holders

    for line in output.splitlines():
        words = line.split()
        if not words:
            continue

        if words[0] == "PID:":
            try:
                pid = int(words[1])
            except (ValueError, IndexError):
                pid = 0
            comm = line.split("COMMAND:")[-1].strip().strip('"') \
                if "COMMAND:" in line else ""
            continue

        # FD  FILE  DENTRY  INODE  TYPE  PATH
        if len(words) >= 5 and words[0].isdigit():
            try:
                inode_addr = int(words[3], 16)
            except ValueError:
                continue
            if inode_addr not in holders:
                holders[inode_addr] = set()
            holders[inode_addr].add((pid, comm))

    return holders


def get_inode_uid(inode):
    try:
        return inode.i_uid.val
    except Exception:
        try:
            return int(inode.i_uid)
        except Exception:
            return -1


# Runs of digits, and long runs of hex, are the part of a generated
# filename that varies per instance.
VARYING_NAME_RE = re.compile(r'[0-9a-fA-F]{6,}|[0-9]+')


def _name_pattern_sub(match):
    # Decide by length, not by whether the run happens to be all digits:
    # a random 32-bit id renders as 'a1b2c3d4' or as '08154711', and those
    # are the same kind of name. Splitting them into two buckets would
    # defeat the grouping.
    return "<ID>" if len(match.group(0)) >= 6 else "<N>"


def get_name_pattern(name):
    """
    Collapse the varying part of a generated filename.

    'sess_a1b2c3d4' and 'sess_9f8e7d6c' are the same kind of file. When
    thousands of inodes are holding the cache, the thing worth seeing is
    that something is producing them, not each individual name.
    """
    return VARYING_NAME_RE.sub(_name_pattern_sub, name)


def get_path_prefix(path, depth):
    """Group a directory at 'depth' components, so siblings collapse."""
    if depth <= 0 or path == "":
        return path if path != "" else "/"

    parts = [p for p in path.split("/") if p != ""]
    if len(parts) <= depth:
        return "/" + "/".join(parts) if parts else "/"

    return "/" + "/".join(parts[:depth]) + "/..."


def _bump(table, key, pages):
    entry = table.get(key)
    if entry is None:
        table[key] = [1, pages]
    else:
        entry[0] = entry[0] + 1
        entry[1] = entry[1] + pages


def bytes_to_str(byte_size):
    """
    Compact human-readable size, for table columns.

    Unlike pages_to_str() this keeps one decimal place: the whole point of
    these tables is comparing consumers, and rounding 1.9 GB down to '1 GB'
    loses the comparison.
    """
    if byte_size >= 1024 * 1024 * 1024:
        return "%.1f GB" % (byte_size / 1024.0 / 1024 / 1024)
    if byte_size >= 1024 * 1024:
        return "%.1f MB" % (byte_size / 1024.0 / 1024)
    if byte_size >= 1024:
        return "%.1f KB" % (byte_size / 1024.0)

    return "%d B" % byte_size


def _print_stat_row(label, inodes, pages, total_pages, label_width=16):
    percentage = (pages * 100.0 / total_pages) if total_pages > 0 else 0
    bar = get_memory_bar(percentage, width=16)
    print("  %-*s %9d %10d %10s %6.1f%%  %s" %
          (label_width, label, inodes, pages, bytes_to_str(pages * page_size),
           percentage, bar))
    crashcolor.set_color(crashcolor.RESET)


def _print_group_table(title, header, table, total_pages, top_n,
                       label_width=16):
    """One '== title ==' section, biggest consumer first."""
    print("")
    print("== %s ==" % title)
    print("  %-*s %9s %10s %10s %7s  %s" %
          (label_width, header, "INODES", "PAGES", "BYTES", "%", "SHARE"))
    print("  " + "-" * (label_width + 60))

    rows = sorted(table.items(), key=lambda kv: kv[1][1], reverse=True)
    for key, (inodes, pages) in rows[:top_n]:
        label = str(key)
        if len(label) > label_width:
            # Keep the tail: the leaf of a path says more than its root
            label = "..." + label[-(label_width - 3):]
        _print_stat_row(label, inodes, pages, total_pages, label_width)

    if len(rows) > top_n:
        rest_inodes = sum(v[0] for _, v in rows[top_n:])
        rest_pages = sum(v[1] for _, v in rows[top_n:])
        _print_stat_row("(%d more)" % (len(rows) - top_n), rest_inodes,
                        rest_pages, total_pages, label_width)


def show_pagecache_sb_stats(options, sb_addr):
    """
    Break down what is holding the page cache of one filesystem.

    'fsinfo -r' says which superblock holds the pages. Given that
    superblock's address it is usually the next question that matters:
    which inodes inside it, what kind of files they are, and whether the
    pages sit in a few big files or are spread thin across many small ones.
    """
    try:
        sb = readSU("struct super_block", int(sb_addr, 16))
        fs_type = sb.s_type.name
    except Exception:
        print("Error: '%s' is not a readable 'struct super_block' address" %
              sb_addr)
        return

    top_n = options.top_count
    if top_n <= 0:
        top_n = 20

    internal_shmem = is_internal_shmem_sb(sb)
    mount_points = get_mount_points(sb)
    if mount_points:
        mount_path = ", ".join(mount_points)
    elif internal_shmem:
        # Not a missing mount point: this one is kern_mount()ed and has no
        # place in any namespace's mount table by design
        mount_path = "<kernel-internal shmem>"
    else:
        # Not in the mount table at all. For a superblock that is still
        # holding gigabytes of cache this is itself the finding: it has
        # been unmounted (often 'umount -l') or lives in a mount namespace
        # other than the one 'mount' reports, and is alive only because
        # something still references its inodes.
        mount_path = "<not mounted>"
    dev_major, dev_minor = get_dev_no(sb)

    total_pages = 0
    total_inodes = 0
    cached_inodes = 0
    cached_file_bytes = 0       # i_size of the inodes that hold cache
    by_type = {}                # type name -> [inodes, pages]
    buckets = [[0, 0] for _ in PAGE_BUCKETS]
    dirty_inodes = dirty_pages = 0
    writeback_inodes = 0
    fully_cached = barely_cached = 0
    sized_inodes = 0
    top_heap = []               # bounded min-heap of the largest consumers

    want_breakdown = getattr(options, "breakdown", 0)
    path_depth = getattr(options, "path_depth", 3)
    dentry_cache = {}           # dentry address -> resolved path
    by_dir = {}                 # directory -> [inodes, pages]
    by_pattern = {}             # filename pattern -> [inodes, pages]
    by_uid = {}                 # owner uid -> [inodes, pages]
    unlinked_inodes = unlinked_pages = 0
    unnamed_inodes = unnamed_pages = 0
    both_inodes = both_pages = 0        # unlinked AND unreachable: the overlap

    by_holder = {}                      # "comm (pid)" -> [inodes, pages]
    by_mapper = {}                      # same, for mmap rather than fd
    orphan_inodes = orphan_pages = 0            # no fd
    mapped_inodes = mapped_pages = 0            # mapped, fd or not
    orphan_mapped_inodes = orphan_mapped_pages = 0   # no fd, but mapped
    unheld_inodes = unheld_pages = 0            # no fd and no mapping either
    unknown_mmap_inodes = 0                     # mappings could not be read
    truncated_mmap_inodes = 0                   # more VMAs than we walked
    want_holders = bool(getattr(options, "holders", 0))
    holders = get_inode_holders() if want_holders else None
    mm_owners = get_mm_owners() if want_holders else None

    for inode in readSUListFromHead(sb.s_inodes,
                                    "i_sb_list",
                                    "struct inode",
                                    maxel=50000000):
        total_inodes = total_inodes + 1
        try:
            nrpages = inode.i_mapping.nrpages
            i_state = inode.i_state
        except Exception:
            continue

        if nrpages == 0 or (i_state & I_SKIP_STATE) != 0:
            continue

        try:
            i_mode = inode.i_mode
            i_size = inode.i_size
        except Exception:
            i_mode = i_size = 0

        try:
            i_nlink = inode.i_nlink
        except Exception:
            i_nlink = -1        # unknown, so do not claim it is unlinked

        cached_inodes = cached_inodes + 1
        total_pages = total_pages + nrpages
        cached_file_bytes = cached_file_bytes + i_size

        type_name = get_inode_type_name(i_mode)
        if type_name not in by_type:
            by_type[type_name] = [0, 0]
        by_type[type_name][0] = by_type[type_name][0] + 1
        by_type[type_name][1] = by_type[type_name][1] + nrpages

        bucket = buckets[get_page_bucket(nrpages)]
        bucket[0] = bucket[0] + 1
        bucket[1] = bucket[1] + nrpages

        if (i_state & I_DIRTY) != 0:
            dirty_inodes = dirty_inodes + 1
            dirty_pages = dirty_pages + nrpages
        if (i_state & I_SYNC) != 0:
            writeback_inodes = writeback_inodes + 1

        # How much of the file is actually resident. A file cached at 100%
        # was read whole; one cached at 2% is being sampled, and evicting
        # it buys little.
        if i_size > 0:
            size_pages = (i_size + page_size - 1) // page_size
            sized_inodes = sized_inodes + 1
            resident = (nrpages * 100.0 / size_pages) if size_pages > 0 else 0
            if resident >= 90:
                fully_cached = fully_cached + 1
            elif resident < 10:
                barely_cached = barely_cached + 1

        if want_breakdown:
            path = get_inode_path(inode, dentry_cache)
            if path == "" or path == "/":
                # No path leads here: a deleted file still pinned by an fd,
                # or a dentry disconnected from the tree
                unnamed_inodes = unnamed_inodes + 1
                unnamed_pages = unnamed_pages + nrpages
                if i_nlink == 0:
                    both_inodes = both_inodes + 1
                    both_pages = both_pages + nrpages
            else:
                name = path.rsplit("/", 1)[-1]
                dirname = path.rsplit("/", 1)[0]
                if dirname == "":
                    dirname = "/"
                _bump(by_dir, get_path_prefix(dirname, path_depth), nrpages)
                _bump(by_pattern, get_name_pattern(name), nrpages)

            _bump(by_uid, get_inode_uid(inode), nrpages)

            if i_nlink == 0:
                unlinked_inodes = unlinked_inodes + 1
                unlinked_pages = unlinked_pages + nrpages

        if holders is not None:
            who = holders.get(int(inode))
            if who:
                for pid, comm in who:
                    _bump(by_holder, "%s (%d)" % (comm, pid), nrpages)
            else:
                orphan_inodes = orphan_inodes + 1
                orphan_pages = orphan_pages + nrpages

            # An fd is not the only thing that pins an inode. A file that was
            # mapped and then had its fd closed - the normal life of a memfd
            # or a POSIX shm segment - holds every one of its pages through
            # the mapping alone, and 'foreach files' cannot see it.
            mappers, vma_count, truncated = get_inode_mappers(inode, mm_owners)
            if truncated:
                truncated_mmap_inodes = truncated_mmap_inodes + 1

            if vma_count is None:
                # Could not read the mappings. Saying 'nothing maps this'
                # here would manufacture a finding out of a missing struct.
                unknown_mmap_inodes = unknown_mmap_inodes + 1
            elif vma_count > 0:
                mapped_inodes = mapped_inodes + 1
                mapped_pages = mapped_pages + nrpages
                if not who:
                    orphan_mapped_inodes = orphan_mapped_inodes + 1
                    orphan_mapped_pages = orphan_mapped_pages + nrpages
                for mapper in mappers:
                    _bump(by_mapper, mapper, nrpages)
            elif not who:
                unheld_inodes = unheld_inodes + 1
                unheld_pages = unheld_pages + nrpages

        # cached_inodes is a unique increasing key, so tuple comparison
        # never has to order the inode objects themselves
        entry = (nrpages, cached_inodes, inode, i_mode, i_size, i_state,
                 i_nlink)
        if len(top_heap) < top_n:
            heapq.heappush(top_heap, entry)
        elif nrpages > top_heap[0][0]:
            heapq.heapreplace(top_heap, entry)

    print("=" * 80)
    print("Page cache statistics for super_block 0x%x" % sb)
    print("=" * 80)
    print("  %-22s : %s" % ("Filesystem type", fs_type))
    print("  %-22s : %s" % ("Device", sb.s_id))
    print("  %-22s : %d:%d" % ("Device number", dev_major, dev_minor))
    print("  %-22s : %s" % ("Mounted on", mount_path))
    print("  %-22s : %d" % ("Block size", sb.s_blocksize))
    print("  %-22s : %d (%s)" %
          ("Cached pages", total_pages,
           bytes_to_str(total_pages * page_size)))
    print("  %-22s : %d of %d inodes on this filesystem" %
          ("Inodes holding cache", cached_inodes, total_inodes))

    if total_pages == 0:
        print("-" * 80)
        print("This filesystem is holding no page cache.")
        print("=" * 80)
        return

    avg_pages = total_pages / float(cached_inodes)
    print("  %-22s : %.1f pages (%s)" %
          ("Average per inode", avg_pages,
           bytes_to_str(int(avg_pages) * page_size)))

    print("")
    print("== Cache by file type ==")
    print("  %-16s %9s %10s %10s %7s  %s" %
          ("TYPE", "INODES", "PAGES", "BYTES", "%", "SHARE"))
    print("  " + "-" * 76)
    for type_name, (inodes, pages) in sorted(by_type.items(),
                                             key=lambda kv: kv[1][1],
                                             reverse=True):
        _print_stat_row(type_name, inodes, pages, total_pages)

    print("")
    print("== Cached pages per inode ==")
    print("  %-16s %9s %10s %10s %7s  %s" %
          ("PAGES/INODE", "INODES", "PAGES", "BYTES", "%", "SHARE"))
    print("  " + "-" * 76)
    for idx, (limit, label) in enumerate(PAGE_BUCKETS):
        inodes, pages = buckets[idx]
        if inodes == 0:
            continue
        _print_stat_row(label, inodes, pages, total_pages)

    print("")
    print("== Cache density ==")
    cached_bytes = total_pages * page_size
    print("  %-30s : %s" % ("Size of the cached files",
                            bytes_to_str(cached_file_bytes)))
    print("  %-30s : %s" % ("Held in the page cache",
                            bytes_to_str(cached_bytes)))
    if cached_file_bytes > 0:
        resident_pct = cached_bytes * 100.0 / cached_file_bytes
        print("  %-30s : %.1f%%" % ("Resident share of those files",
                                    resident_pct))
    if sized_inodes > 0:
        print("  %-30s : %d (%.1f%%)" %
              ("Files cached 90% or more", fully_cached,
               fully_cached * 100.0 / sized_inodes))
        print("  %-30s : %d (%.1f%%)" %
              ("Files cached under 10%", barely_cached,
               barely_cached * 100.0 / sized_inodes))

    if dirty_inodes > 0 or writeback_inodes > 0:
        print("")
        print("== Dirty and writeback ==")
        crashcolor.set_color(crashcolor.YELLOW if dirty_inodes > 0
                             else crashcolor.RESET)
        print("  %-30s : %d inode(s), up to %d page(s) (%s)" %
              ("Dirty", dirty_inodes, dirty_pages,
               bytes_to_str(dirty_pages * page_size)))
        crashcolor.set_color(crashcolor.RESET)
        print("  %-30s : %d inode(s)" % ("Writeback in progress",
                                         writeback_inodes))
        print("  (the dirty page count is the whole cache of the dirty")
        print("   inodes, an upper bound - not every page of them is dirty)")

    if want_breakdown:
        if not by_dir and not by_pattern:
            print("")
            print("== Cache by directory / filename ==")
            print("  Not available: no path could be resolved for any of the")
            print("  %d cached inode(s) on this filesystem." % cached_inodes)
            if internal_shmem:
                print("  That is expected here - see the note at the end: on")
                print("  the internal shmem mount the inodes never had a name.")
            else:
                print("  Their dentries are disconnected from the tree, which")
                print("  happens to a file unlinked while still referenced.")
            print("  See 'Held without a name' below, and use '--holders' to")
            print("  find what is still referencing them.")

        if by_dir:
            _print_group_table("Cache by directory", "DIRECTORY", by_dir,
                               total_pages, top_n, label_width=44)
            if path_depth > 0:
                print("  (directories grouped at %d path component(s); "
                      "--depth 0 for full paths)" % path_depth)
        if by_pattern:
            _print_group_table("Cache by filename pattern", "PATTERN",
                               by_pattern, total_pages, top_n,
                               label_width=40)
            print("  (varying ids collapsed to <ID>, short numbers to <N>)")
        if by_uid:
            _print_group_table("Cache by owner", "UID", by_uid,
                               total_pages, top_n, label_width=16)

        if unlinked_inodes > 0 or unnamed_inodes > 0:
            # These two overlap - an unlinked file usually has no reachable
            # path either - so report the overlap instead of printing the
            # same pages twice and letting them read as a sum.
            union_inodes = unlinked_inodes + unnamed_inodes - both_inodes
            union_pages = unlinked_pages + unnamed_pages - both_pages

            print("")
            print("== Held without a name ==")
            crashcolor.set_color(crashcolor.YELLOW)
            print("  %-34s : %d inode(s), %s" %
                  ("Unlinked (i_nlink == 0)", unlinked_inodes,
                   bytes_to_str(unlinked_pages * page_size)))
            print("  %-34s : %d inode(s), %s" %
                  ("No path to them (disconnected)", unnamed_inodes,
                   bytes_to_str(unnamed_pages * page_size)))
            print("  %-34s : %d inode(s), %s" %
                  ("  both of the above", both_inodes,
                   bytes_to_str(both_pages * page_size)))
            print("  %-34s : %d inode(s), %s (%.1f%% of the cache)" %
                  ("Either, counted once", union_inodes,
                   bytes_to_str(union_pages * page_size),
                   union_pages * 100.0 / total_pages))
            crashcolor.set_color(crashcolor.RESET)
            print("  (no path reaches these pages; something holds a")
            print("   reference to the inode, and they are freed when the")
            print("   last such reference goes away)")

            if unlinked_inodes == cached_inodes and cached_inodes > 0:
                crashcolor.set_color(crashcolor.LIGHTRED)
                print("")
                print("  ** Every cached inode here is unlinked. Nothing can")
                print("     be reclaimed by deleting a file - they are all")
                print("     deleted already. Use '--holders' to find what is")
                print("     still referencing them. **")
                crashcolor.set_color(crashcolor.RESET)

        if holders is not None:
            if by_holder:
                _print_group_table("Cache held open by each process (fd)",
                                   "PROCESS (PID)", by_holder, total_pages,
                                   top_n, label_width=28)
                print("  (a file open in several processes is counted under")
                print("   each of them, so these shares can exceed 100%)")

            if by_mapper:
                _print_group_table("Cache mapped by each process (mmap)",
                                   "PROCESS (PID)", by_mapper, total_pages,
                                   top_n, label_width=28)
                print("  (mappings pin every page just as an open fd does,")
                print("   and outlive the fd they were created from; an inode")
                print("   mapped by several processes is counted under each,")
                print("   so these shares can exceed 100%)")
                if truncated_mmap_inodes > 0:
                    print("  (%d inode(s) have more than %d mappings; only the"
                          % (truncated_mmap_inodes, MAX_MMAP_VMAS))
                    print("   first %d were walked, so some processes holding"
                          % MAX_MMAP_VMAS)
                    print("   them are missing from this table)")

            if not holders:
                # Nothing at all parsed out of 'foreach files'. That is a
                # tooling problem, not a finding - say so rather than letting
                # it read as 'no process holds anything'.
                crashcolor.set_color(crashcolor.YELLOW)
                print("")
                print("  Note: 'foreach files' produced no usable rows, so the")
                print("  fd attribution above is empty for want of input, not")
                print("  because nothing holds these files.")
                crashcolor.set_color(crashcolor.RESET)
            elif orphan_inodes > 0:
                print("")
                print("  %-34s : %d inode(s), %s" %
                      ("Not open by any fd", orphan_inodes,
                       bytes_to_str(orphan_pages * page_size)))
                if orphan_mapped_inodes > 0:
                    print("  %-34s : %d inode(s), %s" %
                          ("  of those, held by a mapping",
                           orphan_mapped_inodes,
                           bytes_to_str(orphan_mapped_pages * page_size)))

            if unknown_mmap_inodes > 0:
                crashcolor.set_color(crashcolor.YELLOW)
                print("")
                print("  %-34s : %d inode(s)" %
                      ("Mappings could not be read", unknown_mmap_inodes))
                crashcolor.set_color(crashcolor.RESET)
                print("  ('i_mmap' is not a layout this build understands, so")
                print("   these are left unclassified rather than reported as")
                print("   unmapped)")

            if unheld_inodes > 0 and holders:
                # No fd, no mapping, and no name. Worth spelling out what is
                # left, because the usual advice - find the process and close
                # the fd - does not apply to any of it.
                print("")
                crashcolor.set_color(crashcolor.YELLOW)
                print("  %-34s : %d inode(s), %s" %
                      ("No fd and no mapping", unheld_inodes,
                       bytes_to_str(unheld_pages * page_size)))
                crashcolor.set_color(crashcolor.RESET)
                print("  A 'struct file' or an inode reference is holding")
                print("  these, rather than anything a process can be asked")
                print("  to let go of. On tmpfs/shmem the usual causes are:")
                print("    - SysV shared memory that exists but is attached")
                print("      to nothing: the IPC namespace holds it on its")
                print("      own ('ipcs -m', NATTCH 0). An *attached*")
                print("      segment has a VMA and would be in the mmap")
                print("      table above instead.")
                print("    - a memfd or shm fd passed over a unix socket and")
                print("      still in the receiver's queue (SCM_RIGHTS): a")
                print("      live 'struct file' in no fd table at all")
                print("    - a loop device's backing file, or a swapfile")
                print("    - GEM/DRM buffers, which map through the DRM node")
                print("      rather than through this inode")

            if internal_shmem:
                print("")
                crashcolor.set_color(crashcolor.LIGHTRED)
                print("  ** This is the kernel-internal shmem mount. **")
                crashcolor.set_color(crashcolor.RESET)
                print("  It is kern_mount()ed, so it is in no mount table and")
                print("  none of its inodes were ever linked into a directory")
                print("  - 'unlinked' and 'no path' are its normal state, not")
                print("  a leak in themselves. shmem_file_setup() allocates")
                print("  from it for anonymous shared mappings, memfd_create(),")
                print("  SysV shared memory and DRM/GEM buffers, so read the")
                print("  size as shared-memory usage rather than page cache.")

    print("")
    print("== Top %d inodes by cached pages ==" % min(top_n, cached_inodes))
    print("  %-18s %10s %10s %7s %10s %8s  %s" %
          ("inode", "PAGES", "CACHED", "%", "SIZE", "RESIDENT", "FILE"))
    print("  " + "-" * 92)
    for nrpages, _seq, inode, i_mode, i_size, i_state, i_nlink in \
            sorted(top_heap, reverse=True):
        percentage = nrpages * 100.0 / total_pages
        size_pages = (i_size + page_size - 1) // page_size
        if size_pages > 0:
            resident_str = "%7.1f%%" % min(100.0,
                                           nrpages * 100.0 / size_pages)
        else:
            resident_str = "      --"

        # The d_parent walk gives a full path and costs no crash command,
        # so prefer it; fall back to 'files -d' when it finds no name
        filename = get_inode_path(inode, dentry_cache)
        if filename == "" or filename == "/":
            filename = get_inode_filename(inode)
        named = filename not in ("", "/", "<no dentry>", "<blank>",
                                 "<invalid>")
        if not named:
            # Say why there is no name rather than leaving a placeholder
            filename = "<deleted>" if i_nlink == 0 else "<no path>"

        marks = ""
        if i_nlink == 0 and named:
            # '<deleted>' already carries this; do not say it twice
            marks = marks + " [deleted]"
        if (i_state & I_DIRTY) != 0:
            marks = marks + " [dirty]"
        if (i_state & I_SYNC) != 0:
            marks = marks + " [writeback]"
        print("  0x%-16x %10d %10s %6.1f%% %10s %8s  %s%s" %
              (inode, nrpages, bytes_to_str(nrpages * page_size), percentage,
               bytes_to_str(i_size), resident_str, filename, marks))

    print("=" * 80)
    print("Total %d page(s) (%s) cached by %d inode(s) on %s" %
          (total_pages, bytes_to_str(total_pages * page_size),
           cached_inodes, mount_path))
    print("=" * 80)


BLOCK_SIZE_BITS = 10
BLOCKSIZE = 1 << BLOCK_SIZE_BITS

def get_uuid(s_uuid):
    result = "%0.2x%0.2x%0.2x%0.2x" % (s_uuid[0], s_uuid[1], s_uuid[2], s_uuid[3])
    result = ""
    for i in range(0, 4):
        result = result + "%0.2x" % (s_uuid[i])

    result = result + "-"
    for i in range(4, 6):
        result = result + "%0.2x" % (s_uuid[i])

    result = result + "-"
    for i in range(6, 8):
        result = result + "%0.2x" % (s_uuid[i])

    result = result + "-"
    for i in range(8, 16):
        result = result + "%0.2x" % (s_uuid[i])

    return result



def get_volume_name(s_volume_name):
    if s_volume_name.strip() == '':
        return "<none>"

    return s_volume_name


def get_attr_str(flags, flags_list, bitop=True):
    result = ""
    idx = 0
    if bitop:
        while flags > 0:
            key = 1 << idx
            if ((flags & 1) == 1) and (key in flags_list):
                result = result + flags_list[key] + " "
            idx = idx + 1
            flags = flags >> 1
    else:
        for key in flags_list:
            if (flags & key) == key:
                result = result + flags_list[key] + " "

    return result


def get_creator_os(creator_os):
    creator_os_list = {4: "lites",
                       3: "FreeBSD",
                       2: "Masix",
                       1: "Hurd",
                       0: "Linux"}
    result = get_attr_str(creator_os, creator_os_list, False)
    return result


def get_errors_behavior(s_errors):
    s_errors_list = {1: "Continue",
                     2: "Read-only",
                     3: "Panic"}
    result = get_attr_str(s_errors, s_errors_list, False)
    return result


def get_fs_state(s_state):
    fs_states_list = {0x0001: "clean",
                      0x0002: "error",
                      0x0004: "orphan"}
    result = get_attr_str(s_state, fs_states_list)
    return result


def get_default_mount_options(mount_options):
    mount_options_list = {0x00400: "journal_data",
                          0x02000: "no_uid32",
                          0x04000: "user_xattr",
                          0x08000: "acl"}
    result = get_attr_str(mount_options, mount_options_list)
    return result


def get_ext_flags(s_flags):
    s_flags_list = {0x0001: "signed_directory_hash",
                    0x0002: "unsigned_directory_hash",
                    0x0004: "test filesystem"}

    result = get_attr_str(s_flags, s_flags_list)
    return result


def get_extX_features(extX_super_block):
    s_feature_compat = extX_super_block.s_feature_compat
    s_feature_incompat = extX_super_block.s_feature_incompat
    s_feature_ro_compat = extX_super_block.s_feature_ro_compat

    compat_list = {0x0001: "dir_prealloc",
                   0x0002: "imagic_inodes",
                   0x0004: "has_journal",
                   0x0008: "ext_attr",
                   0x0010: "resize_inode",
                   0x0020: "dir_index",
                   0x0200: "sparse_super2"}

    ro_compat_list = {0x0001: "sparse_super",
                      0x0002: "large_file",
                      0x0004: "btree_dir",
                      0x0008: "huge_file",
                      0x0010: "uninit_bg", #"gdt_csum",
                      0x0020: "dir_nlink",
                      0x0040: "extra_isize",
                      0x0100: "quota",
                      0x0200: "bigalloc"}

    incompat_list = {0x0001: "compression",
                     0x0002: "filetype",
                     0x0004: "recover",
                     0x0008: "journal_dev",
                     0x0010: "meta_bg",
                     0x0040: "extents",
                     0x0080: "64bit",
                     0x0100: "mmp",
                     0x0200: "flex_bg",
                     0x0400: "ea_inode",
                     0x1000: "dirdata",
                     0x2000: "bg_use_meta_csum",
                     0x4000: "largedir",
                     0x8000: "inline_data"}

    result = get_attr_str(s_feature_compat, compat_list)
    result = result + get_attr_str(s_feature_incompat, incompat_list)
    result = result + get_attr_str(s_feature_ro_compat, ro_compat_list)

    return result


def show_extX_details(sb, fs_type):
    try:
        if fs_type == "ext4":
            extX_sb_info = readSU("struct ext4_sb_info", sb.s_fs_info)
            extX_super_block = readSU("struct ext4_super_block", extX_sb_info.s_es)

            s_blocks_count = (extX_super_block.s_blocks_count_hi << 32) +\
                            extX_super_block.s_blocks_count_lo
            s_r_blocks_count = (extX_super_block.s_r_blocks_count_hi << 32) +\
                            extX_super_block.s_r_blocks_count_lo
            s_free_blocks_count = (extX_super_block.s_free_blocks_count_hi << 32) +\
                            extX_super_block.s_free_blocks_count_lo
            s_frag_size = 0
        elif fs_type == "ext3":
            extX_sb_info = readSU("struct ext3_sb_info", sb.s_fs_info)
            extX_super_block = readSU("struct ext3_super_block", extX_sb_info.s_es)

            s_blocks_count = (extX_super_block.s_blocks_count_hi << 32) +\
                            extX_super_block.s_blocks_count
            s_r_blocks_count = (extX_super_block.s_r_blocks_count_hi << 32) +\
                            extX_super_block.s_r_blocks_count
            s_free_blocks_count = (extX_super_block.s_free_blocks_count_hi << 32) +\
                            extX_super_block.s_free_blocks_count
            s_frag_size = BLOCKSIZE << extX_super_block.s_log_frag_size
        elif fs_type == "ext2":
            extX_sb_info = readSU("struct ext2_sb_info", sb.s_fs_info)
            extX_super_block = readSU("struct ext2_super_block", extX_sb_info.s_es)

            s_blocks_count = (extX_super_block.s_blocks_count_hi << 32) +\
                            extX_super_block.s_blocks_count
            s_r_blocks_count = (extX_super_block.s_r_blocks_count_hi << 32) +\
                            extX_super_block.s_r_blocks_count
            s_free_blocks_count = (extX_super_block.s_free_blocks_count_hi << 32) +\
                            extX_super_block.s_free_blocks_count
            s_frag_size = BLOCKSIZE << extX_super_block.s_log_frag_size
        else:
            return

        s_block_size = BLOCKSIZE << extX_super_block.s_log_block_size

        print("< struct super_block 0x%x >" % sb)
        print("%-30s %s" % ("Filesystem volume name:", get_volume_name(extX_super_block.s_volume_name)))
        mnt_point = dentry_to_filename(sb.s_root)
        print("%-30s %s" % ("Last mounted on:", extX_super_block.s_last_mounted))
        print("%-30s %s" % ("Filesystem UUID:", get_uuid(extX_super_block.s_uuid)))
        print("%-30s 0x%X" % ("Filesystem magic number:", sb.s_magic))
        print("%-30s %d (%s)" % ("Filesystem revision #:", extX_super_block.s_rev_level, "dynamic" if extX_super_block.s_rev_level > 0 else "original"))
        print("%-30s %s" % ("Filesystem features:", get_extX_features(extX_super_block)))
        if fs_type != "ext2":
            print("%-30s %s" % ("Filesystem flags:", get_ext_flags(extX_super_block.s_flags)))

        print("%-30s %s" % ("Default mount options:", get_default_mount_options(extX_sb_info.s_mount_opt)))
        print("%-30s %s" % ("Filesystem state:", get_fs_state(extX_super_block.s_state)))
        print("%-30s %s" % ("Errors behavior:", get_errors_behavior(extX_super_block.s_errors)))
        print("%-30s %s" % ("Filesystem OS type:", get_creator_os(extX_super_block.s_creator_os)))
        print("%-30s %d" % ("Inode count:", extX_super_block.s_inodes_count))
        print("%-30s %d (%d KBytes)" % ("Block count:", s_blocks_count,
                                        (s_blocks_count * s_block_size) // 1024))
        print("%-30s %d (%d KBytes)" % ("Reserved block count:", s_r_blocks_count,
                                        (s_r_blocks_count * s_block_size) // 1024))
        print("%-30s %d (%d Kbytes)" % ("Free blocks:", s_free_blocks_count,
                                        (s_free_blocks_count * s_block_size) // 1024))
        print("%-30s %d" % ("Free inodes:", extX_super_block.s_free_inodes_count))
        print("%-30s %d" % ("First block:", extX_super_block.s_first_data_block))
        print("%-30s %d" % ("Block size:", s_block_size))
        print("%-30s %d" % ("Fragment size:", s_frag_size))
        if fs_type != "ext2":
            print("%-30s %d" % ("Reserved GDT blocks:", extX_super_block.s_reserved_gdt_blocks))
        # That's enough for now. The remaining will be implemented later if needed
        print("")
        print("# Available %d MBytes on %s" % ((s_free_blocks_count * s_block_size) / (1024 * 1024), mnt_point))
    except:
        print("Can't read details for 0x%x (%s)" % (sb, dentry_to_filename(sb.s_root)), end='')
        return


def show_xfs_details(sb, fs_type):
    xfs_mount = readSU("struct xfs_mount", sb.s_fs_info)
    xfs_sb = xfs_mount.m_sb
    if member_offset("struct xfs_mount", "m_fsname") >= 0:
        volume_name = get_volume_name(xfs_mount.m_fsname)
    else:
        volume_name = get_volume_name(xfs_sb.sb_fname)

    print("< struct super_block 0x%x >" % sb)
    print("%-30s %s" % ("Filesystem volume name", volume_name))
    mnt_point = dentry_to_filename(sb.s_root)
    print("%-30s %s" % ("Mount point", mnt_point))
    print("%-30s %x" % ("Magic number", xfs_sb.sb_magicnum))
    print("%-30s %d" % ("Block size", xfs_sb.sb_blocksize))
    print("%-30s %d" % ("Number of data blocks", xfs_sb.sb_dblocks))
    print("%-30s %d" % ("Number of realtime blocks", xfs_sb.sb_rblocks))

    print("%-30s %s" % ("UUID", get_uuid(xfs_sb.sb_uuid.b)))
    print("%-30s %d" % ("Size of an allocation group", xfs_sb.sb_agblocks))
    print("%-30s %d" % ("Number of allocation groups", xfs_sb.sb_agcount))
    print("%-30s %d" % ("Sector size(bytes)", xfs_sb.sb_sectsize))
    print("%-30s %d" % ("inode size(bytes)", xfs_sb.sb_inodesize))

    print("%-30s %d" % ("allocated inode count", xfs_sb.sb_icount))
    print("%-30s %d" % ("free inodes", xfs_sb.sb_ifree))
    print("%-30s %d" % ("free data blocks", xfs_sb.sb_fdblocks))
    print("%-30s %d" % ("free realtime extents", xfs_sb.sb_frextents))

    print("")
    print("# Available %d MBytes on %s" % ((xfs_sb.sb_blocksize * xfs_sb.sb_fdblocks) / (1024 * 1024), mnt_point))
    pass

def show_superblock(sb):
    fs_type = sb.s_type.name
    try:
        if fs_type == "ext4":
            show_extX_details(sb, fs_type)
            print()
        elif fs_type =="xfs":
            show_xfs_details(sb, fs_type)
            print()
    except Exception as e:
        print("Error in handling", sb)
        print(e)


def show_dumpe2fs(options):
    if options.dumpe2fs == "*":
        options.dumpe2fs = '.'

    super_blocks = sym2addr("super_blocks")
    printed = False
    for sb in readSUListFromHead(super_blocks,
                                "s_list",
                                "struct super_block"):
        mount_name = dentry_to_filename(sb.s_root)
        try:
            if re.search(options.dumpe2fs, mount_name):
                show_superblock(sb)
        except:
            if printed == False:
                print("Error occured. Please check your regular expression.")
                printed = True



def show_fsnotify_group(options):
    fsnotify_group = readSU("struct fsnotify_group",
                            int(options.fsnotify_group, 16))
    if member_offset("struct __wait_queue_head", "task_list") >= 0:
        notification_tasklist = fsnotify_group.notification_waitq.task_list
        field_name="task_list"
        wait_queue_name="struct __wait_queue"
    else:
        # RHEL8 uses different names for structure and entries
        notification_tasklist = fsnotify_group.notification_waitq.head
        field_name="entry"
        wait_queue_name="struct wait_queue_entry"

    for wq in readSUListFromHead(notification_tasklist,
                                 field_name,
                                 wait_queue_name):
        func = addr2sym(wq.func)
        print(wq)
        if func == "pollwake":
            pwq = readSU("struct poll_wqueues", wq.private)
            print("\tfunc: %s, task: %s <%s>" %
                  (func, pwq.polling_task, pwq.polling_task.comm))
        elif func == "woken_wake_function":
            tsk = readSU("struct task_struct", wq.private)
            print("\tfunc: %s, task: %s <%s>" %
                  (func, tsk, tsk.comm))
        elif func == "ep_poll_callback":
            print(func)
            epitem_offset = member_offset("struct eppoll_entry", "wait")
            eppoll_entry = readSU("struct eppoll_entry", wq - epitem_offset)
            epi = eppoll_entry.base
            ep = epi.ep
            print(epi)
            print(ep.wq)


    if options.show_details:
        if member_offset("struct fsnotify_group", "notification_list") >= 0:
            print("%s Notification List %s" % ("-"*20, "-"*20))
            inode_list = {}
            notification_list = fsnotify_group.notification_list
            for fsnotify_event in readSUListFromHead(notification_list,
                                                     "list",
                                                     "struct fsnotify_event"):
                inode_list[fsnotify_event.inode] = fsnotify_event

            for inode in inode_list:
                print(inode_list[inode])
                options.inode = "%x" % inode
                show_inode_details(options)

    if options.show_details:
        print("%s Process with fsnofiy_group %s" % ("-"*20, "-"*20))
    tt = Tasks.TaskTable()
    fsnotify_owner_task = None
    fsnotify_file = None
    fsnotify_file_str = None
    for t in tt.allThreads():
        files_result = exec_crash_command("files %d" % t.pid)
        if files_result.find("[fanotify]") < 0:
            continue
        files_list = files_result.splitlines()
        for f in files_list:
            if f.find("[fanotify]") < 0:
                continue
            words = f.split()
            file_data = readSU("struct file", int(words[1], 16))
            if file_data.private_data == fsnotify_group:
                if options.show_details:
                    print("PID : %d (%s)" % (t.pid, t.comm))
                    print(f)
                if t.pid == t.tgid:
                    fsnotify_owner_task = t
                    fsnotify_file = file_data
                    fsnotify_file_str = f


    if member_offset("struct fsnotify_group", "user_waits") >= 0:
        fsnotify_group_ops_cmd = "struct fsnotify_group.ops,user_waits 0x%x -d" % (fsnotify_group)
    else:
        fsnotify_group_ops_cmd = "struct fsnotify_group.ops 0x%x -d" % (fsnotify_group)
    try:
        print("\ncrash> %s" % fsnotify_group_ops_cmd)
        print(exec_crash_command(fsnotify_group_ops_cmd))
    except:
        pass

    if fsnotify_owner_task != None:
        print()
        crashcolor.set_color(crashcolor.LIGHTGREEN)
        print("fsnotify owner = ", end="")
        print(fsnotify_owner_task)
        crashcolor.set_color(crashcolor.RESET)
        if fsnotify_file_str != None:
            print("\ncrash> files %d | grep fanotify" % (fsnotify_owner_task.pid))
            print(fsnotify_file_str)
            print("\ncrash> struct file.private_data 0x%x" % fsnotify_file)
            print("  private_data = 0x%x, <-- same as fsnotify_group" %
                  fsnotify_file.private_data)


'''
        if member_offset("struct fsnotify_group", "fanotify_data") >= 0:
            print("%s Access wait List %s" % ("-"*20, "-"*20))
            access_waitq = fsnotify_group.fanotify_data.access_waitq
            cmd_str = "waitq 0x%x" % access_waitq
            print(cmd_str)
            print(exec_crash_command(cmd_str))
'''


DCACHE_ENTRY_TYPE=0x07000000
DCACHE_MISS_TYPE=0x00000000

def show_negative_dentries(options):
    result_lines = exec_crash_command("kmem -S dentry").splitlines()
    neg_cnt = 0
    total_cnt = 0
    for line in result_lines:
        words = line.split()
        if (len(words) == 0 or not words[0].startswith("[")):
            continue
        try:
            dentry = readSU("struct dentry", int(words[0][1:-1], 16))
            total_cnt = total_cnt + 1
            if (dentry.d_flags & DCACHE_ENTRY_TYPE) == DCACHE_MISS_TYPE:
                neg_cnt = neg_cnt + 1
                if options.show_details:
                    print("%s" % dentry_to_filename(dentry))
        except:
            continue

    print("Based on kmem -S dentry")
    print("Negative dentries : %d" % (neg_cnt))
    print("Total dentries    : %d" % (total_cnt))

    result_lines = exec_crash_command("p dentry_stat -d")
    print()
    print(result_lines)

def show_task_info(options):
    task_addr = int(options.task_info, 16)
    task_struct =readSU("struct task_struct", task_addr)
    print("0x%x : %s (%d)" % (task_struct, task_struct.comm, task_struct.pid))
    print("")
    options.file = "%x" % (task_struct.mm.exe_file)
    show_file_details(options)


PAGE_SIZE=0
_PAGE_FILE = 0x40


def init_swap_data():
    global PAGE_SIZE
    global _PAGE_FILE

    PAGE_SIZE = 1 << get_page_shift()
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        _PAGE_FILE = 0x40
    if (sys_info.machine.startswith("arm")):
        _PAGE_FILE = (1 << 2)
    if (arch in ("aarch64")):
        _PAGE_FILE = (1 << 2)
    if (sys_info.machine.startswith("ppc")):
        pass
    if (sys_info.machine.startswith("s390")):
        _PAGE_FILE = 0x601


MM_SWAPENTS = 2

def show_task_swap_usage(task, options):
    swap_usage = 0
    mm_struct = task.mm
    if mm_struct == 0:
        return
    swap_count = mm_struct.rss_stat.count[MM_SWAPENTS]
    try:
        swap_usage = swap_count.counter
    except:
        swap_usage = int(swap_count)

    if swap_usage > 0:
        print("%10d %15d %s" % (task.pid, swap_usage, task.comm))


def show_swap_usage(options):
    init_swap_data()
    init_task = readSymbol("init_task")
    print("%10s %15s %s" % ("PID", "SWAP", "COMM"))
    for task in readSUListFromHead(init_task.tasks,
                                   "tasks",
                                   "struct task_struct",
                                   maxel=5000000):
        show_task_swap_usage(task, options)


def fsinfo():
    op = OptionParser()
    op.add_option("-a", "--all", dest="all", default=0,
                  action="store_true",
                  help="Show all")
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show detailed information")
    op.add_option("-c", "--caches", dest="show_caches", default=0,
                  action="store_true",
                  help="Show dentry/inodes caches")
    op.add_option("-C", "--CACHED", dest="show_cached_details", default=0,
                  action="store_true",
                  help="Show CACHED details")
    op.add_option("-f", "--file", dest="file", default="",
                  action="store",
                  help="Show detailed file information for 'struct file' address (hex)")
    op.add_option("--findpidbyfile", dest="file_addr_for_pid", default="",
                  action="store",
                  help="Find PID from a /proc file address (hex)")
    op.add_option("--findpidbydentry", dest="dentry_addr_for_pid",
                  default="", action="store",
                  help="Find PID from a /proc dentry address (hex)")
    op.add_option("-i", "--inode", dest="inode", default="",
                  action="store",
                  help="Show detailed inode information for 'struct inode' address (hex)")
    op.add_option("-n", "--fsnotify", dest="fsnotify_group", default="",
                  action="store",
                  help="Show fsnotify details for fsnotify_group")
    op.add_option("--negdents", dest="degative_dentries", default=0,
                  action="store_true",
                  help="Show negative dentries")
    op.add_option("-r", "--page_caches", dest="show_page_caches", default=0,
                  action="store_true",
                  help="Show page caches per super_block. With a "
                       "'struct super_block' address (hex), show what is "
                       "consuming that filesystem's page cache")
    op.add_option("--top", dest="top_count", default=20,
                  action="store", type="int", metavar="N",
                  help="With '-r <super_block>', number of rows to list "
                       "in each table (default: 20)")
    op.add_option("--breakdown", dest="breakdown", default=0,
                  action="store_true",
                  help="With '-r <super_block>', also group the cache by "
                       "directory, filename pattern and owner, and report "
                       "cache held by unlinked files")
    op.add_option("--holders", dest="holders", default=0,
                  action="store_true",
                  help="With '-r <super_block>', attribute the cache to the "
                       "processes holding it, both by open fd ('foreach "
                       "files', run once) and by mapping (each inode's VMA "
                       "tree) - the only way to find a culprit for unlinked "
                       "files")
    op.add_option("--depth", dest="path_depth", default=3,
                  action="store", type="int", metavar="N",
                  help="With '--breakdown', group directories at N path "
                       "components (default: 3; 0 for full paths)")
    op.add_option("-s", "--slab", dest="show_slab", default=0,
                  action="store_true",
                  help="Show all 'dentry' details in slab")
    op.add_option("--show_open_files", dest="show_open_files", default=0,
                  action="store_true",
                  help="Show open files per process")
    op.add_option("--show_open_file_size", dest="show_open_file_size", default=0,
                  action="store_true",
                  help="Show file size of each open files")
    op.add_option("-S", "--swap", dest="show_swap", default=0,
                  action="store_true",
                  help="Show all 'dentry' details in slab")
    op.add_option("-t", "--task", dest="task_info", default="",
                  action="store",
                  help="Show task related information")
    op.add_option("-p", "--dumpe2fs", dest="dumpe2fs", default="",
                  action="store",
                  help="Shows dumpe2fs like information")
    op.add_option("-z", "--frozen", dest="show_frozen", default=0,
                  action="store_true",
                  help="Is a filesystem freeze blocking the system: frozen "
                       "filesystems, tasks waiting for a thaw, freeze "
                       "agents and hung-task reports (-d for backtraces)")

    (o, args) = op.parse_args()

    sys.setrecursionlimit(10**6)
    get_machine_symbol("")

    if (o.file_addr_for_pid != ""):
        find_pid_from_file(o)
        sys.exit(0);
    if (o.dentry_addr_for_pid != ""):
        find_pid_from_dentry(o)
        sys.exit(0);
    if (o.file != ""):
        show_file_details(o)
        sys.exit(0)
    if (o.inode != ""):
        show_inode_details(o)
        sys.exit(0)
    if (o.show_slab):
        show_slab_dentry(o)
        sys.exit(0)
    if (o.show_caches):
        show_caches(o)
        sys.exit(0)
    if (o.show_cached_details):
        show_cached_details(o)
        sys.exit(0)
    if (o.show_page_caches):
        if len(args) > 0:
            show_pagecache_sb_stats(o, args[0])
        else:
            show_page_caches(o)
        sys.exit(0)
    if (o.dumpe2fs != ""):
        show_dumpe2fs(o)
        sys.exit(0)

    if (o.fsnotify_group != ""):
        show_fsnotify_group(o)
        sys.exit(0)

    if (o.degative_dentries):
        show_negative_dentries(o)
        sys.exit(0)

    if (o.task_info):
        show_task_info(o)
        sys.exit(0)

    if (o.show_open_files):
        show_open_files(o)
        sys.exit(0)

    if (o.show_open_file_size):
        show_open_file_size(o)
        sys.exit(0)

    if (o.show_swap):
        show_swap_usage(o)
        sys.exit(0)

    if (o.show_frozen):
        show_frozen_summary(o)
        sys.exit(0)


    all_filesystem_info(o)

if ( __name__ == '__main__'):
    fsinfo()
