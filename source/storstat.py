"""
Storage status verdicts: is a SCSI host in error handling, a device or a
path down, or I/O stuck, and where?

Each check takes plain values read from the dump and returns findings,
(state, note) pairs; the report's answer is the worst state found.  The
SCSI counters mean:
  host_busy     commands the host has sent to the HBA and not completed
  host_failed   commands that failed or timed out, waiting for the error
                handler; it runs once host_failed == host_busy
  host_blocked  / device_blocked: a queuecommand returned busy and the
                queue is held back until the counter drains
  iorequest_cnt - iodone_cnt: commands sent to the driver and not done,
                including those the error handler aborted, so it grows
                with every timeout and is not an in-flight count

Used by 'devinfo --status'.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

# Age of the oldest request at which I/O is called slow and stalled (the
# SCSI command timeout is 30s by default).
SLOW_SEC = 5.0
STALL_SEC = 30.0

# States from worst to least bad.
STATES = ("ERROR RECOVERY", "DEVICE OFFLINE", "PATH DOWN", "I/O STALLED",
          "QUEUE STOPPED", "DEVICE BLOCKED", "I/O SLOW", "ERRORS SEEN",
          "BUSY", "IDLE")
PROBLEMS = STATES[:7]

SHOST_RECOVERY = ("SHOST_RECOVERY", "SHOST_CANCEL_RECOVERY",
                  "SHOST_DEL_RECOVERY")
SHOST_GOING = ("SHOST_CANCEL", "SHOST_DEL")
SDEV_DOWN = ("SDEV_OFFLINE", "SDEV_TRANSPORT_OFFLINE", "SDEV_CANCEL",
             "SDEV_DEL")
SDEV_HELD = ("SDEV_BLOCK", "SDEV_CREATED_BLOCK", "SDEV_QUIESCE")
NVME_RECOVERY = ("NVME_CTRL_RESETTING", "NVME_CTRL_CONNECTING")
NVME_DOWN = ("NVME_CTRL_DELETING", "NVME_CTRL_DELETING_NOIO",
             "NVME_CTRL_DEAD")


def host_findings(state, busy, failed, blocked, eh_scheduled=0):
    out = []
    if state in SHOST_RECOVERY or failed or eh_scheduled:
        note = "%s, %d of %d busy command(s) failed" % (state, failed or 0,
                                                       busy or 0)
        if failed and busy is not None and failed < busy:
            note += "; the error handler waits for the other %d" % (
                busy - failed)
        elif eh_scheduled and not failed:
            note += "; host reset scheduled by the driver"
        out.append(("ERROR RECOVERY", note))
    elif state in SHOST_GOING:
        out.append(("DEVICE OFFLINE", "%s: host being removed" % state))
    if blocked:
        out.append(("DEVICE BLOCKED", "host_blocked %d: the HBA returned "
                    "busy" % blocked))
    return out


def device_findings(state, blocked=0, ioerr=0, iotmo=0):
    out = []
    if state in SDEV_DOWN:
        out.append(("DEVICE OFFLINE", state))
    elif state in SDEV_HELD:
        out.append(("DEVICE BLOCKED", "%s: I/O held until the device is "
                    "unblocked" % state))
    if blocked:
        out.append(("DEVICE BLOCKED", "device_blocked %d: the device "
                    "returned busy" % blocked))
    if ioerr or iotmo:
        out.append(("ERRORS SEEN", "%d error(s), %d timeout(s) since boot"
                    % (ioerr or 0, iotmo or 0)))
    return out


def queue_findings(started, timedout=0, oldest=None, timeout_sec=None,
                   stopped="", held=0, started_alloc=None, done=0,
                   done_oldest=None, queued=0, queued_oldest=None):
    """
    Findings for the requests one queue holds; ages are in seconds, None
    when unknown.
      started, oldest   requests sent to the driver (active or timed out),
                        the oldest of them from dispatch
      started_alloc     the oldest of them from allocation: a driver that
                        restarts the timer (during an HBA reset, or on a
                        requeue) keeps the dispatch age small
      done, done_oldest requests the device completed that the kernel has
                        not finished, the oldest from dispatch
      queued, queued_oldest  not sent to the driver yet, from allocation
      stopped           why the queue does not dispatch, or ''
    """
    out = []
    if stopped and held:
        out.append(("QUEUE STOPPED", "%s with %d request(s) waiting"
                    % (stopped, held)))
    if timedout:
        out.append(("I/O STALLED", "%d request(s) timed out, oldest %s"
                    % (timedout, age_text(oldest))))
    elif oldest is not None and oldest >= SLOW_SEC:
        past = timeout_sec and oldest >= timeout_sec
        note = "%d request(s) at the device, oldest %.1fs" % (started, oldest)
        if past:
            note += ", past its %ds timeout" % timeout_sec
        out.append(("I/O STALLED" if oldest >= STALL_SEC or past
                    else "I/O SLOW", note))
    elif started_alloc is not None and started_alloc >= STALL_SEC:
        out.append(("I/O STALLED", "%d request(s) at the device, oldest "
                    "allocated %.1fs ago but dispatched %s ago: its timer "
                    "was restarted (HBA reset or requeue)"
                    % (started, started_alloc, age_text(oldest))))
    elif started:
        out.append(("BUSY", "%d request(s) at the device, oldest %s"
                    % (started, age_text(oldest))))
    if done and done_oldest is not None and done_oldest >= SLOW_SEC:
        out.append(("I/O STALLED" if done_oldest >= STALL_SEC else "I/O SLOW",
                    "%d request(s) completed by the device but not finished "
                    "by the kernel, oldest dispatched %.1fs ago: completion "
                    "processing is stuck" % (done, done_oldest)))
    stalled = [f for f in out if f[0] in ("I/O STALLED", "I/O SLOW",
                                          "QUEUE STOPPED")]
    if queued and not stalled and queued_oldest is not None and \
            queued_oldest >= STALL_SEC:
        out.append(("I/O STALLED", "%d request(s) not sent to the driver, "
                    "oldest allocated %.1fs ago" % (queued, queued_oldest)))
    return out


def nvme_findings(state):
    if state in NVME_RECOVERY:
        return [("ERROR RECOVERY", state)]
    if state in NVME_DOWN:
        return [("DEVICE OFFLINE", state)]
    return []


def rport_findings(state):
    if state and state not in ("FC_PORTSTATE_ONLINE",):
        return [("PATH DOWN", state)]
    return []


def worst(states):
    """The worst state of a list, by STATES order."""
    ranked = [s for s in states if s in STATES]
    return min(ranked, key=STATES.index) if ranked else "IDLE"


def age_text(age):
    return "-" if age is None else "%.1fs" % age
