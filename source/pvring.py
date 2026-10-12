"""
Paravirtual I/O rings: what the guest posted, what the host has not
completed, and what the host completed that the guest has not processed.

A paravirtual device (virtio, VMware pvscsi, Hyper-V VMBus) shares rings of
free-running indices with the host.  Their differences say which side holds
an outstanding request:
  host   posted by the guest, not completed by the host
  guest  completed by the host, not yet processed by the guest
  kick   added by the guest without notifying the host
With the age of the oldest outstanding block request on the device, that
tells a host that stopped completing I/O (datastore or backend stall) from
a guest that lost an interrupt or stopped processing completions -- the
question aged requests alone cannot answer.

Used by 'devinfo --pvio'.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

# Age of the oldest outstanding request at which a side is called slow, and
# stalled (the SCSI command timeout is 30s on most guests).
SLOW_SEC = 5.0
STALL_SEC = 30.0

# States from worst to least bad; the report's answer is the worst one.
STATES = ("BROKEN", "HOST STALLED", "GUEST NOT PROCESSING",
          "GUEST NOT NOTIFIED", "HOST SLOW", "IN FLIGHT", "IDLE", "n/a",
          "NOT DECODED")
PROBLEMS = STATES[:5]

# virtio queues that hold buffers for the host to fill (receive, events,
# balloon stats) rather than requests: outstanding buffers there are normal.
FILL_QUEUE_PREFIXES = ("input", "event", "stats", "reporting", "free_page",
                       "rx")


def ring_diff(a, b, bits):
    return (a - b) & ((1 << bits) - 1)


def virtio_split(avail_idx, used_idx, last_used_idx, num_added=0):
    """Split virtqueue: avail.idx is written by the guest, used.idx by the
    host, last_used_idx is how far the guest has processed used.idx."""
    return {
        "host": ring_diff(avail_idx, used_idx, 16),
        "guest": ring_diff(used_idx, last_used_idx, 16),
        "kick": num_added,
    }


def pvscsi(req_prod, req_cons, cmp_prod, cmp_cons):
    """
    VMware pvscsi rings_state: the guest produces requests and consumes
    completions, the device the other way round.  not_taken is the part of
    host that the device has not even picked up yet (with a request
    threshold it may wait for more requests before looking).
    """
    return {
        "host": ring_diff(req_prod, cmp_prod, 32),
        "not_taken": ring_diff(req_prod, req_cons, 32),
        "guest": ring_diff(cmp_prod, cmp_cons, 32),
        "kick": 0,
    }


def vmbus(out_write, out_read, out_size, in_write, in_read, in_size):
    """
    Hyper-V VMBus channel, in bytes: the outbound ring is written by the
    guest and read by the host, the inbound ring the other way round.
    """
    return {
        "host": (out_write - out_read) % out_size if out_size else 0,
        "guest": (in_write - in_read) % in_size if in_size else 0,
        "kick": 0,
    }


def is_request_queue(name):
    """False for virtio queues of buffers the host fills (receive, event)."""
    lower = (name or "").lower()
    return not lower.startswith(FILL_QUEUE_PREFIXES)


def verdict(counts, oldest=None, broken=False, request_queue=True,
            unit="request(s)", guest_unit="completion(s)", polled=False):
    """
    (state, note) for one ring.  oldest is the age in seconds of the oldest
    request the device or queue holds, from dispatch, or None when unknown.

    The age is not tied to a ring entry, so a side is blamed only when it
    can hold the aged request: the host whenever it holds entries the guest
    has notified it about; the guest for "not notified" only when every
    entry the host holds is unkicked, and for "not processing" only when
    the host holds nothing.
    """
    if broken:
        return "BROKEN", "device marked broken; nothing on it completes"
    if not request_queue:
        return "n/a", "buffers posted for the host to fill; normal"
    host, guest, kick = counts["host"], counts["guest"], counts["kick"]
    aged = oldest is not None and oldest >= SLOW_SEC
    if aged and host > kick:
        note = "%d %s at the host, oldest %.1fs" % (host, unit, oldest)
        if guest:
            note += "; %d %s also wait for the guest" % (guest, guest_unit)
        return ("HOST STALLED" if oldest >= STALL_SEC else "HOST SLOW"), note
    if aged and host:
        return ("GUEST NOT NOTIFIED",
                "%d added without notifying the host; oldest request %.1fs"
                % (kick, oldest))
    if aged and guest:
        return ("GUEST NOT PROCESSING",
                "%d %s wait for the guest; oldest request %.1fs (%s)"
                % (guest, guest_unit, oldest,
                   "poll queue not polled" if polled
                   else "lost interrupt or stuck handler"))
    if host:
        return "IN FLIGHT", "%d %s at the host, %s" % (
            host, unit, "age unknown" if oldest is None
            else "oldest %.1fs" % oldest)
    if guest:
        return "IN FLIGHT", "%d %s being processed" % (guest, guest_unit)
    return "IDLE", ""


def worst(states):
    """The worst state of a list, by STATES order."""
    ranked = [s for s in states if s in STATES]
    return min(ranked, key=STATES.index) if ranked else "IDLE"


def swap16(value):
    return ((value & 0xff) << 8) | ((value >> 8) & 0xff)


def age_text(age):
    return "-" if age is None else "%.1fs" % age
