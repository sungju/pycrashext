"""
Checks for spinlock decoding, MCS queue reconstruction and lock matching.

Run directly: python3 source/lockdecode_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from lockdecode import (decode_qspinlock, encode_tail, describe_qspinlock,
                        decode_tickets, ticket_position, in_use_slots,
                        build_queues, candidate_words, match_lock)


def check_qspinlock_small_layout():
    d = decode_qspinlock(0x00000001, 8192)
    assert (d["locked"], d["pending"], d["tail_cpu"]) == (1, 0, None)
    # CPU 2, slot 1, pending, locked.
    val = encode_tail(2, 1, 8192) | 0x100 | 1
    assert val == (3 << 18) | (1 << 16) | 0x101
    d = decode_qspinlock(val, 8192)
    assert (d["locked"], d["pending"], d["tail_cpu"], d["tail_idx"]) == (1, 1, 2, 1)
    # CPU numbers past 2046 need all 14 bits.
    d = decode_qspinlock(encode_tail(5000, 0, 8192) | 1, 8192)
    assert d["tail_cpu"] == 5000, d


def check_qspinlock_large_layout():
    val = encode_tail(20000, 3, 16384) | 0x100 | 1
    assert val == (20001 << 11) | (3 << 9) | 0x101
    d = decode_qspinlock(val, 16384)
    assert (d["locked"], d["pending"], d["tail_cpu"], d["tail_idx"]) == (1, 1, 20000, 3)


def check_describe():
    assert describe_qspinlock(decode_qspinlock(0, 8192)) == "unlocked"
    assert "_Q_SLOW_VAL" in describe_qspinlock(decode_qspinlock(3, 8192))
    assert "corrupted" in describe_qspinlock(decode_qspinlock(0x42, 8192))
    assert "tail CPU 0 slot 0" in describe_qspinlock(
        decode_qspinlock(encode_tail(0, 0, 8192) | 1, 8192))


def check_tickets():
    # Free lock, held with no waiters, held with two waiters.
    assert decode_tickets(4, 4, 8)["held"] is False
    t = decode_tickets(4, 5, 8)
    assert (t["held"], t["waiters"]) == (True, 0)
    assert decode_tickets(4, 7, 8)["waiters"] == 2
    # Wraps at the ticket width.
    assert decode_tickets(0xfffe, 0x0001, 16)["waiters"] == 2
    # Paravirt: step 2, bit 0 the slowpath flag.
    t = decode_tickets(10, 17, 8, inc=2)
    assert (t["held"], t["waiters"], t["slowpath"]) == (True, 2, True)
    assert decode_tickets(10, 10, 8, inc=2)["held"] is False
    assert ticket_position(12, 10, 8, inc=2) == 0
    assert ticket_position(16, 10, 8, inc=2) == 2
    assert ticket_position(12, 12, 16, inc=2) == -1


def check_in_use_slots():
    assert [in_use_slots(c) for c in (0, 1, 4, 6, -1)] == [0, 1, 4, 4, 0]


def check_build_queues():
    # CPU 3 (head) -> CPU 1 -> CPU 2 slot 1 (tail); CPU 5 alone.
    nodes = {0x100: (1, 0, 0x210), 0x300: (3, 0, 0x100),
             0x210: (2, 1, 0), 0x500: (5, 0, 0)}
    queues = build_queues(nodes)
    assert ([0x300, 0x100, 0x210], False) in queues
    assert ([0x500], False) in queues
    assert len(queues) == 2
    # A next pointing at a node not in use ends the chain there.
    assert build_queues({0x100: (1, 0, 0x999)}) == [([0x100], False)]


def check_build_queues_broken():
    cycle = build_queues({0x100: (1, 0, 0x200), 0x200: (2, 0, 0x100)})
    assert cycle == [([0x100, 0x200], True)]
    # Two nodes claiming the same successor.
    queues = build_queues({0x100: (1, 0, 0x300), 0x200: (2, 0, 0x300),
                           0x300: (3, 0, 0)})
    assert any(broken for _, broken in queues)
    assert sorted(a for chain, _ in queues for a in chain) == [0x100, 0x200, 0x300]


def check_candidate_words():
    text = """ #3 [ffffb4a1c0237e50] native_queued_spin_lock_slowpath at ffffffff9a3c1a2b
    ffffb4a1c0237e58: ffff9e2a4c8b1d40 0000000000000046
    ffa0b4a1c0237e60: ff11000123456780 00007ffd12345678
        RAX: 0000000000000001  RBX: ffff9e2a4c8b1d41  RDI: FFFF9E2A4C8B1D40"""
    words = candidate_words(text)
    assert 0xffff9e2a4c8b1d40 in words
    assert 0xff11000123456780 in words              # 5-level paging direct map
    assert 0xffff9e2a4c8b1d41 not in words          # not 4-byte aligned
    assert 0x46 not in words and 0x00007ffd12345678 not in words
    # Stack slots are where words live, not values held.
    assert 0xffffb4a1c0237e50 not in words
    assert 0xffffb4a1c0237e58 not in words
    assert 0xffa0b4a1c0237e60 not in words


def check_match_lock():
    lock, other, node = 0xffff0000000a0000, 0xffff0000000b0000, 0xffff0000000c0000
    mem = {lock: encode_tail(7, 0, 8192) | 0x101,
           other: encode_tail(3, 0, 8192) | 1,          # another queue's lock
           node: encode_tail(7, 0, 8192)}               # excluded range
    found = match_lock({7: {lock, other, node}, 4: {lock}},
                       mem.get, 7, 0, 8192, exclude=[(node, node + 64)])
    assert [(a, n) for a, _, n in found] == [(lock, 2)]
    assert found[0][1]["pending"] == 1
    assert match_lock({7: {other}}, mem.get, 7, 0, 8192) == []


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
