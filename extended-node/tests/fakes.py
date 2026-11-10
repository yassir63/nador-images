"""Mock BCC tables only. These do not compile, verify, or execute BPF C."""

import ctypes as ct


class Identity(ct.Structure):
    _fields_ = [("tid", ct.c_uint), ("generation", ct.c_ulonglong)]


class Target(ct.Structure):
    _fields_ = [("tgid", ct.c_uint), ("start_ticks", ct.c_ulonglong),
                ("generation", ct.c_ulonglong), ("kernel_start_ns", ct.c_ulonglong)]


class Interval(ct.Structure):
    _fields_ = [("at", ct.c_ulonglong), ("cookie", ct.c_ulonglong),
                ("kind", ct.c_uint), ("stack_id", ct.c_int)]


class Total(ct.Structure):
    _fields_ = [("runnable_ns", ct.c_ulonglong), ("blocked_ns", ct.c_ulonglong),
                ("unknown_ns", ct.c_ulonglong), ("samples", ct.c_ulonglong)]


class StackKey(ct.Structure):
    _fields_ = [("tid", ct.c_uint), ("generation", ct.c_ulonglong), ("stack_id", ct.c_int)]


class DropKey(ct.Structure):
    _fields_ = [("netns", ct.c_ulonglong), ("ifindex", ct.c_uint),
                ("reason", ct.c_uint), ("location", ct.c_uint)]


def clone(value):
    return type(value).from_buffer_copy(bytes(value))


class Table:
    def __init__(self, key_type, leaf_type):
        self.Key, self.Leaf = key_type, leaf_type
        self.data = {}
        self.fail_read = False
        self.fail_write = False

    def __getitem__(self, key):
        if self.fail_read:
            raise OSError("mock map read failure")
        return self.data[bytes(key)][1]

    def __setitem__(self, key, value):
        if self.fail_write:
            raise OSError("mock map full")
        self.data[bytes(key)] = (clone(key), clone(value))

    def __delitem__(self, key):
        del self.data[bytes(key)]

    def items(self):
        if self.fail_read:
            raise OSError("mock map enumeration failure")
        return [(clone(k), clone(v)) for k, v in self.data.values()]


class FakeBPF:
    def __init__(self, *, text):
        self.text = text
        self.cleaned = False
        if "TRACEPOINT_PROBE(skb" in text:
            events = ("skb:kfree_skb",)
        else:
            events = ("sched:sched_switch", "sched:sched_process_exit")
        self.tracepoint_fds = {name.encode(): 123 for name in events}
        self.maps = {
            "targets": Table(ct.c_uint, Target),
            "starts": Table(Identity, Interval),
            "pending": Table(Identity, Interval),
            "totals": Table(Identity, Total),
            "exited": Table(Identity, ct.c_ubyte),
            "blocked_stacks": Table(StackKey, ct.c_ulonglong),
            "counts": Table(DropKey, ct.c_ulonglong),
            "diagnostics": Table(ct.c_int, ct.c_ulonglong),
        }
        for i in range(9):
            self.maps["diagnostics"][ct.c_int(i)] = ct.c_ulonglong(0)

    def __getitem__(self, name):
        return self.maps[name]

    def diag(self, index, value):
        self.maps["diagnostics"][ct.c_int(index)] = ct.c_ulonglong(value)

    def drop(self, inode, ifindex, reason, count, location=0):
        table = self.maps["counts"]
        table[DropKey(inode, ifindex, reason, location)] = ct.c_ulonglong(count)
        self.diag(0, sum(v.value for _, v in table.items()))

    def cleanup(self):
        self.cleaned = True
        self.tracepoint_fds.clear()
