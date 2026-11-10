#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifndef TASK_REPORT_MAX
#error Unsupported kernel: TASK_REPORT_MAX is unavailable
#endif
#if TASK_REPORT_MAX != @PREEMPT@
#error Running tracepoint state mask differs from build headers
#endif

struct target {
    u32 tgid;
    u64 start_ticks;
    u64 generation;
    u64 kernel_start_ns;
};
struct identity { u32 tid; u64 generation; };
struct interval { u64 at; u64 cookie; u32 kind; s32 stack_id; };
struct total { u64 runnable_ns; u64 blocked_ns; u64 unknown_ns; u64 samples; };

BPF_HASH(targets, u32, struct target, @CAPACITY@);
BPF_HASH(starts, struct identity, struct interval, @CAPACITY@);
BPF_HASH(pending, struct identity, struct interval, @CAPACITY@);
BPF_HASH(totals, struct identity, struct total, @CAPACITY@);
BPF_HASH(exited, struct identity, u8, @CAPACITY@);
BPF_ARRAY(diagnostics, u64, 9);
#if @STACKS@
struct stack_key { u32 tid; u64 generation; s32 stack_id; };
BPF_STACK_TRACE(stacks, @STACK_CAPACITY@);
BPF_HASH(blocked_stacks, struct stack_key, u64, @STACK_KEY_CAPACITY@);
#endif

static __always_inline void diag(u32 i) {
    u64 *v = diagnostics.lookup(&i);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline int verify(struct target *target, u64 *cookie) {
    u64 pid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (bpf_probe_read_kernel(cookie, sizeof(*cookie), &task->start_boottime))
        return 0;
    if ((pid >> 32) != target->tgid || *cookie / @TICK_NS@ != target->start_ticks)
        return 0;
    if (!target->kernel_start_ns)
        target->kernel_start_ns = *cookie;
    return target->kernel_start_ns == *cookie;
}

static __always_inline void commit(struct identity *key, u64 cookie) {
    struct interval *p = pending.lookup(key);
    if (!p) return;
    struct interval saved = *p;
    pending.delete(key);
    if (saved.cookie != cookie) { diag(6); return; }
    struct total zero = {};
    struct total *v = totals.lookup_or_try_init(key, &zero);
    if (!v) { diag(1); return; }
    if (saved.kind == 0) __sync_fetch_and_add(&v->runnable_ns, saved.at);
    else if (saved.kind == 1) __sync_fetch_and_add(&v->blocked_ns, saved.at);
    else __sync_fetch_and_add(&v->unknown_ns, saved.at);
    __sync_fetch_and_add(&v->samples, 1);
#if @STACKS@
    if (saved.kind == 1 && saved.stack_id >= 0) {
        struct stack_key sk = { .tid = key->tid, .generation = key->generation,
                                .stack_id = saved.stack_id };
        u64 zero_count = 0;
        u64 *count = blocked_stacks.lookup_or_try_init(&sk, &zero_count);
        if (count) __sync_fetch_and_add(count, 1);
        else diag(8);
    }
#endif
}

TRACEPOINT_PROBE(sched, sched_switch) {
    diag(0);
    u64 now = bpf_ktime_get_ns();
    u32 prev = args->prev_pid;
    struct target *t = targets.lookup(&prev);
    if (t) {
        struct identity key = { .tid = prev, .generation = t->generation };
        if (!exited.lookup(&key)) {
            u64 cookie = 0;
            if (!verify(t, &cookie)) {
                starts.delete(&key);
                pending.delete(&key);
                diag(2);
            } else {
                commit(&key, cookie);
                u64 state = args->prev_state;
                u32 kind = 2;
                if (state == 0 || state == @PREEMPT@) kind = 0;
                else if (!(state & ~((u64)@BLOCKED@))) kind = 1;
                if (kind == 2) diag(4);
                struct interval start = { .at = now, .cookie = cookie,
                                          .kind = kind, .stack_id = -1 };
#if @STACKS@
                if (kind == 1) {
                    start.stack_id = stacks.get_stackid(args, 0);
                    if (start.stack_id < 0) diag(7);
                }
#endif
                if (starts.update(&key, &start)) diag(1);
            }
        }
    }
    u32 next = args->next_pid;
    t = targets.lookup(&next);
    if (t) {
        struct identity key = { .tid = next, .generation = t->generation };
        struct interval *s = starts.lookup(&key);
        if (s) {
            struct interval saved = *s;
            starts.delete(&key);
            if (now < saved.at) { diag(5); return 0; }
            saved.at = now - saved.at;
            // Validate the incoming task at its next switch-out or exit before charging.
            if (pending.update(&key, &saved)) diag(1);
        }
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct target *t = targets.lookup(&tid);
    if (!t) return 0;
    struct identity key = { .tid = tid, .generation = t->generation };
    u64 cookie = 0;
    if (verify(t, &cookie)) commit(&key, cookie);
    else diag(2);
    starts.delete(&key);
    pending.delete(&key);
    // Tombstone the generation; leave totals until userspace observes removal.
    u8 one = 1;
    if (exited.update(&key, &one)) diag(1);
    diag(3);
    return 0;
}
