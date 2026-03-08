#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Structured event sent to userspace via perf buffer
struct data_t {
    u32  pid;
    char comm[16];
};

// Declare the perf output channel
BPF_PERF_OUTPUT(events);

// Runs on every execve syscall
int syscall__execve(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
