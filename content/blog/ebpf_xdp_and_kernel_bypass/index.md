---
title: "eBPF, XDP and Kernel Bypass"
author: "Erich"
date: 2025-06-14
draft: false
---

🧠 Is eBPF a Kernel Bypass? Clearing the Confusion

eBPF (extended Berkeley Packet Filter) has exploded in popularity for observability, security, and networking on Linux. But if you’ve browsed Reddit or Hacker News, you’ve probably seen people claim:

    “eBPF runs in userspace.”
    “eBPF is a kernel bypass.”
    “eBPF replaces DPDK!”

Let’s clear the fog. In this post, we’ll walk through what eBPF really is, where it runs, and whether it qualifies as a “kernel bypass.”
🔍 What Is eBPF?

At its core, eBPF is a virtual machine inside the Linux kernel that allows you to attach tiny programs to key parts of the system — like syscalls, network packet processing, or tracing events.

You write these eBPF programs in userspace, typically in C, and then load them into the kernel via a syscall (bpf()), where they are verified and JIT-compiled to native code.

So:

    📦 Written in userspace

    🚀 Executed in kernel space

🤔 So… Is eBPF a Kernel Bypass?

No. eBPF is not a kernel bypass. In fact, it’s the opposite.

    eBPF runs inside the kernel and operates with kernel cooperation.

    It extends the kernel's capabilities safely and dynamically.

    It is sandboxed, verified, and runs in specific hook points (e.g., network ingress, syscall entry, kprobes, tracepoints, etc.).

✅ eBPF Enhances Kernel Behavior
❌ eBPF Does Not Bypass the Kernel
🧵 Why Do People Say eBPF “Runs in Userspace”?

There’s a grain of truth, but it’s misleading.

    eBPF code is developed and compiled in userspace.

    You use userspace tools like clang, bpftool, bcc, libbpf, or bpftool prog load to load programs into the kernel.

    But once loaded, eBPF programs run in kernel context, not in userspace.

Saying “eBPF runs in userspace” is like saying "drivers run in Notepad because you wrote them there." It’s true that you write them in userspace, but they run in kernelspace.
⚡ But What About XDP or AF_XDP?

Good question!

These are part of the eBPF ecosystem, especially in networking.
Technology	Runs In	Description
XDP	Kernel (very early)	Processes packets in the driver before the kernel stack. Used for fast packet filtering and redirection.
AF_XDP	Userspace	A socket type that allows zero-copy packet I/O between NIC and userspace. Can act as a true kernel bypass.
DPDK	Userspace	Full kernel bypass. Userland packet processing with direct NIC access via UIO or VFIO.

So if you want true kernel bypass, you’ll use DPDK or AF_XDP in zero-copy mode. eBPF + XDP can drop or redirect packets before they hit the TCP/IP stack, but it’s still happening inside the kernel.
🧠 Summary
Statement	✅ / ❌	Clarification
eBPF runs in kernel space	✅	After loading, eBPF executes in the kernel
eBPF is a kernel bypass	❌	It extends the kernel, not bypasses it
You write eBPF in userspace	✅	Then it’s loaded into kernel
XDP can avoid the kernel network stack	⚠️	Partially true — it avoids the full stack but is still in kernel
AF_XDP and DPDK bypass the kernel	✅	These give userland access to NICs
🛠️ Want to Go Deeper?

    Build an XDP program to drop or redirect packets

    Compare DPDK vs AF_XDP vs XDP in real benchmarks

    Trace syscalls with eBPF using tools like bcc or bpftrace

🔚 Conclusion

eBPF is a powerful in-kernel extension mechanism, not a bypass. If you're aiming for extreme packet throughput or latency reduction in userland, consider AF_XDP or DPDK. But for safety, flexibility, and observability — eBPF is unmatched.

If you're confused by what runs where, just remember:

    You write in userspace, but eBPF thinks in kernelspace.

