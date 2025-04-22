---
title: "jBPF for RIC with srsRAN"
author: "Erich"
date: 2025-04-10
draft: false
---


# What is jBPF?
jBPF stands for Janus BPF, it is eBPF like that part of janus project provided by microsoft. jBPF runs in user space mode unlike eBPF that runs in kernel stack, it is based on userspace BPF (uBPF). just like the developer said:

>Userspace eBPF instrumentation and control framework for deploying control and monitoring functions in a secure manner. It is part of Project Janus and provides probes for eBPF-like functionality outside of the Linux kernel.

As Telecom technology require low latency in such manner, eBPF comes for accomplish this requirement. eBPF already implemented in several usecases that require low latency and control something without interupt the process. In this scenario telecom technology also require this manner, and eBPF already proven to resolve this requirements, such as linux scheduler modification without interuptthe process and firewall.

jBPF that part of janus project provided by microsoft already provide us the way to use eBPF instrumentation for Radio Access Network Monitor and control utilization. The project you can find at here:
https://github.com/microsoft/jbpf.git

The jbpf instrumentation and control library provides a flexible and safe user-mode instrumentation framework built on eBPF technology. It splits responsibilities between the core application developers and a potentially broader community of developers who want safe access to instrumentation and control, similar to eBPF in Linux kernel. However, jbpf operates entirely in user mode and makes no calls to Linux kernel.

The core application developers define common instrumentation points with access to important internal application structures and APIs, but without prescribing how these will be consumed. Other developers can deploy their own code, inlined, at the instrumentation points. It allows them to efficiently process internal application data in an arbitrary way to extract particular information without needing to copy it elsewhere. The instrumentation code is statically verified before executed to enforce safety.
