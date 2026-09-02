# fil_mon

A lightweight, real-time Linux process and file handle monitor powered by eBPF (`bpftrace`), Python, and SQLite. It captures short-lived binary executions, tracks dynamic file lifecycle events (`openat`, `close`, `exit`), renders a live terminal ASCII tree of active file descriptors, and persists detailed historical logs.

Designed specifically to bypass native eBPF kernel stack limitations (such as the 512-byte stack limit and string map limitations in `bpftrace` 0.14) by offloading thread state correlation to userspace Python.

---

## Features

* **Real-Time ASCII Tree Rendering**: Displays a live, auto-updating directory tree of non-system files currently opened by active processes.
* **Low-Overhead eBPF Tracing**: Hooks directly into kernel tracepoints (`sys_enter_openat`, `sys_exit_openat`, `sys_enter_close`, `sys_enter_exit_group`).
* **High-Performance Logging**: Persists process events to an optimized SQLite database using Write-Ahead Logging (WAL) and indexed filepath lookups.
* **Post-Mortem Analysis**: Reconstructs complete file interaction topologies from historical runs using a standalone offline CLI renderer.
* **Kernel-Safe Architecture**: Emits raw entry/exit tuples directly to stdout, eliminating BPF map string lookups that cause kernel stack overflows (`looks like the BPF stack limit of 512 bytes is exceeded`).

---

## Requirements

* **Operating System**: Linux (Tested on Pop!_OS 22.04 / Ubuntu 22.04, Kernel 5.15+)
* **Dependencies**:
  * `bpftrace` (v0.14.0+)
  * `python3` (v3.8+)
  * `sqlite3`
  * `coreutils` (`stdbuf`)

### Installation

Install required system packages:

```bash
sudo apt update
sudo apt install -y bpftrace python3 sqlite3 coreutils
