# frank-scripts (pykdump Extensions for Linux `crash`)

A collection of Python diagnostic scripts for analyzing Linux kernel vmcores with [crash](https://github.com/crash-utility/crash) and [pykdump](https://github.com/AlexSidorenko/pykdump).

## Requirements

- `crash` with `mpykdump.so` loaded (`extend /path/to/mpykdump.so`)
- Kernel debuginfo (`vmlinux` and module `.ko` debuginfo for subsystem scripts)
- Standard ID databases on the analysis host where applicable:
  - `/usr/share/hwdata/pci.ids` (for `lspci.py`)
  - `/usr/share/hwdata/usb.ids` (for `lsusb.py`)

## Usage

Load `mpykdump.so` inside `crash` and run any script via `epython`:

```text
crash> extend /path/to/mpykdump.so
crash> epython /path/to/frank-scripts/<script>.py [options]
```

If `PYKDUMPPATH` includes this directory, you can invoke scripts by name (`epython lspci -nn`).

---

## Script Reference

### Hang, Lock & Concurrency Analysis

- **`lock_graph.py`** — Wait-chain and lock-dependency graph across `TASK_UNINTERRUPTIBLE` (`UN`) tasks.
  - Correlates `mutex`/`rw_semaphore` owners, `jbd2` journal waiters, and workqueue flushes (`__flush_workqueue`) into a directed waiter → blocker graph, detects deadlock cycles, and groups root blockers (`BLOCK_IO`, `FOLIO_WRITEBACK`, `SUNRPC`, `XFS_ICLOG_IO`, `SMB_CIFS`, etc.).
  - Options: `-v` (list all standalone waiters)
- **`wq_stuck.py`** — Workqueue and `kworker` bottleneck inspector.
  - Walks `workqueues`, `pool_workqueue`s, and `worker_pool`s; shows active workers (`PID`, state, CPU, age, `current_func`), queued `pool->worklist` / `inactive_works`, and saturated or stalled pools.
  - Options: `-a` / `--all` (include idle workqueues), `-w <substr>` (filter by workqueue name)
- **`rwsem.py`** — Decodes `struct rw_semaphore` state (owner task, modern `count` bits `WRITER_LOCKED` / `WAITERS` / `HANDOFF` / reader count, and `wait_list` / `first_waiter` waiters).
- **`file_lock.py`** — Inspects VFS file locks (`file_lock_list`, per-CPU `file_lock_list_struct` / `file_lock_core`, `blocked_hash`, and per-file/inode locks).

### Filesystems & Storage

- **`jbd2_show.py`** — `ext4` / `jbd2` journal and transaction inspector.
  - Displays journal flags, sequence numbers, ring space, running/committing/checkpoint transactions, blocked wait-queue tasks, and an automatic `Interpretation:` diagnosis of stalls, aborts, freezes, or low journal space.
  - Options: `-v` / `--verbose` (buffer lists & locked `buffer_head`s), `-m <substr>` (filter by mount/device), `--raw` (omit interpretation)
- **`io_trace.py`** — End-to-end in-flight block I/O tracer.
  - Walks all in-flight `blk_mq` requests (`LinuxDump.block.get_all_requests`) and correlates each `request` → `bio` → `iomap_dio` / `buffer_head` / `folio->mapping->host` back to filesystem, inode, file path, and waiting `PID`, plus `loopN` backing files.
  - Options: `-d <disk>`, `-m <min_age_sec>`, `-s` (summary only), `-v` (expand all bios per request)
- **`lsloops.py`** — Lists loopback devices (`loopN`) and their backing files.
- **`find.py`** — Walks dcache/mounts from a dentry or path (including mountpoint traversal and path resolution).
- **`xfs_info.py`** — Inspects XFS filesystems, AGs, logs, and buffers.
- **`check_frozen.py`** — Checks superblocks for frozen filesystem state (`s_writers.frozen`).
- **`fdinfo.py`**, **`print_paths.py`**, **`dump_inode_pages.py`**, **`count_dentries.py`**, **`count_delegations.py`**, **`show_autofs.py`** — VFS/dentry/fd/inode helpers.

### Networking & SunRPC / NFS

- **`rpc_hang.py`** — End-to-end SunRPC / NFS hang correlator.
  - Correlates `rpc_xprt` / `sock_xprt` state, slot usage, queue lengths, underlying TCP socket state (`skc_state`, `unacked_bytes`, `snd_wnd`, `retrans_out`, `wmem`/`rmem`), NFS mountpoints, and in-flight `rpc_task`s with owning user `PID`s and ages.
  - Options: `-a` / `--active-only`, `-s <server_substr>`, `-m <min_age_sec>`

### Hardware, Topology & Memory

- **`lspci.py`** — `lspci`-compatible PCI bus/device inspector starting from `pci_root_buses` (uses `pci.ids`).
  - Options: `-t` (tree), `-v` / `-vv` / `-vvv`, `-k` (kernel driver), `-n` / `-nn`, `-D`, `-P` / `-PP`, `-m` / `-vm` / `-vmm`, `-s <slot>`, `-d <vendor>:<device>[:<class>[:<progif>]]`, `-i <pci.ids>`
  - Note: raw PCI config space (`-x`) and live-only hardware registers are unavailable in a vmcore.
- **`lsusb.py`** — `lsusb` and `usb-devices` inspector starting from `usb_bus_idr` (uses `usb.ids`).
  - Options: `-t` / `--tree`, `-v` / `--verbose`, `-U` / `--usb-devices` (switch to `usb-devices` format), `-i <usb.ids>`
- **`lstopo.py`** — Displays CPU/NUMA/memory topology.
- **`kmem_S.py`** — `kmem -S` replacement for Linux 7.1+ SLUB kernels with `cpu_sheaves`.
  - Walks per-node `kmem_cache_node` partial/full slab lists, decodes slab freelists (including `CONFIG_SLAB_FREELIST_HARDENED`), and inspects per-CPU `slub_percpu_sheaves` and `node_barn` sheaves to classify objects as active or inactive.
  - Options: `<cache>` (name or hex `struct kmem_cache` address), `-a` / `--active` (active objects only), `-i` / `--inactive` / `--free` (inactive objects only), `-q` / `--addresses-only` (one `0x...` address per line)
- **`gfp.py`**, **`list_sb_memcg_lrus.py`**, **`dump_vma_file.py`** — Memory allocation, memcg LRU, and VMA helpers.

### Debugging & Shared Library

- **`scope_vars.py`** — Queries DWARF/GDB location expressions for variables in scope at a given kernel text address.
- **`sorenson_lib.py`** — Shared helper utilities used across scripts.
