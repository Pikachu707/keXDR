#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# keXDR — kernel-side telemetry collector.
#
# Collects host and network events from one in-kernel observation point and writes them
# as JSON lines to a rotating log, for the orchestrator to build a provenance graph from.
#
# WHAT IT COLLECTS
#   Execution and lifecycle : execve, fork, exit
#   Filesystem              : openat, unlinkat
#   Privilege               : setuid
#   Memory                  : mmap and mprotect, but only where a mapping is both
#                             writable and executable, plus deferred W->X promotions
#   Injection               : ptrace, memfd_create
#   Network                 : every packet, with the process that owns the socket
#
# HOW A PACKET IS ATTRIBUTED TO A PROCESS
#   When a socket is opened, the security context of the opening process is written
#   into bpf_sk_storage attached to the struct sock:
#
#       active open      fentry on tcp_v4_connect / tcp_v6_connect
#       passive open     fexit  on inet_csk_accept
#       connected UDP    fentry on udp_sendmsg
#
#   A CGROUP_SKB program then reads skb->sk on every packet and recovers that context,
#   so attribution is a lookup on the kernel object rather than a match on addresses.
#   Such records carry attribution="exact" and a key of <netns, socket cookie>.
#
#   Packets with no owning socket -- forwarded traffic, unconnected datagrams, packets
#   that reach the backlog before accept() returns -- carry attribution="degraded" and
#   no owner.  They are never guessed at.
#
# PAYLOAD HANDLING
#   Up to 1024 bytes of application-layer data are copied per socket, accumulated over
#   at most 4 in-sequence segments in one direction, and used to identify the logical
#   destination (HTTP Host, TLS SNI, DNS question).  Data-transfer syscalls are not
#   instrumented: the collector records which artifact a process touched, never the
#   bytes it moved.
#
# REQUIREMENTS
#   Linux 5.8-6.8 with BTF and cgroup v2, BCC, and root.
#   Whatever cannot be attached is reported at startup and the affected records degrade
#   explicitly; the collector never reports an attribution it did not establish.
#
# USAGE
#   sudo python3 ebpf_probe.py -o ./audit_logs
#   Logs land in <output>/YYYY-MM-DD/audit_HH.json

import argparse
import ctypes as ct
import hashlib
import json
import os
import re
import resource
import socket
import struct
import sys
import threading
import time
import traceback
from collections import OrderedDict
from datetime import datetime, timezone

from bcc import BPF

# ============================================================================
# Global state
# ============================================================================
LOG_BASE_DIR = None
CURRENT_LOG_HANDLE = None
CURRENT_FILE_PATH = None

# Attribution quality tags carried on every network record.
ATTR_EXACT = "exact"        # recovered through kappa off skb->sk
ATTR_DEGRADED = "degraded"  # kappa unavailable; netns-scoped five-tuple kappa5 only

# Whether a logical destination could be read out of the payload.
L7_RESOLVED = "resolved"
L7_UNRESOLVED = "unresolved"   # QUIC, ECH: no application-layer destination exists
L7_FALLBACK_L4 = "l4_fallback" # field deferred past the projection window


class C:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    C_EXEC = '\033[93m\033[1m'
    C_OPEN = '\033[92m'
    C_CONN = '\033[95m'
    C_NET = '\033[96m\033[1m'
    C_MEMFD = '\033[91m\033[1m'
    C_INJECT = '\033[35m\033[1m'
    C_DEL = '\033[41m\033[37m'
    C_PRIV = '\033[43m\033[30m'
    C_BIND = '\033[36m'
    C_LIFE = '\033[90m'


# ============================================================================
# BPF C program
# ============================================================================
bpf_text_template = r"""
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/string.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

#ifndef PROT_READ
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* Injected by the loader. */
#define FILTER_TGID YOUR_PID_GOES_HERE
#define COALESCE_TTL_NS COALESCE_TTL_GOES_HERE

#define TASK_COMM_LEN 16
#define DATA_BUF_LEN_MAX 256
#define MAX_ARGS 6
#define ARG_LEN 32

/* the projection is *bounded*, not zero-copy.  1024 B spans the request
   line, a TLS ClientHello and a DNS question, and caps how much of a conversation
   can ever reach the log. */
#define MAX_L7 1024
#define L7_CHUNK 256
#define MAX_SEGS 4

/* ---------------- event type ids (shared with userspace) ---------------- */
#define EV_EXEC 0
#define EV_OPEN 1
#define EV_CONNECT 2
#define EV_MEMFD 5
#define EV_INJECT 6
#define EV_DELETE 7
#define EV_SETUID 8
#define EV_MMAP 9
#define EV_MPROTECT 10
#define EV_BIND 11   /* announces socket-key -> owner binding */
#define EV_FORK 12
#define EV_EXIT 13   /* closes a Process Tombstone */

/* ---------------- attribution tags ---------------- */
#define A_EXACT 1
#define A_DEGRADED 2

/* =========================================================================
 * Security context of the process at the moment of a kernel transition:
 * timestamp, PID, PPID, UID, cgroup id and an identity for the running binary.
 * H(bin) is anchored here as the binary's inode identity; the cryptographic
 * digest itself is computed once per identity in userspace and cached.  An
 * in-kernel SHA-256 over a whole binary is not a thing the verifier will take.
 * ========================================================================= */
struct csec_t {
    u64 ts;             /* bpf_ktime_get_boot_ns at the kernel transition */
    u64 pid;
    u64 ppid;
    u64 cgroup_id;      /* persistent container identity anchor */
    u32 uid;
    u32 netns;
    u64 bin_dev;        /* H(bin) part 1: superblock device */
    u64 bin_ino;        /* H(bin) part 2: inode number */
    u64 bin_gen;        /* H(bin) part 3: i_generation, defeats inode reuse */
    char comm[TASK_COMM_LEN];
};

/* Per-socket kernel storage: the whole point of the design.  Packet and syscall
   reach the same kernel object rather than the same tuple. */
/* compile-time check that the word-sized copy above is exact */
typedef char kexdr_csec_wordsize_check[(sizeof(struct csec_t) % 8 == 0) ? 1 : -1];

struct sk_ctx_t {
    struct csec_t sec;
    u64 cookie;         /* kappa part 2, latched lazily on the first packet */
    u32 l7_len;         /* bytes accumulated in the reassembly window */
    u32 next_seq;       /* expected TCP seq: enforces in-sequence assembly */
    u16 seg_count;
    u8  window_closed;
    u8  bind_emitted;
    u8  l7_proto;
    u8  passive;        /* 1 if bound at accept(), 0 if bound at connect() */
    u8  emitted_l7;
    u8  l7_dir;         /* direction the window belongs to: 1 egress, 0 ingress */
    u8  l7_dir_set;     /* latched on the first payload-bearing packet */
    u8  pad;
    u64 last_report_ns; /* per-socket coalescing of flow records */
    /* L7_CHUNK bytes of slack past MAX_L7.  Nothing ever reports more than l7_len
       bytes; the tail exists purely so that (off & (MAX_L7-1)) + L7_CHUNK stays inside
       the map value for every possible masked offset, which is what lets the verifier
       accept the append below without depending on branch refinement surviving a
       spill/reload. */
    u8  l7_buf[MAX_L7 + L7_CHUNK];
};

#ifdef KEXDR_KAPPA
BPF_SK_STORAGE(sk_ctx_map, struct sk_ctx_t);
#endif

/* ---------------- syscall event ---------------- */
struct exec_data_t   { char filename[64]; char args[MAX_ARGS][ARG_LEN]; };
struct connect_data_t{ u32 daddr; u16 dport; u16 family; u8 daddr6[16];
                       u64 cookie; char _pad[DATA_BUF_LEN_MAX - 34]; };
struct open_data_t   { char filename[DATA_BUF_LEN_MAX]; };
struct unlink_data_t { char filename[DATA_BUF_LEN_MAX]; };
struct setuid_data_t { u32 target_uid; };
struct mmap_data_t   { u64 addr; u64 len; u32 prot; u32 flags; u8 wx_now; u8 wx_promoted; u8 jit_baseline; u8 pad; };
struct life_data_t   { u64 child_pid; u64 exit_code; };

struct __attribute__((packed)) syscall_event_t {
    struct csec_t sec;
    u32 event_type;
    u32 arg_count;
    union {
        struct exec_data_t exec;
        struct connect_data_t connect;
        struct open_data_t open;
        struct unlink_data_t unlink;
        struct setuid_data_t setuid;
        struct mmap_data_t mmap_evt;
        struct life_data_t life;
    } data;
};

/* ---------------- network event ---------------- */
struct __attribute__((packed)) network_event_t {
    struct csec_t sec;      /* zeroed when attribution == A_DEGRADED */
    u64 cookie;             /* kappa part 2 */
    u64 timestamp;
    u32 netns;              /* kappa part 1, and the kappa5 netns component.
                               Non-zero only on the exact path: see the degraded
                               branch below for why it cannot be filled otherwise. */
    u8  ip_ver;
    u8  attribution;        /* A_EXACT | A_DEGRADED */
    u8  protocol;           /* L4 */
    u8  app_protocol;       /* coarse in-kernel class; decoding is userspace */
    u32 src_ip;  u32 dst_ip;
    u8  src_ip6[16]; u8 dst_ip6[16];
    u16 src_port; u16 dst_port;
    u16 payload_len;        /* bytes of window actually captured */
    u8  ip_ttl; u8 tcp_flags;
    u8  egress;
    u8  seg_count;
    u8  truncated;          /* window filled or segment budget exhausted */
    u8  passive;
    u8  l7_dir;             /* direction the shipped payload was captured in */
    u8  raw_payload[MAX_L7];
};

/* execve / connect / mmap ride a reserved ring and were never dropped;
   the bulk ring absorbs the repetitive openat and packet records. */
BPF_PERF_OUTPUT(prio_events);
BPF_PERF_OUTPUT(syscall_events);
BPF_PERF_OUTPUT(network_events);

BPF_PERCPU_ARRAY(syscall_buffer, struct syscall_event_t, 1);
BPF_PERCPU_ARRAY(network_buffer, struct network_event_t, 1);

/* Self-identification latch: the exclusion keys on the probe's TGID
   *and* its start_boottime, both captured in kernel at load time, so it cannot be
   inherited by a task that recycles our PID. */
struct self_id_t { u64 tgid; u64 start_boottime; u8 latched; };
BPF_ARRAY(self_id, struct self_id_t, 1);

/* mprotect W->X promotion tracking, fixed capacity by construction. */
struct wrange_t { u64 addr; u64 len; u64 ts; };
struct wkey_t   { u64 pid; u64 page; };
/* Keyed by <pid, first page>, not by pid alone.  One slot per process is wrong twice
   over: a process holds many writable mappings at once, and any later allocation --
   including whatever the runtime does between the write and the mprotect -- evicts the
   range the promotion check is about to look for. */
BPF_TABLE("lru_hash", struct wkey_t, struct wrange_t, writable_ranges, 8192);

/* mmap is recorded on EXIT, because sys_enter_mmap carries only the caller's address
   *hint*, which is NULL for every anonymous mapping.  Registering that hint means the
   later mprotect looks up page 0 and never matches. */
struct mmap_pend_t { u64 len; u32 prot; u32 flags; };
BPF_HASH(mmap_pending, u64, struct mmap_pend_t, 10240);

/* Per-artifact coalescing. key = pid ^ hash(path) */
BPF_TABLE("lru_hash", u64, u64, artifact_seen, 65536);

/* Runtimes whose W+X mappings are ordinary behaviour, populated by the loader.
   The key must be a struct: BCC rejects a bare array type here. */
struct comm_key_t { char comm[TASK_COMM_LEN]; };
BPF_HASH(jit_baseline, struct comm_key_t, u8, 64);

/* ========================================================================= */
/* helpers */
/* ========================================================================= */

static __always_inline int is_self(void)
{
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != FILTER_TGID)
        return 0;

    u32 z = 0;
    struct self_id_t *s = self_id.lookup(&z);
    if (!s || !s->latched)
        return 1;   /* pre-latch: our own TGID, conservative */

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    u64 sb = 0;
    bpf_probe_read_kernel(&sb, sizeof(sb), &t->start_boottime);
    return sb == s->start_boottime;
}

static __always_inline u32 task_netns(struct task_struct *t)
{
    u32 inum = 0;
    struct nsproxy *ns = NULL;
    struct net *net = NULL;
    bpf_probe_read_kernel(&ns, sizeof(ns), &t->nsproxy);
    if (!ns) return 0;
    bpf_probe_read_kernel(&net, sizeof(net), &ns->net_ns);
    if (!net) return 0;
    bpf_probe_read_kernel(&inum, sizeof(inum), &net->ns.inum);
    return inum;
}

/* H(bin) anchor: <s_dev, i_ino, i_ctime> of the currently mapped executable. */
static __always_inline void fill_binary_identity(struct task_struct *t, struct csec_t *sec)
{
    struct mm_struct *mm = NULL;
    struct file *exe = NULL;
    struct inode *inode = NULL;
    struct super_block *sb = NULL;

    bpf_probe_read_kernel(&mm, sizeof(mm), &t->mm);
    if (!mm) return;
    bpf_probe_read_kernel(&exe, sizeof(exe), &mm->exe_file);
    if (!exe) return;
    bpf_probe_read_kernel(&inode, sizeof(inode), &exe->f_inode);
    if (!inode) return;

    bpf_probe_read_kernel(&sec->bin_ino, sizeof(u64), &inode->i_ino);
    bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
    if (sb) {
        u32 dev = 0;
        bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
        sec->bin_dev = (u64)dev;
    }
    /* i_generation rather than i_ctime: the ctime field was renamed __i_ctime in 6.6
       and its layout is not stable across 5.8-6.8.  Inode generation
       lists inode generation as a key component anyway. */
    u32 gen = 0;
    bpf_probe_read_kernel(&gen, sizeof(gen), &inode->i_generation);
    sec->bin_gen = (u64)gen;
}

/* Fills the security context synchronously with the transition it describes. */
static __always_inline void fill_csec(struct csec_t *sec)
{
    u64 id_pid = bpf_get_current_pid_tgid();
    u64 id_uid = bpf_get_current_uid_gid();

    sec->ts = bpf_ktime_get_boot_ns();
    sec->pid = id_pid >> 32;
    sec->uid = id_uid & 0xFFFFFFFF;
    sec->cgroup_id = bpf_get_current_cgroup_id();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    sec->ppid = 0;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        pid_t ptgid = 0;
        bpf_probe_read_kernel(&ptgid, sizeof(ptgid), &parent->tgid);
        sec->ppid = (u64)ptgid;
    }
    sec->netns = task_netns(task);
    fill_binary_identity(task, sec);
    bpf_get_current_comm(&sec->comm, sizeof(sec->comm));
}

/* The BPF backend cannot lower a call to memset, and clang emits one for any
   object past its inline threshold -- every event struct here is over it.  So the
   zeroing is written as explicit stores with a compile-time constant length, which
   fully unrolls.  The two 1 KB payload buffers are deliberately NOT cleared: both
   are read by userspace only up to their explicit length field, and clearing them
   on every packet would cost more than it protects. */
#define KEXDR_BZERO(p, nbytes) do { \
    u8 *__q = (u8 *)(p); \
    _Pragma("unroll")                                                    \
    for (int __i = 0; __i < (int)(nbytes); __i++) __q[__i] = 0;          \
} while (0)

/* Same reasoning for the security-context copies: 80 B sits close to clang's inline threshold
   for memcpy, and a libcall there would fail the same way.  Both endpoints are at
   offset 0 of an 8-aligned map value, so the word-sized copy is aligned. */
#define KEXDR_BCOPY_CSEC(dst, src) do { \
    u64 *__d = (u64 *)(void *)(dst); \
    const u64 *__s = (const u64 *)(const void *)(src); \
    _Pragma("unroll")                                                    \
    for (int __i = 0; __i < (int)(sizeof(struct csec_t) / 8); __i++)     \
        __d[__i] = __s[__i];                                             \
} while (0)

/* Packet context has no process helpers (CGROUP_SKB exposes neither
   bpf_get_current_pid_tgid nor _comm nor _uid_gid on 6.8, measured), and `current` in
   an ingress softirq is not the peer anyway.  Anything emitted from there must carry
   the context that was latched on the socket, so the two constructors are separate. */
#define KEXDR_BCOPY_L7(dst, src) do { \
    u64 *__d = (u64 *)(void *)(dst); \
    const u64 *__s = (const u64 *)(const void *)(src); \
    _Pragma("unroll")                                                    \
    for (int __i = 0; __i < (int)(MAX_L7 / 8); __i++) __d[__i] = __s[__i]; \
} while (0)

static __always_inline struct syscall_event_t *new_event_raw(u32 type)
{
    u32 key = 0;
    struct syscall_event_t *e = syscall_buffer.lookup(&key);
    if (!e) return NULL;
    KEXDR_BZERO(e, sizeof(*e));
    e->event_type = type;
    return e;
}

static __always_inline struct syscall_event_t *new_event(u32 type)
{
    struct syscall_event_t *e = new_event_raw(type);
    if (!e) return NULL;
    fill_csec(&e->sec);
    return e;
}

/* djb2 over a bounded prefix; used only as a coalescing key, never as evidence. */
static __always_inline u64 str_hash(const char *s, int max)
{
    u64 h = 5381;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (i >= max) break;
        char c = s[i];
        if (c == 0) break;
        h = ((h << 5) + h) + (u64)c;
    }
    return h;
}

/* repeated accesses to the same artifact by the same process collapse
   in kernel.  This is a collection policy, not a detection policy: the first access
   in each TTL window is always emitted. */
static __always_inline int artifact_is_new(u64 pid, u64 h)
{
    u64 key = pid ^ (h << 1);
    u64 now = bpf_ktime_get_boot_ns();
    u64 *prev = artifact_seen.lookup(&key);
    if (prev && (now - *prev) < COALESCE_TTL_NS)
        return 0;
    artifact_seen.update(&key, &now);
    return 1;
}

/* ========================================================================= */
/* execution provenance and privilege transitions */
/* ========================================================================= */

int trace_exec_syscall(struct tracepoint__syscalls__sys_enter_execve *ctx)
{
    if (is_self()) return 0;

    struct syscall_event_t *event = new_event(EV_EXEC);
    if (!event) return 0;

    bpf_probe_read_user_str(&event->data.exec.filename,
                            sizeof(event->data.exec.filename), (void *)ctx->filename);

    const char __user *const __user *argp = ctx->argv;
    const char __user *arg = NULL;
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        if (bpf_probe_read_user(&arg, sizeof(arg), &argp[i]) != 0) break;
        if (!arg) break;
        bpf_probe_read_user_str(event->data.exec.args[i], ARG_LEN, arg);
        event->arg_count++;
    }
    /* reserved ring: execve is never dropped under overload */
    prio_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_fork(struct tracepoint__sched__sched_process_fork *ctx)
{
    if (is_self()) return 0;
    struct syscall_event_t *event = new_event(EV_FORK);
    if (!event) return 0;
    event->data.life.child_pid = (u64)ctx->child_pid;
    /* Lineage Ledger input: every observed parent-child relation. */
    prio_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_exit(struct tracepoint__sched__sched_process_exit *ctx)
{
    if (is_self()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    /* thread exits are noise; only the thread-group leader closes a Tombstone */
    if ((id >> 32) != (id & 0xFFFFFFFF)) return 0;

    struct syscall_event_t *event = new_event(EV_EXIT);
    if (!event) return 0;
    prio_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_openat_syscall(struct tracepoint__syscalls__sys_enter_openat *ctx)
{
    /* Self-latch: the loader opens a sentinel immediately after attach,
       and we capture our own start_boottime in kernel rather than trusting a value
       handed down from userspace. */
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid == FILTER_TGID) {
        u32 z = 0;
        struct self_id_t *s = self_id.lookup(&z);
        if (s && !s->latched) {
            struct task_struct *t = (struct task_struct *)bpf_get_current_task();
            u64 sb = 0;
            bpf_probe_read_kernel(&sb, sizeof(sb), &t->start_boottime);
            s->tgid = tgid;
            s->start_boottime = sb;
            s->latched = 1;
        }
        return 0;
    }
    if (is_self()) return 0;

    struct syscall_event_t *event = new_event(EV_OPEN);
    if (!event) return 0;
    bpf_probe_read_user_str(&event->data.open.filename,
                            sizeof(event->data.open.filename),
                            (const char __user *)ctx->filename);

    u64 h = str_hash(event->data.open.filename, DATA_BUF_LEN_MAX);
    if (!artifact_is_new(event->sec.pid, h)) return 0;

    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

/* connect() is kept as a *syscall* record because it states intent (the logical
   destination the process asked for) even when the flow is later rewritten by a
   proxy or SNAT rule.  Ownership itself is not established here — sk_storage is. */
int trace_connect_syscall(struct tracepoint__syscalls__sys_enter_connect *ctx)
{
    if (is_self()) return 0;

    const struct sockaddr __user *uaddr = (const struct sockaddr __user *)ctx->uservaddr;
    if (!uaddr) return 0;

    struct syscall_event_t *event = new_event(EV_CONNECT);
    if (!event) return 0;

    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family);
    event->data.connect.family = family;

    if (family == AF_INET) {
        struct sockaddr_in a4 = {};
        bpf_probe_read_user(&a4, sizeof(a4), uaddr);
        event->data.connect.daddr = a4.sin_addr.s_addr;
        event->data.connect.dport = bpf_ntohs(a4.sin_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 a6 = {};
        bpf_probe_read_user(&a6, sizeof(a6), uaddr);
        __builtin_memcpy(event->data.connect.daddr6, &a6.sin6_addr, 16);
        event->data.connect.dport = bpf_ntohs(a6.sin6_port);
    } else {
        return 0;
    }
    prio_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

/* ========================================================================= */
/* memory semantics for fileless threats */
/* ========================================================================= */

/* mmap is split across enter and exit.  sys_enter_mmap has the prot bits but not the
   address: its `addr` argument is only the caller's hint, and every anonymous mapping
   passes NULL there.  Recording that hint registers page 0, so the mprotect promotion
   check below never finds anything -- which is exactly what a ground-truth test of the
   deferred W->X pattern reports as a miss. */
int trace_mmap_syscall(struct tracepoint__syscalls__sys_enter_mmap *ctx)
{
    if (is_self()) return 0;

    u32 prot = (u32)ctx->prot;
    if (!(prot & PROT_WRITE))
        return 0;                       /* nothing we track starts read-only */

    u64 id = bpf_get_current_pid_tgid();
    struct mmap_pend_t p = {};
    p.len = (u64)ctx->len;
    p.prot = prot;
    p.flags = (u32)ctx->flags;
    mmap_pending.update(&id, &p);
    return 0;
}

int trace_mmap_exit(struct tracepoint__syscalls__sys_exit_mmap *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct mmap_pend_t *p = mmap_pending.lookup(&id);
    if (!p) return 0;

    u64 addr = (u64)ctx->ret;
    u32 prot = p->prot;
    u64 len = p->len;
    mmap_pending.delete(&id);

    if (addr == 0 || addr > 0xfffffffffffff000ULL)
        return 0;                       /* mmap failed; ret is a negative errno */

    u64 pid = id >> 32;

    /* Writable-but-not-executable ranges are remembered, not reported: they are the
       first half of the deferred W->X pattern that trace_mprotect_syscall looks for. */
    if (!(prot & PROT_EXEC)) {
        struct wkey_t k = {};
        k.pid = pid;
        k.page = addr >> 12;
        struct wrange_t w = {};
        w.addr = addr;
        w.len = len;
        w.ts = bpf_ktime_get_boot_ns();
        writable_ranges.update(&k, &w);
        return 0;
    }

    /* A mapping is only an injection indicator when it is writable AND executable.
       Requiring both matters: a filter on PROT_EXEC alone reports every ordinary
       library mapping -- a dozen or more per dynamically linked exec, carrying no path
       and so no provenance value -- on the reserved ring that exists to keep execve and
       connect from being crowded out. */
    struct syscall_event_t *event = new_event(EV_MMAP);
    if (!event) return 0;

    event->data.mmap_evt.addr = addr;
    event->data.mmap_evt.len = len;
    event->data.mmap_evt.prot = prot;
    event->data.mmap_evt.flags = p->flags;
    event->data.mmap_evt.wx_now = 1;

    /* JIT gating: a baselined runtime mapping W+X is expected behaviour.
       We annotate rather than drop, so the orchestrator keeps the option of scoring it. */
    struct comm_key_t ck = {};
    bpf_get_current_comm(&ck.comm, sizeof(ck.comm));
    u8 *jit = jit_baseline.lookup(&ck);
    event->data.mmap_evt.jit_baseline = jit ? 1 : 0;

    prio_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

/* the dominant loader pattern defers the W->X promotion to a second call,
   so mmap alone misses it.  Fixed-capacity per-PID LRU of previously writable ranges. */
int trace_mprotect_syscall(struct tracepoint__syscalls__sys_enter_mprotect *ctx)
{
    if (is_self()) return 0;

    u32 prot = (u32)ctx->prot;
    if (!(prot & PROT_EXEC)) return 0;

    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 addr = (u64)ctx->start;
    u64 len = (u64)ctx->len;

    /* mprotect may target an offset inside the mapping rather than its base, so walk
       back a bounded number of pages looking for a registered range that contains it.
       Bounded by construction: 16 lookups, only on mprotect, which is rare. */
    u8 promoted = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        struct wkey_t k = {};
        k.pid = pid;
        k.page = (addr >> 12) - (u64)i;
        struct wrange_t *w = writable_ranges.lookup(&k);
        if (w && addr >= w->addr && addr < (w->addr + w->len)) {
            promoted = 1;
            break;
        }
    }

    /* X-only on a range never seen writable is ordinary library loading; the
       promotion case is the one worth a record. */
    if (!promoted && !(prot & PROT_WRITE)) return 0;

    struct syscall_event_t *event = new_event(EV_MPROTECT);
    if (!event) return 0;
    event->data.mmap_evt.addr = addr;
    event->data.mmap_evt.len = len;
    event->data.mmap_evt.prot = prot;
    event->data.mmap_evt.wx_now = (prot & PROT_WRITE) ? 1 : 0;
    event->data.mmap_evt.wx_promoted = promoted;

    struct comm_key_t ck = {};
    bpf_get_current_comm(&ck.comm, sizeof(ck.comm));
    u8 *jit = jit_baseline.lookup(&ck);
    event->data.mmap_evt.jit_baseline = jit ? 1 : 0;

    prio_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_memfd_create_syscall(struct tracepoint__syscalls__sys_enter_memfd_create *ctx)
{
    if (is_self()) return 0;
    struct syscall_event_t *event = new_event(EV_MEMFD);
    if (!event) return 0;
    bpf_probe_read_user_str(&event->data.open.filename,
                            sizeof(event->data.open.filename),
                            (const char __user *)ctx->uname);
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_ptrace_syscall(struct tracepoint__syscalls__sys_enter_ptrace *ctx)
{
    if (is_self()) return 0;
    struct syscall_event_t *event = new_event(EV_INJECT);
    if (!event) return 0;
    /* request code and target PID distinguish benign debugging from hijacking */
    u64 raw[2];
    raw[0] = (u64)ctx->request;
    raw[1] = (u64)ctx->pid;
    bpf_probe_read_kernel(event->data.open.filename, sizeof(raw), raw);
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_unlinkat_syscall(struct tracepoint__syscalls__sys_enter_unlinkat *ctx)
{
    if (is_self()) return 0;
    struct syscall_event_t *event = new_event(EV_DELETE);
    if (!event) return 0;
    bpf_probe_read_user_str(&event->data.unlink.filename,
                            sizeof(event->data.unlink.filename),
                            (const char __user *)ctx->pathname);
    /* anti-forensics indicator: never coalesced */
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_setuid_syscall(struct tracepoint__syscalls__sys_enter_setuid *ctx)
{
    if (is_self()) return 0;
    struct syscall_event_t *event = new_event(EV_SETUID);
    if (!event) return 0;
    event->data.setuid.target_uid = (u32)ctx->uid;
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

/* =========================================================================
 * socket-unique attribution.  kappa = <netns, socket cookie>
 * ========================================================================= */

static __always_inline void stamp_socket(struct sk_ctx_t *v, u8 passive)
{
    /* Everything ahead of l7_buf, which is bounded by v->l7_len and reset below. */
    KEXDR_BZERO(v, __builtin_offsetof(struct sk_ctx_t, l7_buf));
    fill_csec(&v->sec);
    v->passive = passive;
}

#ifdef KEXDR_KAPPA
/* Active open.
   fentry runs on the caller's own connect() stack, so bpf_get_current_* refer to the
   connecting process even when the connect is non-blocking.  A SOCK_OPS program cannot
   be used here: on 6.8 that program type exposes neither the process-context helpers
   needed to build the security context nor bpf_sk_storage_get. */
#ifdef KEXDR_KAPPA_TRACING
KFUNC_PROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    if (!sk) return 0;
    if (is_self()) return 0;
    struct sk_ctx_t *v = sk_ctx_map.sk_storage_get(sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!v) return 0;
    stamp_socket(v, 0);
    return 0;
}

KFUNC_PROBE(tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    if (!sk) return 0;
    if (is_self()) return 0;
    struct sk_ctx_t *v = sk_ctx_map.sk_storage_get(sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!v) return 0;
    stamp_socket(v, 0);
    return 0;
}

/* These two must be fentry/fexit, not kprobes.  bpf_sk_storage_get is exposed to
   BPF_PROG_TYPE_TRACING only: a kprobe asking for it fails to load with
   "unknown func bpf_sk_storage_get#107".  fentry/fexit also hand us a BTF-typed
   struct sock * rather than a scalar dug out of pt_regs.  The cost is that the
   argument lists below must match the kernel's prototypes, so this block is compiled
   separately and dropped if it does not.

   A listening socket has no owner until its handshake completes, which is why the
   write for a passive open happens at accept rather than at listen. */
KRETFUNC_PROBE(inet_csk_accept, struct sock *lsk, int flags, int *err, bool kern,
               struct sock *ret)
{
    if (!ret) return 0;
    if (is_self()) return 0;

    struct sk_ctx_t *v = sk_ctx_map.sk_storage_get(ret, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!v) return 0;
    stamp_socket(v, 1);
    return 0;
}

/* Connected UDP carries most DNS traffic and takes the same path. */
KFUNC_PROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk) return 0;
    if (is_self()) return 0;

    struct sk_ctx_t *v = sk_ctx_map.sk_storage_get(sk, 0, 0);
    if (v) return 0;   /* already owned */
    v = sk_ctx_map.sk_storage_get(sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!v) return 0;
    stamp_socket(v, 0);
    return 0;
}
#endif /* KEXDR_KAPPA_TRACING */
#endif /* KEXDR_KAPPA */

/* ---------------- bounded L7 projection ---------------- */

/* Coarse in-kernel classification only.  Structured decoding into HTTP/TLS/DNS/SSH/
   MySQL/PostgreSQL/Redis/SMB/FTP/LDAP/ICMP is deferred to userspace over the payload
   already captured here. */
#define L7_UNKNOWN 0
#define L7_HTTP 1
#define L7_SSH 3
#define L7_FTP 4
#define L7_SMB 6
#define L7_DNS 7
#define L7_MYSQL 8
#define L7_PGSQL 9
#define L7_REDIS 10
#define L7_LDAP 11
#define L7_ICMP 13
#define L7_TLS 14
#define L7_QUIC 20   /* reported unresolved: no application-layer destination */

static __always_inline u8 classify_window(u8 *buf, u32 len, u16 sport, u16 dport, u8 l4)
{
    if (l4 == IPPROTO_ICMP) return L7_ICMP;

    if (l4 == IPPROTO_UDP) {
        if (dport == 53 || sport == 53) return L7_DNS;
        if (dport == 443 || sport == 443) return L7_QUIC;
        return L7_UNKNOWN;
    }

    if (len >= 3) {
        if (buf[0] == 22 && buf[1] == 3) return L7_TLS;
        if (buf[0] == 'S' && buf[1] == 'S' && buf[2] == 'H') return L7_SSH;
        if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') return L7_HTTP;
        if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S') return L7_HTTP;
        if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T') return L7_HTTP;
        if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T') return L7_HTTP;
        if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L') return L7_HTTP;
        if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A') return L7_HTTP;
        if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T') return L7_HTTP;
        if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T') return L7_HTTP;
        if (buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N') return L7_HTTP;
    }
    if (len >= 4 && buf[0] == 0xfe && buf[1] == 'S' && buf[2] == 'M' && buf[3] == 'B')
        return L7_SMB;
    if (len >= 1 && buf[0] == '*') {
        if (dport == 6379 || sport == 6379) return L7_REDIS;
    }
    if (len >= 1 && buf[0] == 0x30) {
        if (dport == 389 || sport == 389 || dport == 636 || sport == 636) return L7_LDAP;
    }

    /* port-derived last resort; the decoder in userspace still gets the bytes */
    if (dport == 3306 || sport == 3306) return L7_MYSQL;
    if (dport == 5432 || sport == 5432) return L7_PGSQL;
    if (dport == 6379 || sport == 6379) return L7_REDIS;
    if (dport == 21   || sport == 21)   return L7_FTP;
    if (dport == 445  || sport == 445)  return L7_SMB;
    if (dport == 389  || sport == 389)  return L7_LDAP;
    if (dport == 53   || sport == 53)   return L7_DNS;
    return L7_UNKNOWN;
}

/* Appends this packet's payload to the socket's reassembly window. */
static __always_inline int window_append(struct __sk_buff *skb, struct sk_ctx_t *v,
                                         u32 poff, u32 plen)
{
    /* The offset is bounded by masking rather than by a branch.  Branch refinement
       applies to a register, and clang may spill this value before the test and reload
       the unrefined copy afterwards, in which case the bound never reaches the pointer
       arithmetic and the verifier rejects the access.  A mask is data flow, so whatever
       gets spilled is already bounded. */
    u32 off = v->l7_len & (MAX_L7 - 1);
    if (off >= MAX_L7 - L7_CHUNK)
        return 0;

    /* Copy exactly what this packet carries, up to one chunk.  Rounding down to a
       power of two would cut a short record such as a DNS question mid-field.  want is
       masked rather than clamped so its bound also reaches the pointer arithmetic. */
    u32 want = plen & (L7_CHUNK - 1);   /* 0..255 */
    if (plen >= L7_CHUNK)
        want = L7_CHUNK - 1;
    if (want == 0)
        return 0;

    /* off is at most MAX_L7-1 and want at most L7_CHUNK-1, while the buffer runs to
       MAX_L7 + L7_CHUNK, so this is in range for every value either can take. */
    if (bpf_skb_load_bytes(skb, poff, &v->l7_buf[off & (MAX_L7 - 1)], want) != 0)
        return 0;
    v->l7_len = off + want;             /* <= 767 + 255 = 1022 */
    return want;
}

/* Shared IPv4/IPv6 parse + kappa recovery + window management. */
static __always_inline int project_skb(struct __sk_buff *skb, u32 nhoff, u8 egress,
                                       u8 have_sk)
{
    u32 zero = 0;
    struct network_event_t *event = network_buffer.lookup(&zero);
    if (!event) return 0;
    KEXDR_BZERO(event, __builtin_offsetof(struct network_event_t, raw_payload));

    u8 vbyte = 0;
    if (bpf_skb_load_bytes(skb, nhoff, &vbyte, 1) < 0) return 0;
    u8 ver = vbyte >> 4;

    u32 l4_off = 0;
    u8 l4 = 0;
    u16 l3_payload = 0;

    if (ver == 4) {
        u8 ihl = (vbyte & 0x0F) * 4;
        u16 tot = 0;
        if (bpf_skb_load_bytes(skb, nhoff + 2, &tot, 2) < 0) return 0;
        tot = bpf_ntohs(tot);
        bpf_skb_load_bytes(skb, nhoff + 8, &event->ip_ttl, 1);
        bpf_skb_load_bytes(skb, nhoff + 9, &l4, 1);
        bpf_skb_load_bytes(skb, nhoff + 12, &event->src_ip, 4);
        bpf_skb_load_bytes(skb, nhoff + 16, &event->dst_ip, 4);
        if (tot < ihl) return 0;
        l3_payload = tot - ihl;
        l4_off = nhoff + ihl;
        event->ip_ver = 4;
    } else if (ver == 6) {
        /* IPv4 and IPv6 are both parsed.  A chain of extension headers
           past the fixed header is not walked; such a packet degrades to L4. */
        u16 plen = 0;
        if (bpf_skb_load_bytes(skb, nhoff + 4, &plen, 2) < 0) return 0;
        l3_payload = bpf_ntohs(plen);
        bpf_skb_load_bytes(skb, nhoff + 6, &l4, 1);
        bpf_skb_load_bytes(skb, nhoff + 7, &event->ip_ttl, 1);
        bpf_skb_load_bytes(skb, nhoff + 8, event->src_ip6, 16);
        bpf_skb_load_bytes(skb, nhoff + 24, event->dst_ip6, 16);
        l4_off = nhoff + 40;
        event->ip_ver = 6;
    } else {
        return 0;
    }

    u32 poff = 0, plen = 0;
    u32 seq = 0;

    if (l4 == IPPROTO_TCP) {
        u16 s = 0, d = 0;
        bpf_skb_load_bytes(skb, l4_off, &s, 2);
        bpf_skb_load_bytes(skb, l4_off + 2, &d, 2);
        event->src_port = bpf_ntohs(s);
        event->dst_port = bpf_ntohs(d);
        bpf_skb_load_bytes(skb, l4_off + 4, &seq, 4);
        seq = bpf_ntohl(seq);
        u8 doff_b = 0;
        bpf_skb_load_bytes(skb, l4_off + 12, &doff_b, 1);
        u8 doff = (doff_b >> 4) * 4;
        bpf_skb_load_bytes(skb, l4_off + 13, &event->tcp_flags, 1);
        if (l3_payload > doff) plen = l3_payload - doff;
        poff = l4_off + doff;
    } else if (l4 == IPPROTO_UDP) {
        u16 s = 0, d = 0;
        bpf_skb_load_bytes(skb, l4_off, &s, 2);
        bpf_skb_load_bytes(skb, l4_off + 2, &d, 2);
        event->src_port = bpf_ntohs(s);
        event->dst_port = bpf_ntohs(d);
        if (l3_payload > 8) plen = l3_payload - 8;
        poff = l4_off + 8;
    } else if (l4 == IPPROTO_ICMP || l4 == IPPROTO_ICMPV6) {
        plen = l3_payload;
        poff = l4_off;
    } else {
        return 0;
    }

    event->protocol = l4;
    event->egress = egress;
    event->timestamp = bpf_ktime_get_boot_ns();


    struct sk_ctx_t *v = NULL;
#ifdef KEXDR_KAPPA
    if (have_sk) {
        struct bpf_sock *sk = skb->sk;
        if (sk) {
            sk = bpf_sk_fullsock(sk);
            if (sk)
                v = sk_ctx_map.sk_storage_get(sk, 0, 0);
        }
    }
#endif

    if (!v) {
        /* kappa unavailable: unconnected datagram socket, forwarded traffic, or a
           packet that reached the backlog before accept() returned.  These are tagged
           degraded and carry no owner rather than being guessed at. */
        /* kappa5 = <netns, proto, saddr, sport, daddr, dport>.  The netns component
           is not optional: without it the key is a bare five-tuple, and two containers
           can legitimately hold the same one. */
        event->attribution = A_DEGRADED;

        /* kappa5 = <netns, proto, saddr, sport, daddr, dport> is netns-SCOPED, and we
           cannot supply the netns component here.  netns is a property of the socket
           or the task, and this branch is by definition reached when there is no
           socket; bpf_get_netns_cookie is not exposed to CGROUP_SKB on 6.8 (measured),
           and `current` in the ingress softirq is not the peer.  So the key we can
           actually build is a bare five-tuple.  It is reported as such -- netns 0 with
           netns_scoped false -- so the orchestrator never treats it as disambiguated
           between namespaces. */
        event->netns = 0;
        if (plen > 0) {
            u32 want = plen > L7_CHUNK ? L7_CHUNK : plen;
            #pragma unroll
            for (int i = 0; i < 7; i++) {
                u32 n = L7_CHUNK >> i;
                if (n > want) continue;
                if (bpf_skb_load_bytes(skb, poff, event->raw_payload, n) == 0) {
                    event->payload_len = n;
                    break;
                }
            }
        }
        /* These bytes came from this packet, so the payload direction is the record's
           own direction -- unlike the exact path, where the shipped window may have
           been accumulated on earlier packets. */
        event->l7_dir = egress;
        event->app_protocol = classify_window(event->raw_payload, event->payload_len,
                                              event->src_port, event->dst_port, l4);
        network_events.perf_submit(skb, event, sizeof(*event));
        return 0;
    }

    /* ---- exact path ---- */
    if (v->cookie == 0)
        v->cookie = bpf_get_socket_cookie(skb);

    event->attribution = A_EXACT;
    event->cookie = v->cookie;
    event->netns = v->sec.netns;
    event->passive = v->passive;
    KEXDR_BCOPY_CSEC(&event->sec, &v->sec);

    /* Announce the socket-key to owner binding once per socket so the orchestrator can
       index it in O(1) and never has to match on a tuple. */
    if (!v->bind_emitted) {
        v->bind_emitted = 1;
        struct syscall_event_t *be = new_event_raw(EV_BIND);
        if (be) {
            /* current is wrong here (softirq), so copy the stored context verbatim */
            KEXDR_BCOPY_CSEC(&be->sec, &v->sec);
            be->data.connect.cookie = v->cookie;
            be->data.connect.dport = event->dst_port;
            be->data.connect.daddr = event->dst_ip;
            be->data.connect.family = (event->ip_ver == 6) ? AF_INET6 : AF_INET;
            __builtin_memcpy(be->data.connect.daddr6, event->dst_ip6, 16);
            prio_events.perf_submit(skb, be, sizeof(*be));
        }
    }

    /* ---- reassembly window ----
       Up to 1024 B over the first 4 segments, in sequence order.  A field an adversary
       split across segments therefore still classifies; a field deferred beyond the
       window falls back to L4, which userspace reports rather than mis-parses. */
    /* The window is PER DIRECTION.  Appending both directions into one buffer splices
       a request and its reply together, and makes the in-sequence test meaningless
       because the two directions carry independent sequence spaces.  The direction is
       latched on the first payload-bearing packet, which picks the requesting side of
       an active open and of an accepted connection alike -- in both cases the side
       whose first bytes name the destination (request line, ClientHello, DNS question).
       The other direction still yields flow records, just no payload. */
    if (plen > 0 && !v->l7_dir_set) {
        v->l7_dir_set = 1;
        v->l7_dir = egress;
    }

    if (plen > 0 && !v->window_closed && v->l7_dir == egress) {
        int in_order = (v->seg_count == 0) || (seq == v->next_seq) || (l4 != IPPROTO_TCP);
        if (in_order) {
            int n = window_append(skb, v, poff, plen);
            if (n > 0) {
                v->seg_count++;
                if (l4 == IPPROTO_TCP) v->next_seq = seq + plen;
                /* The window also has to close when the message is simply complete.
                   Waiting only for MAX_SEGS or a full buffer means a one-segment
                   request -- an HTTP GET, a DNS question, a short ClientHello, i.e.
                   the common case -- never closes, so its projection is never shipped
                   and the flow reports no logical destination at all.  PSH is the
                   sender saying "that was a message"; a datagram is one by definition.
                   A ClientHello split across segments still accumulates, because the
                   stack sets PSH only on the last segment of a write. */
                u8 psh = (l4 == IPPROTO_TCP) ? (event->tcp_flags & 0x08) : 1;
                if (v->seg_count >= MAX_SEGS || v->l7_len >= MAX_L7 - L7_CHUNK || psh)
                    v->window_closed = 1;
            }
        }
        /* a retransmission or a reorder inside the window is tolerated: we simply
           do not advance, and the next in-sequence segment lands normally */
    } else if (plen > 0) {
        v->window_closed = 1;
    }

    if (v->l7_proto == L7_UNKNOWN)
        v->l7_proto = classify_window(v->l7_buf, v->l7_len,
                                      event->src_port, event->dst_port, l4);
    event->app_protocol = v->l7_proto;
    event->seg_count = (u8)v->seg_count;

    /* Emit the projection once the window closes, then coalesce flow records so a
       long-lived socket does not re-ship its prefix on every packet. */
    u64 now = event->timestamp;
    int emit = 0;

    if (v->window_closed && !v->emitted_l7) {
        v->emitted_l7 = 1;
        emit = 1;
        u32 n = v->l7_len;
        if (n > MAX_L7) n = MAX_L7;
        event->payload_len = (u16)n;
        event->truncated = (v->seg_count >= MAX_SEGS) ? 1 : 0;
        event->l7_dir = v->l7_dir;
        /* Both sides are map values, i.e. direct memory: the helper buys nothing here
           and bpf_probe_read_kernel is one of the constructs gated per program type.
           An unrolled word copy has neither problem. */
        KEXDR_BCOPY_L7(event->raw_payload, v->l7_buf);
    } else if ((now - v->last_report_ns) > COALESCE_TTL_NS) {
        emit = 1;
        event->payload_len = 0;   /* flow record: header semantics only */
    }

    if (emit) {
        v->last_report_ns = now;
        network_events.perf_submit(skb, event, sizeof(*event));
    }
    return 0;
}

/* cgroup_skb sees the packet starting at the network header, and — crucially — has
   skb->sk, which is what makes the binding exact. */
#ifdef KEXDR_KAPPA
int kexdr_skb_egress(struct __sk_buff *skb) { project_skb(skb, 0, 1, 1); return 1; }
int kexdr_skb_ingress(struct __sk_buff *skb) { project_skb(skb, 0, 0, 1); return 1; }
#endif

/* Degraded leg only.  A raw socket filter is an off-socket collector: it starts at the
   Ethernet header and has no owning socket, so everything it reports is A_DEGRADED.
   It exists to cover forwarded traffic and hosts where cgroup attach is unavailable. */
int socket_filter(struct __sk_buff *skb)
{
    u32 nhoff = 0xFFFFFFFF;
    u8 vb = 0;
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 14, &vb, 1); if ((vb >> 4) == 4 || (vb >> 4) == 6) nhoff = 14; }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 16, &vb, 1); if ((vb >> 4) == 4 || (vb >> 4) == 6) nhoff = 16; }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 0,  &vb, 1); if ((vb >> 4) == 4 || (vb >> 4) == 6) nhoff = 0;  }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 4,  &vb, 1); if ((vb >> 4) == 4 || (vb >> 4) == 6) nhoff = 4;  }
    if (nhoff == 0xFFFFFFFF) return 0;
    project_skb(skb, nhoff, 2, 0);
    return 0;
}
"""


# ============================================================================
# Userspace: wire structures (must mirror the C definitions byte for byte)
# ============================================================================
class Csec(ct.Structure):
    """Security context: timestamp, PID, PPID, UID, cgroup id, binary identity."""
    _pack_ = 1
    _fields_ = [
        ("ts", ct.c_uint64),
        ("pid", ct.c_uint64),
        ("ppid", ct.c_uint64),
        ("cgroup_id", ct.c_uint64),
        ("uid", ct.c_uint32),
        ("netns", ct.c_uint32),
        ("bin_dev", ct.c_uint64),
        ("bin_ino", ct.c_uint64),
        ("bin_gen", ct.c_uint64),
        ("comm", ct.c_char * 16),
    ]


class SyscallEvent(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("sec", Csec),
        ("event_type", ct.c_uint32),
        ("arg_count", ct.c_uint32),
        ("data", ct.c_ubyte * 256),
    ]


class NetworkEvent(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("sec", Csec),
        ("cookie", ct.c_uint64),
        ("timestamp", ct.c_uint64),
        ("netns", ct.c_uint32),
        ("ip_ver", ct.c_uint8),
        ("attribution", ct.c_uint8),
        ("protocol", ct.c_uint8),
        ("app_protocol", ct.c_uint8),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_ip6", ct.c_ubyte * 16),
        ("dst_ip6", ct.c_ubyte * 16),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("payload_len", ct.c_uint16),
        ("ip_ttl", ct.c_uint8),
        ("tcp_flags", ct.c_uint8),
        ("egress", ct.c_uint8),
        ("seg_count", ct.c_uint8),
        ("truncated", ct.c_uint8),
        ("passive", ct.c_uint8),
        ("l7_dir", ct.c_uint8),
        ("raw_payload", ct.c_ubyte * 1024),
    ]


class MmapData(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("addr", ct.c_uint64),
        ("len", ct.c_uint64),
        ("prot", ct.c_uint32),
        ("flags", ct.c_uint32),
        ("wx_now", ct.c_uint8),
        ("wx_promoted", ct.c_uint8),
        ("jit_baseline", ct.c_uint8),
        ("pad", ct.c_uint8),
    ]


class ConnectData(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("daddr", ct.c_uint32),
        ("dport", ct.c_uint16),
        ("family", ct.c_uint16),
        ("daddr6", ct.c_ubyte * 16),
        ("cookie", ct.c_uint64),
    ]


# Event type ids, mirrored from the C side.
EV_EXEC, EV_OPEN, EV_CONNECT = 0, 1, 2
EV_MEMFD, EV_INJECT, EV_DELETE, EV_SETUID, EV_MMAP = 5, 6, 7, 8, 9
EV_MPROTECT, EV_BIND, EV_FORK, EV_EXIT = 10, 11, 12, 13

A_EXACT, A_DEGRADED = 1, 2

PROTO_NAMES = {
    0: "UNKNOWN", 1: "HTTP", 3: "SSH", 4: "FTP", 6: "SMB", 7: "DNS",
    8: "MySQL", 9: "PostgreSQL", 10: "Redis", 11: "LDAP", 13: "ICMP",
    14: "TLS", 20: "QUIC",
}

PORT_MAP = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 8080: "HTTP", 443: "HTTPS", 8443: "HTTPS",
    110: "POP3", 995: "POP3", 139: "NetBIOS", 445: "SMB",
    143: "IMAP", 993: "IMAP", 161: "SNMP", 389: "LDAP", 636: "LDAP",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}

# Runtimes whose W+X mappings are ordinary JIT behaviour.  The kernel
# only annotates; the decision to down-weight stays in userspace and in the graph.
TASK_COMM_LEN = 16  # must match the kernel-side #define

JIT_BASELINE_COMMS = [
    "java", "node", "python3", "python", "mono", "dotnet", "chrome",
    "firefox", "beam.smp", "ruby", "julia", "lua", "php-fpm", "wine",
]

ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]|\x1B]0;.*?\x07')

seen_flows = {}
attached_interfaces = set()
attach_latencies = []          # mean attach latency after iface creation

# kappa index: <netns, cookie> -> owning process, published for the orchestrator.
kappa_index = OrderedDict()
KAPPA_INDEX_MAX = 200000

# Short-lived record of exactly-attributed five-tuples, so the degraded raw-socket leg
# does not re-report a flow the cgroup path already bound exactly.
exact_flow_ttl = OrderedDict()
EXACT_FLOW_TTL_S = 10.0

# H(bin): SHA-256 resolved once per <dev, ino, generation> and cached.
_binhash_cache = OrderedDict()
BINHASH_CACHE_MAX = 8192

STATS = {
    "syscall_events": 0,
    "network_events": 0,
    "exact": 0,
    "degraded": 0,
    "degraded_dup": 0,   # duplicates of an exactly-bound flow, excluded from the ratio
    "lost_bulk": 0,
    "lost_prio": 0,
    "l7_unresolved": 0,
}


def strip_ansi(text):
    return ansi_escape.sub('', text).replace('\x07', '')


def int_to_ip(addr_int):
    try:
        return socket.inet_ntoa(struct.pack("=I", addr_int))
    except Exception:
        return "0.0.0.0"


def ip6_to_str(raw):
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes(raw))
    except Exception:
        return "::"


def extract_cstr(buf, maxlen):
    s = bytes(buf[:maxlen]).split(b'\x00', 1)[0]
    try:
        return s.decode('utf-8', 'replace')
    except Exception:
        return repr(s)


def decode_tcp_flags(flags):
    res = []
    for bit, name in ((0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"),
                      (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")):
        if flags & bit:
            res.append(name)
    return "[" + ", ".join(res) + "]" if res else "[NONE]"


def binary_hash(sec, pid):
    """Resolve H(bin) from the inode identity the kernel captured.

    The kernel cannot hash a binary, so it anchors the identity as
    <s_dev, i_ino, i_generation> and we digest the file once per identity.  If the
    file is already gone (the dropper deleted itself, which is the interesting case),
    we still return a stable identity string rather than nothing.
    """
    ident = (sec.bin_dev, sec.bin_ino, sec.bin_gen)
    if ident == (0, 0, 0):
        return None
    hit = _binhash_cache.get(ident)
    if hit is not None:
        _binhash_cache.move_to_end(ident)
        return hit

    digest = None
    try:
        with open("/proc/%d/exe" % pid, "rb") as f:
            h = hashlib.sha256()
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
            digest = "sha256:" + h.hexdigest()
    except Exception:
        digest = "inode:%d:%d:%d" % ident

    _binhash_cache[ident] = digest
    if len(_binhash_cache) > BINHASH_CACHE_MAX:
        _binhash_cache.popitem(last=False)
    return digest


def csec_dict(sec, pid_hint=None):
    """Serialise the security context as the orchestrator expects to consume it."""
    pid = int(sec.pid) if sec.pid else (pid_hint or 0)
    d = {
        "pid": pid,
        "ppid": int(sec.ppid),
        "uid": int(sec.uid),
        "cgroup_id": int(sec.cgroup_id),
        "netns": int(sec.netns),
        "comm": sec.comm.decode('utf-8', 'replace').rstrip('\x00'),
        "boot_ns": int(sec.ts),
    }
    bh = binary_hash(sec, pid)
    if bh:
        d["binary_hash"] = bh
    return d


def remember_kappa(netns, cookie, sec):
    if not cookie:
        return
    key = "%d:%d" % (netns, cookie)
    kappa_index[key] = sec
    kappa_index.move_to_end(key)
    if len(kappa_index) > KAPPA_INDEX_MAX:
        kappa_index.popitem(last=False)


# ============================================================================
# Rotated JSON logging (unchanged behaviour: YYYY-MM-DD/audit_HH.json)
# ============================================================================
def get_log_file_handle():
    global LOG_BASE_DIR, CURRENT_LOG_HANDLE, CURRENT_FILE_PATH
    if not LOG_BASE_DIR:
        return None

    now = datetime.now()
    day_dir = os.path.join(LOG_BASE_DIR, now.strftime("%Y-%m-%d"))
    full_path = os.path.join(day_dir, "audit_%s.json" % now.strftime("%H"))

    if full_path != CURRENT_FILE_PATH:
        if CURRENT_LOG_HANDLE:
            try:
                CURRENT_LOG_HANDLE.close()
            except Exception:
                pass
            CURRENT_LOG_HANDLE = None
        if not os.path.exists(day_dir):
            try:
                os.makedirs(day_dir, exist_ok=True)
            except Exception as e:
                print(f"{C.FAIL}Failed to create log dir: {e}{C.ENDC}")
                return None
        try:
            CURRENT_LOG_HANDLE = open(full_path, 'a', encoding='utf-8')
            CURRENT_FILE_PATH = full_path
            print(f"{C.OKCYAN}Log rotated: {full_path}{C.ENDC}")
        except Exception as e:
            print(f"{C.FAIL}Failed to open log file: {e}{C.ENDC}")
            return None
    return CURRENT_LOG_HANDLE


def log_json_event(data):
    handle = get_log_file_handle()
    if not handle:
        return
    try:
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        json.dump(data, handle)
        handle.write('\n')
        handle.flush()
    except Exception:
        pass


def format_header(ts, tag, color, pid, uid, ppid, cg, comm):
    return (f"{C.DIM}[{ts}]{C.ENDC} {color}[ {tag:<5} ]{C.ENDC} "
            f"{C.DIM}UID:{uid:<5} PID:{pid:<6} PPID:{ppid:<6} CG:{cg:<8} {comm:<16}{C.ENDC}")


def hdr(ts, tag, color, sec):
    comm = sec.comm.decode('utf-8', 'replace').rstrip('\x00')
    return format_header(ts, tag, color, sec.pid, sec.uid, sec.ppid, sec.cgroup_id, comm)

# --- L7 Parsers ---

def parse_http_details(payload):
    try:
        text = payload[:1024].decode('utf-8', 'ignore')
        lines = text.splitlines()
        if not lines: return None

        methods = ('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/')
        if not lines[0].startswith(methods): return None

        info = [f"Request/Status: {C.BOLD}{lines[0][:100]}{C.ENDC}"]
        for line in lines[1:]:
            line = line.strip()
            if not line: break
            if ': ' in line:
                key, val = line.split(': ', 1)
                val_display = val if len(val) < 120 else val[:117] + "..."
                info.append(f"{C.DIM}{key}:{C.ENDC} {val_display}")

        return "\n".join(info)
    except:
        return None


def parse_generic_text(payload):
    try:
        text = payload[:512].decode('utf-8', 'ignore')
        printable = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
        if printable / len(text) > 0.9:
            lines = text.splitlines()
            if len(lines) > 0:
                clean_lines = [l.strip() for l in lines if l.strip()]
                return "\n".join([f"{l[:100]}" for l in clean_lines])
    except:
        pass
    return None


def parse_tls_details(payload):
    try:
        if len(payload) < 9 or payload[0] != 22: return None
        hs_type = payload[5]
        if hs_type == 1:
            # Client Hello Logic
            pos = 43
            if pos >= len(payload): return "Client Hello"
            pos += 1 + payload[pos]
            if pos + 2 >= len(payload): return "Client Hello"
            pos += 2 + ((payload[pos] << 8) | payload[pos + 1])
            if pos >= len(payload): return "Client Hello"
            pos += 1 + payload[pos]
            if pos + 2 >= len(payload): return "Client Hello"
            ext_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2
            end = pos + ext_len
            sni = "N/A"
            while pos + 4 <= end and pos + 4 <= len(payload):
                etype = (payload[pos] << 8) | payload[pos + 1]
                elen = (payload[pos + 2] << 8) | payload[pos + 3]
                if etype == 0x0000:
                    if pos + 9 < len(payload):
                        nlen = (payload[pos + 7] << 8) | payload[pos + 8]
                        if pos + 9 + nlen <= len(payload):
                            sni = payload[pos + 9: pos + 9 + nlen].decode('utf-8', 'ignore')
                    break
                pos += 4 + elen
            return f"TLS Client Hello | SNI: {C.BOLD}{sni}{C.ENDC}"
        return f"TLS Handshake (Type {hs_type})"
    except:
        return None


def parse_dns_details(payload):
    try:
        if len(payload) < 12: return None
        trans_id = (payload[0] << 8) | payload[1]
        qr = (payload[2] >> 7) & 1
        pos = 12
        labels = []
        while pos < len(payload):
            length = payload[pos]
            if (length & 0xC0) == 0xC0:
                labels.append("<ptr>")
                pos += 2
                break
            if length == 0:
                pos += 1
                break
            pos += 1
            if pos + length > len(payload): break
            labels.append(payload[pos:pos + length].decode('utf-8', 'ignore'))
            pos += length

        qtype_str = ""
        if pos + 2 <= len(payload):
            qtype = (payload[pos] << 8) | payload[pos + 1]
            qtypes = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
            qtype_name = qtypes.get(qtype, f"TYPE{qtype}")
            qtype_str = f"[{qtype_name}] "

        type_label = "Response" if qr else "Query"
        return f"DNS {type_label} [ID:{trans_id:04x}] {qtype_str}{C.BOLD}{'.'.join(labels)}{C.ENDC}"
    except:
        return None


def parse_smb_details(payload):
    try:
        if payload.startswith(b'\xfeSMB'): return "SMB2/3 Header"
        if payload.startswith(b'\xffSMB'): return "SMB1 Header"
        if len(payload) > 5 and payload[4:8] == b'\xfeSMB': return "SMB2/3 (NetBIOS)"
        return None
    except:
        return None


def parse_ftp_details(payload):
    try:
        return payload.decode('utf-8', 'ignore').strip()
    except:
        return None


def parse_redis_details(payload):
    try:
        try:
            text = payload.decode('utf-8', 'ignore').strip()
        except:
            text = ""
        marker = payload[0:1]
        if marker == b'*':
            lines = re.split(b'\r?\n', payload)
            args = []
            idx = 1
            try:
                num_args = int(lines[0][1:])
                while idx < len(lines) and len(args) < num_args:
                    curr = lines[idx]
                    if curr.startswith(b'$'):
                        idx += 1
                        if idx < len(lines): args.append(lines[idx].decode('utf-8', 'ignore'))
                    elif curr:
                        args.append(curr.decode('utf-8', 'ignore'))
                    idx += 1
                return f"Redis Cmd: {' '.join(args)}"
            except:
                pass
        elif marker == b'+':
            return f"Redis Status: {text[1:]}"
        if text:
            first = text.split()[0].upper()
            if first in {'PING', 'SET', 'GET', 'DEL', 'KEYS', 'INFO', 'SELECT', 'AUTH'}:
                return f"Redis Inline: {text[:80]}"
        return None
    except:
        return None


def parse_mysql_details(payload):
    try:
        if len(payload) < 5: return None
        seq = payload[3]
        body = payload[4:]
        if seq == 0 and len(body) > 0:
            cmd = body[0]
            if cmd == 0x03: return f"MySQL Query: {body[1:].decode('utf-8', 'ignore').strip()}"
            if len(body) > 10 and body[0] == 10: return f"MySQL Server Greeting"
        if seq == 1 and len(body) > 30: return "MySQL Login Attempt"
        return None
    except:
        return None


def parse_pgsql_details(payload):
    try:
        if len(payload) < 5: return None
        if chr(payload[0]) == 'Q':
            query = payload[5:].split(b'\x00')[0].decode('utf-8', 'ignore')
            return f"PgSQL Query: {query}"
        return None
    except:
        return None


def parse_icmp_details(ev, payload):
    if len(payload) >= 2: return f"ICMP Type {payload[0]} Code {payload[1]}"
    return None


def parse_ldap_details(payload):
    if len(payload) > 5 and payload[0] == 0x30: return "LDAP Message (ASN.1)"
    return None



# ============================================================================
# Logical destination extraction
# ----------------------------------------------------------------------------
# Attribution and destination identification are two different questions.  kappa
# fixes *which process owns a flow*; this function answers *which endpoint the flow
# actually reaches*, from L7 semantics that survive the address rewriting a proxy or
# SNAT rule applies downstream of connect().  The orchestrator needs it as a field,
# not buried in a display string, because it is the join key for the gateway leg.
# ============================================================================
def _http_host(payload):
    try:
        head = payload[:1024].decode('utf-8', 'ignore')
        for line in head.split('\r\n')[1:]:
            if not line:
                break
            if line.lower().startswith('host:'):
                return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return None


def _tls_sni(payload):
    """Returns (sni, ech_present).  ECH means there is no cleartext destination."""
    try:
        if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
            return None, False
        pos = 43
        if pos >= len(payload):
            return None, False
        pos += 1 + payload[pos]                                    # session id
        if pos + 2 > len(payload):
            return None, False
        pos += 2 + ((payload[pos] << 8) | payload[pos + 1])         # cipher suites
        if pos >= len(payload):
            return None, False
        pos += 1 + payload[pos]                                     # compression
        if pos + 2 > len(payload):
            return None, False
        ext_len = (payload[pos] << 8) | payload[pos + 1]
        pos += 2
        end = min(pos + ext_len, len(payload))

        sni, ech = None, False
        while pos + 4 <= end:
            etype = (payload[pos] << 8) | payload[pos + 1]
            elen = (payload[pos + 2] << 8) | payload[pos + 3]
            if etype == 0x0000 and pos + 9 <= len(payload):
                nlen = (payload[pos + 7] << 8) | payload[pos + 8]
                if pos + 9 + nlen <= len(payload):
                    sni = payload[pos + 9: pos + 9 + nlen].decode('utf-8', 'ignore')
            elif etype == 0xfe0d:
                ech = True
            pos += 4 + elen
        return sni, ech
    except Exception:
        return None, False


def _dns_qname(payload):
    try:
        if len(payload) < 13:
            return None
        pos, labels = 12, []
        while pos < len(payload):
            n = payload[pos]
            if n == 0 or (n & 0xC0) == 0xC0:
                break
            pos += 1
            if pos + n > len(payload):
                break
            labels.append(payload[pos:pos + n].decode('utf-8', 'ignore'))
            pos += n
        return ".".join(labels) if labels else None
    except Exception:
        return None


def extract_l7_destination(proto_id, payload, dst_port, truncated):
    """-> (logical_dst, kind, status).

    status is one of L7_RESOLVED / L7_UNRESOLVED / L7_FALLBACK_L4.  We never invent a
    destination: QUIC and Encrypted Client Hello are reported unresolved, and a header
    deferred past the projection window is reported as an L4 fallback.  the cases; keeping them distinct in the log is what lets the orchestrator
    avoid asserting attribution it cannot establish.
    """
    if proto_id == 20:                       # QUIC
        return None, "quic", L7_UNRESOLVED

    if not payload:
        return None, None, L7_FALLBACK_L4

    if proto_id == 1:
        host = _http_host(payload)
        if host:
            return host, "http_host", L7_RESOLVED
        return None, "http_host", (L7_FALLBACK_L4 if truncated else L7_UNRESOLVED)

    if proto_id == 14:
        sni, ech = _tls_sni(payload)
        if sni:
            return sni, "tls_sni", L7_RESOLVED
        if ech:
            return None, "tls_ech", L7_UNRESOLVED
        return None, "tls_sni", (L7_FALLBACK_L4 if truncated else L7_UNRESOLVED)

    if proto_id == 7:
        q = _dns_qname(payload)
        if q:
            return q, "dns_qname", L7_RESOLVED
        return None, "dns_qname", L7_FALLBACK_L4

    return None, None, L7_FALLBACK_L4


# ============================================================================
# Network event handler
# ============================================================================
def handle_network_event(cpu, data, size):
    try:
        ev = ct.cast(data, ct.POINTER(NetworkEvent)).contents
        STATS["network_events"] += 1
        ts = datetime.now().strftime("%H:%M:%S")
        now = time.time()

        if ev.ip_ver == 6:
            sip, dip = ip6_to_str(ev.src_ip6), ip6_to_str(ev.dst_ip6)
        else:
            sip, dip = int_to_ip(ev.src_ip), int_to_ip(ev.dst_ip)

        exact = (ev.attribution == A_EXACT)
        # kappa5 = <netns, proto, saddr, sport, daddr, dport>.  The netns
        # component is what keeps two containers holding the same five-tuple apart, so
        # it is part of the key rather than a display field.
        netns_scoped = bool(ev.netns)
        kappa5 = "%s:%d:%s:%d:%s:%d" % (ev.netns if netns_scoped else "?",
                                        ev.protocol, sip, ev.src_port, dip, ev.dst_port)
        # The dedup key deliberately OMITS netns.  It has to: an exact record carries
        # the task netns inum and a degraded one cannot carry any netns at all, so a
        # netns-scoped key would never match across the two legs and every flow would
        # be reported twice.  What this match actually is, then, is a bare five-tuple
        # over a short window -- weaker than kappa5, and it is only ever used to drop a
        # duplicate, never to assert an owner.
        dedup_key = (sip, ev.src_port, dip, ev.dst_port, ev.protocol)

        if exact:
            STATS["exact"] += 1
            exact_flow_ttl[dedup_key] = now
            if len(exact_flow_ttl) > 20000:
                exact_flow_ttl.popitem(last=False)
        else:
            # Do not double-report a flow the cgroup path already bound exactly; the
            # degraded leg exists for traffic with no owning socket, not as a second
            # opinion on traffic that has one.
            seen_at = exact_flow_ttl.get(dedup_key)
            if seen_at and (now - seen_at) < EXACT_FLOW_TTL_S:
                # Counted apart from genuinely unattributed traffic: folding these into
                # `degraded` would deflate the exact share, which is the one number
                # meant to report how much traffic resolved through the socket key.
                STATS["degraded_dup"] += 1
                return
            STATS["degraded"] += 1

        payload = bytes(ev.raw_payload)[:min(ev.payload_len, 1024)]
        proto_id = ev.app_protocol
        proto_name = PROTO_NAMES.get(proto_id, "UNKNOWN")

        # Structured decoding over payload already captured in kernel.
        l7_info = None
        if payload:
            if proto_id == 1:
                l7_info = parse_http_details(payload)
            elif proto_id == 14:
                l7_info = parse_tls_details(payload)
            elif proto_id == 7:
                l7_info = parse_dns_details(payload)
            elif proto_id == 3 and payload.startswith(b'SSH-'):
                l7_info = "SSH Banner: " + payload.split(b'\r\n')[0].decode('utf-8', 'ignore')
            elif proto_id == 13:
                l7_info = parse_icmp_details(ev, payload)
            elif proto_id == 8:
                l7_info = parse_mysql_details(payload)
            elif proto_id == 9:
                l7_info = parse_pgsql_details(payload)
            elif proto_id == 10:
                l7_info = parse_redis_details(payload)
            elif proto_id == 6:
                l7_info = parse_smb_details(payload)
            elif proto_id == 4:
                l7_info = parse_ftp_details(payload)
            elif proto_id == 11:
                l7_info = parse_ldap_details(payload)
            if not l7_info:
                l7_info = parse_generic_text(payload)

        if proto_name == "UNKNOWN":
            if ev.dst_port in PORT_MAP:
                proto_name = PORT_MAP[ev.dst_port] + "?"
            elif ev.src_port in PORT_MAP:
                proto_name = PORT_MAP[ev.src_port] + "?"
            elif ev.protocol == 6:
                proto_name = "TCP"
            elif ev.protocol == 17:
                proto_name = "UDP"

        logical_dst, l7_kind, l7_status = extract_l7_destination(
            proto_id, payload, ev.dst_port, bool(ev.truncated))
        if l7_status == L7_UNRESOLVED:
            STATS["l7_unresolved"] += 1

        should_print = (l7_info is not None) or (dedup_key not in seen_flows) or \
                       (now - seen_flows.get(dedup_key, 0) > 5)

        direction = {1: "egress", 0: "ingress", 2: "promisc"}.get(ev.egress, "unknown")
        kappa = ("%d:%d" % (ev.netns, ev.cookie)) if exact else None

        if should_print:
            seen_flows[dedup_key] = now
            print(f"{C.DIM}{'-' * 78}{C.ENDC}")
            tag = (f"{C.OKGREEN}kappa={kappa}{C.ENDC}" if exact
                   else f"{C.WARNING}DEGRADED (kappa5){C.ENDC}")
            print(f"{C.C_NET}[ NET   ] {sip}:{ev.src_port} --> {dip}:{ev.dst_port} "
                  f"({proto_name}){C.ENDC} {C.DIM}[{direction}]{C.ENDC} {tag}")
            if exact:
                comm = ev.sec.comm.decode('utf-8', 'replace').rstrip('\x00')
                print(f"         {C.DIM}owner: {comm} pid={ev.sec.pid} "
                      f"cg={ev.sec.cgroup_id} {'passive' if ev.passive else 'active'}{C.ENDC}")
            if logical_dst:
                print(f"         {C.DIM}logical dst ({l7_kind}):{C.ENDC} {C.BOLD}{logical_dst}{C.ENDC}")
            elif l7_status == L7_UNRESOLVED:
                print(f"         {C.DIM}logical dst: unresolved ({l7_kind}){C.ENDC}")
            if ev.protocol == 6:
                print(f"         {C.DIM}Flags: {decode_tcp_flags(ev.tcp_flags)} "
                      f"segs={ev.seg_count}{C.ENDC}")
            if l7_info:
                for line in str(l7_info).split('\n'):
                    print(f"         {C.DIM}|-{C.ENDC} {line}")

            rec = {
                "type": "NETWORK",
                "subtype": proto_name,
                "src_ip": sip, "src_port": ev.src_port,
                "dst_ip": dip, "dst_port": ev.dst_port,
                "proto_id": ev.protocol,
                "ip_ver": ev.ip_ver,
                "direction": direction,
                # --- the fields the orchestrator joins on ---
                "attribution": ATTR_EXACT if exact else ATTR_DEGRADED,
                "netns": int(ev.netns),
                "sk_cookie": int(ev.cookie),
                "kappa": kappa,
                # Present on every record, exact or not: it is the degraded join key,
                # and on an exact record it is what lets a later degraded packet on the
                # same flow inherit this owner instead of being guessed at.
                "kappa5": kappa5,
                "netns_scoped": netns_scoped,
                # --- destination identification, kept separate from attribution ---
                "logical_dst": logical_dst,
                "l7_kind": l7_kind,
                "l7_status": l7_status,
                "segments": int(ev.seg_count),
                # Which direction the shipped bytes were captured in.  A loopback flow
                # is seen once per endpoint socket, so without this a request and its
                # reply are indistinguishable downstream.
                "l7_payload_dir": ("egress" if ev.l7_dir else "ingress"),
                "truncated": bool(ev.truncated),
                "payload_info": strip_ansi(str(l7_info)) if l7_info else "",
            }
            if exact:
                rec.update(csec_dict(ev.sec))
                rec["passive_open"] = bool(ev.passive)
            log_json_event(rec)

        if len(seen_flows) > 4000:
            seen_flows.clear()
    except Exception:
        pass


# ============================================================================
# Syscall / lifecycle event handler
# ============================================================================
PTRACE_REQ = {
    0: "PTRACE_TRACEME", 1: "PTRACE_PEEKTEXT", 2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSER", 4: "PTRACE_POKETEXT", 5: "PTRACE_POKEDATA",
    6: "PTRACE_POKEUSER", 8: "PTRACE_KILL", 9: "PTRACE_SINGLESTEP",
    16: "PTRACE_ATTACH", 17: "PTRACE_DETACH", 12: "PTRACE_GETREGS",
}


def prot_string(prot):
    parts = []
    if prot & 0x1: parts.append("READ")
    if prot & 0x2: parts.append("WRITE")
    if prot & 0x4: parts.append("EXEC")
    return "|".join(parts) if parts else "NONE"


def handle_syscall_event(cpu, data, size):
    try:
        ev = ct.cast(data, ct.POINTER(SyscallEvent)).contents
        STATS["syscall_events"] += 1
        sec = ev.sec
        ts_str = datetime.now().strftime("%H:%M:%S")
        comm = sec.comm.decode('utf-8', 'replace').rstrip('\x00')
        base = csec_dict(sec)
        et = ev.event_type

        if et == EV_EXEC:
            filename = extract_cstr(ev.data, 64)
            args = [filename]
            for i in range(1, min(ev.arg_count, 6)):
                off = 64 + (i * 32)
                a = extract_cstr(ev.data[off:off + 32], 32)
                if a:
                    args.append(a)
            cmd, arguments = args[0], " ".join(args[1:])
            print(f"{hdr(ts_str, 'EXEC', C.C_EXEC, sec)} CMD: {C.BOLD}{cmd} {arguments}{C.ENDC}")
            log_json_event(dict(base, type="SYSCALL", subtype="EXEC", cmd=cmd, args=arguments))

        elif et == EV_FORK:
            life = struct.unpack("QQ", bytes(ev.data[:16]))
            child = life[0]
            # Lineage Ledger input: every observed parent-child relation is recorded,
            # so a pruned ancestor can later be recovered by lineage as well as by
            # artifact.
            log_json_event(dict(base, type="SYSCALL", subtype="FORK", child_pid=child))

        elif et == EV_EXIT:
            # Closes a Process Tombstone: the orchestrator distils the terminated
            # process and keeps it discoverable after it leaves the active graph.
            print(f"{hdr(ts_str, 'EXIT', C.C_LIFE, sec)} process exited")
            log_json_event(dict(base, type="SYSCALL", subtype="EXIT"))

        elif et == EV_OPEN:
            fname = extract_cstr(ev.data, 256)
            if fname and not fname.startswith(('/proc', '/sys', '/dev', '/lib', '/usr')):
                print(f"{hdr(ts_str, 'OPEN', C.C_OPEN, sec)} {fname}")
                log_json_event(dict(base, type="SYSCALL", subtype="OPEN", filename=fname))

        elif et == EV_CONNECT:
            cd = ct.cast(ev.data, ct.POINTER(ConnectData)).contents
            if cd.family == socket.AF_INET6:
                daddr = ip6_to_str(cd.daddr6)
            else:
                daddr = int_to_ip(cd.daddr)
            if cd.dport:
                print(f"{hdr(ts_str, 'CONN', C.C_CONN, sec)} -> {daddr}:{cd.dport}")
                # This records *intent*, not ownership.  Ownership was already written
                # into sk_storage in kernel; the orchestrator must not re-derive it here.
                log_json_event(dict(base, type="SYSCALL", subtype="CONNECT",
                                    dst_ip=daddr, dst_port=cd.dport,
                                    requested_dst=f"{daddr}:{cd.dport}"))

        elif et == EV_BIND:
            cd = ct.cast(ev.data, ct.POINTER(ConnectData)).contents
            kappa = "%d:%d" % (sec.netns, cd.cookie)
            remember_kappa(sec.netns, cd.cookie, base)
            daddr = ip6_to_str(cd.daddr6) if cd.family == socket.AF_INET6 else int_to_ip(cd.daddr)
            print(f"{hdr(ts_str, 'BIND', C.C_BIND, sec)} kappa={kappa} -> {daddr}:{cd.dport}")
            # The binding announcement: <netns, cookie> -> owner.  This is what lets the
            # orchestrator do an O(1) exact join instead of a |t_net - t_host| <= delta
            # window over a five-tuple.
            log_json_event(dict(base, type="BIND", subtype="KAPPA", kappa=kappa,
                                netns=int(sec.netns), sk_cookie=int(cd.cookie),
                                dst_ip=daddr, dst_port=cd.dport))

        elif et == EV_MEMFD:
            name = extract_cstr(ev.data, 256)
            print(f"{hdr(ts_str, 'MEMFD', C.C_MEMFD, sec)} fileless storage: {name}")
            log_json_event(dict(base, type="SYSCALL", subtype="MEMFD", name=name))

        elif et == EV_INJECT:
            req_code, target_pid = struct.unpack("QQ", bytes(ev.data[:16]))
            req_name = PTRACE_REQ.get(req_code, f"PTRACE_CMD_{req_code}")
            if req_code == 0:
                target_pid = sec.ppid
            print(f"{hdr(ts_str, 'INJ', C.C_INJECT, sec)} {C.BOLD}{req_name}{C.ENDC} on PID {target_pid}")
            log_json_event(dict(base, type="SYSCALL", subtype="INJECT",
                                request_code=req_code, request_name=req_name,
                                target_pid=target_pid))

        elif et == EV_DELETE:
            fname = extract_cstr(ev.data, 256)
            print(f"{hdr(ts_str, 'DEL', C.C_DEL, sec)} DELETED: {fname}")
            log_json_event(dict(base, type="SYSCALL", subtype="DELETE", filename=fname))

        elif et == EV_SETUID:
            target_uid = struct.unpack("I", bytes(ev.data[:4]))[0]
            print(f"{hdr(ts_str, 'PRIV', C.C_PRIV, sec)} setuid -> {target_uid}")
            log_json_event(dict(base, type="SYSCALL", subtype="SETUID", target_uid=target_uid))

        elif et in (EV_MMAP, EV_MPROTECT):
            m = ct.cast(ev.data, ct.POINTER(MmapData)).contents
            p_str = prot_string(m.prot)
            wx = bool(m.wx_now) or bool(m.wx_promoted)
            if wx:
                label = "W+X promoted (mprotect)" if m.wx_promoted else "W+X at map time"
                color = C.FAIL
            else:
                label = "executable mapping"
                color = C.OKBLUE
            jit = " [JIT-baselined]" if m.jit_baseline else ""
            tag = "MPROT" if et == EV_MPROTECT else "MMAP"
            print(f"{hdr(ts_str, tag, color, sec)} {hex(m.addr)} len={m.len} "
                  f"[{p_str}] {label}{jit}")
            log_json_event(dict(base, type="SYSCALL",
                                subtype=("MPROTECT" if et == EV_MPROTECT else "MMAP"),
                                addr=hex(m.addr), len=m.len, prot=p_str,
                                is_exec=True,
                                wx=wx,
                                wx_promoted=bool(m.wx_promoted),
                                jit_baseline=bool(m.jit_baseline)))
    except Exception:
        traceback.print_exc()


# ============================================================================
# Loader
# ============================================================================
def build_bpf(pid, coalesce_ns):
    text = bpf_text_template.replace("YOUR_PID_GOES_HERE", str(pid))
    text = text.replace("COALESCE_TTL_GOES_HERE", str(coalesce_ns) + "ULL")
    return text


def load_jit_baseline(b):
    try:
        tbl = b["jit_baseline"]
        for name in JIT_BASELINE_COMMS:
            k = tbl.Key()
            raw = name.encode()[:TASK_COMM_LEN - 1]
            if hasattr(k, "comm"):
                k.comm = raw
            else:
                k.value = raw
            tbl[k] = tbl.Leaf(1)
    except Exception as e:
        print(f"{C.WARNING}Could not populate JIT baseline map: {e}{C.ENDC}")


def attach_cgroup_programs(b, cgroup_path):
    """Attach the exact-attribution path.  Returns a list of (fn, fd, type) to detach.

    Everything here is what makes the binding exact.  If any of it fails we say so
    loudly rather than continuing and quietly reporting tuple matches as attribution.
    """
    try:
        from bcc import BPFAttachType
        T_INGRESS = BPFAttachType.CGROUP_INET_INGRESS
        T_EGRESS = BPFAttachType.CGROUP_INET_EGRESS
    except Exception:
        T_INGRESS, T_EGRESS = 0, 1

    attached = []
    cg_fd = os.open(cgroup_path, os.O_RDONLY)

    # No sock_ops program any more: on 6.8 that type has neither the process helpers
    # needed to build the security context nor bpf_sk_storage_get.  Active opens bind through
    # fentry(tcp_v4_connect / tcp_v6_connect) instead, which BCC attaches at load.
    fn_eg = b.load_func("kexdr_skb_egress", BPF.CGROUP_SKB)
    b.attach_func(fn_eg, cg_fd, T_EGRESS)
    attached.append((fn_eg, cg_fd, T_EGRESS))

    fn_in = b.load_func("kexdr_skb_ingress", BPF.CGROUP_SKB)
    b.attach_func(fn_in, cg_fd, T_INGRESS)
    attached.append((fn_in, cg_fd, T_INGRESS))
    print(f"{C.OKGREEN}  cgroup_skb ingress+egress attached (kappa recovery live){C.ENDC}")
    return attached


def main():
    global LOG_BASE_DIR

    parser = argparse.ArgumentParser(description="keXDR kernel-native telemetry engine (K)")
    parser.add_argument("-i", "--iface", default="",
                        help="Interface for the degraded leg (default: auto-discover)")
    parser.add_argument("-o", "--output", default="",
                        help="Base directory for logs (YYYY-MM-DD/audit_HH.json)")
    parser.add_argument("--cgroup", default="/sys/fs/cgroup",
                        help="cgroup v2 mount point for the exact-attribution path")
    parser.add_argument("--no-kappa", action="store_true",
                        help="Skip socket-scoped binding; everything degrades to kappa5")
    parser.add_argument("--no-degraded-leg", action="store_true",
                        help="Do not attach the raw-socket fallback collector")
    parser.add_argument("--no-coalesce", action="store_true",
                        help="Disable per-artifact coalescing (~11.4%% CPU)")
    parser.add_argument("--coalesce-ms", type=int, default=5000,
                        help="Per-artifact coalescing window in ms (default 5000)")
    parser.add_argument("--scan-interval", type=float, default=2.0,
                        help="Interface tracker period in seconds (default 2)")
    parser.add_argument("--stats-interval", type=float, default=60.0,
                        help="Seconds between attribution statistics lines")
    args = parser.parse_args()

    print(f"{C.HEADER}{'=' * 80}{C.ENDC}")
    print(f"{C.HEADER}keXDR — Kernel-Native Telemetry (K){C.ENDC}")
    print(f"{C.DIM}kappa = <netns, socket cookie> on bpf_sk_storage | bounded L7 "
          f"projection <= 1024 B{C.ENDC}")
    print(f"{C.HEADER}{'=' * 80}{C.ENDC}")

    if args.output:
        LOG_BASE_DIR = args.output
        os.makedirs(LOG_BASE_DIR, exist_ok=True)
        print(f"{C.OKCYAN}Logging to {LOG_BASE_DIR}{C.ENDC}")

    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK,
                           (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:
        pass

    my_pid = os.getpid()
    coalesce_ns = 0 if args.no_coalesce else args.coalesce_ms * 1000000
    text = build_bpf(my_pid, coalesce_ns)

    # Compile with the exact-attribution path first; fall back only if the kernel
    # cannot support it, and say which mode we ended up in.
    b = None
    kappa_mode = False
    tracing_legs = False
    if not args.no_kappa:
        # Stage 1: everything, including the fexit/fentry legs.  Those depend on the
        # kernel's prototypes for inet_csk_accept and udp_sendmsg, which do change
        # across releases, so they get their own attempt.
        try:
            b = BPF(text=text, cflags=["-DKEXDR_KAPPA", "-DKEXDR_KAPPA_TRACING"])
            kappa_mode = True
            tracing_legs = True
        except Exception as e:
            print(f"{C.WARNING}fexit/fentry legs unavailable: "
                  f"{str(e).strip().splitlines()[-1] if str(e).strip() else e}{C.ENDC}")
            print(f"{C.WARNING}  (needs BTF and matching prototypes for inet_csk_accept "
                  f"/ udp_sendmsg){C.ENDC}")
        # Fallback: keep whatever binds without the fentry/fexit legs.  Passive opens and
        # connected UDP lose their owner and fall to kappa5 -- partial, not fake.
        if b is None:
            try:
                b = BPF(text=text, cflags=["-DKEXDR_KAPPA"])
                kappa_mode = True
                print(f"{C.WARNING}Continuing with active-open binding only.{C.ENDC}")
            except Exception as e:
                print(f"{C.WARNING}Socket-scoped binding did not compile: {e}{C.ENDC}")
                print(f"{C.WARNING}Falling back to kappa5 only. Requires kernel >= 5.8 "
                      f"with BTF and bpf_sk_storage support.{C.ENDC}")
    if b is None:
        b = BPF(text=text)

    attached_cgroup = []
    try:
        # --- execution, memory, filesystem, lifecycle ---
        tps = [
            ("syscalls:sys_enter_execve", "trace_exec_syscall"),
            ("syscalls:sys_enter_openat", "trace_openat_syscall"),
            ("syscalls:sys_enter_connect", "trace_connect_syscall"),
            ("syscalls:sys_enter_memfd_create", "trace_memfd_create_syscall"),
            ("syscalls:sys_enter_ptrace", "trace_ptrace_syscall"),
            ("syscalls:sys_enter_unlinkat", "trace_unlinkat_syscall"),
            ("syscalls:sys_enter_setuid", "trace_setuid_syscall"),
            ("syscalls:sys_enter_mmap", "trace_mmap_syscall"),
            ("syscalls:sys_exit_mmap", "trace_mmap_exit"),
            ("syscalls:sys_enter_mprotect", "trace_mprotect_syscall"),
            ("sched:sched_process_fork", "trace_fork"),
            ("sched:sched_process_exit", "trace_exit"),
        ]
        for tp, fn in tps:
            try:
                b.attach_tracepoint(tp=tp, fn_name=fn)
            except Exception as e:
                print(f"{C.WARNING}tracepoint {tp} unavailable: {e}{C.ENDC}")

        # NOTE: sys_enter_read / sys_enter_write are deliberately NOT attached.
        # K records which artifact a process opened or removed, never the bytes it
        # moved.  Adding them would put terminal and file content into the log and
        # multiply the collector's overhead.

        # --- socket-scoped ownership ---
        if kappa_mode:
            # KFUNC_PROBE / KRETFUNC_PROBE are attached by BCC when the module loads,
            # so reaching here at all means they took.
            if tracing_legs:
                print(f"{C.OKGREEN}  fentry(tcp_v4_connect/tcp_v6_connect) attached "
                      f"(active opens){C.ENDC}")
                print(f"{C.OKGREEN}  fexit(inet_csk_accept) attached (passive opens){C.ENDC}")
                print(f"{C.OKGREEN}  fentry(udp_sendmsg) attached (connected UDP / DNS){C.ENDC}")
            else:
                print(f"{C.WARNING}  passive opens and connected UDP will report "
                      f"degraded attribution{C.ENDC}")
            try:
                attached_cgroup = attach_cgroup_programs(b, args.cgroup)
            except Exception as e:
                kappa_mode = False
                print(f"{C.FAIL}cgroup attach failed: {e}{C.ENDC}")
                print(f"{C.WARNING}Running with kappa5 only: every network record will be "
                      f"tagged '{ATTR_DEGRADED}'.{C.ENDC}")

        load_jit_baseline(b)

        # Latch our own <TGID, start_boottime> in kernel.
        try:
            sentinel = "/proc/self/cmdline"
            with open(sentinel, "rb"):
                pass
        except Exception:
            pass

        # --- degraded leg: off-socket collector for traffic with no owning socket ---
        sock_fn = None
        if not args.no_degraded_leg:
            sock_fn = b.load_func("socket_filter", BPF.SOCKET_FILTER)
            ifaces = [args.iface] if args.iface else \
                     [n for _, n in socket.if_nameindex()]
            for iface in ifaces:
                try:
                    BPF.attach_raw_socket(sock_fn, iface)
                    attached_interfaces.add(iface)
                except Exception:
                    pass
            print(f"{C.OKCYAN}  degraded leg on {len(attached_interfaces)} interface(s){C.ENDC}")

        def lost_bulk(count):
            STATS["lost_bulk"] += count

        def lost_prio(count):
            # Should stay at zero: execve/connect/mmap ride the reserved ring.
            STATS["lost_prio"] += count
            print(f"{C.FAIL}[!] reserved ring lost {count} records{C.ENDC}")

        b["prio_events"].open_perf_buffer(handle_syscall_event, page_cnt=256, lost_cb=lost_prio)
        b["syscall_events"].open_perf_buffer(handle_syscall_event, page_cnt=128, lost_cb=lost_bulk)
        b["network_events"].open_perf_buffer(handle_network_event, page_cnt=256, lost_cb=lost_bulk)

        if kappa_mode and tracing_legs:
            mode = f"{C.OKGREEN}EXACT (kappa){C.ENDC}"
        elif kappa_mode:
            mode = (f"{C.WARNING}PARTIAL (kappa on active opens; passive TCP and "
                    f"connected UDP degraded){C.ENDC}")
        else:
            mode = f"{C.WARNING}DEGRADED (kappa5 only){C.ENDC}"
        print(f"\n{C.OKGREEN}Monitoring active. Attribution mode: {mode}\n{C.ENDC}")

        # Interface tracker: 2 s enumerate-and-diff, no orchestrator API.
        # The attach blind spot is bounded by this interval, and we measure it rather
        # than assume it.
        def auto_discover():
            while True:
                time.sleep(args.scan_interval)
                if sock_fn is None:
                    continue
                try:
                    current = {n for _, n in socket.if_nameindex()}
                    for iface in current - attached_interfaces:
                        if iface == "lo":
                            continue
                        t0 = time.time()
                        try:
                            BPF.attach_raw_socket(sock_fn, iface)
                            attached_interfaces.add(iface)
                            attach_latencies.append(time.time() - t0)
                            print(f"{C.OKGREEN}[auto-discovery] attached {iface}{C.ENDC}")
                        except Exception:
                            pass
                except Exception:
                    pass

        threading.Thread(target=auto_discover, daemon=True).start()

        last_stats = time.time()
        while True:
            try:
                b.perf_buffer_poll(timeout=50)
                if args.stats_interval and (time.time() - last_stats) > args.stats_interval:
                    last_stats = time.time()
                    # degraded_dup is excluded by construction: those packets were
                    # already attributed exactly on the cgroup leg.
                    tot = STATS["exact"] + STATS["degraded"]
                    share = (100.0 * STATS["exact"] / tot) if tot else 0.0
                    print(f"{C.DIM}[stats] syscall={STATS['syscall_events']} "
                          f"net={STATS['network_events']} "
                          f"exact={STATS['exact']} ({share:.1f}%) "
                          f"degraded={STATS['degraded']} "
                          f"dup_dropped={STATS['degraded_dup']} "
                          f"l7_unresolved={STATS['l7_unresolved']} "
                          f"lost_bulk={STATS['lost_bulk']} lost_prio={STATS['lost_prio']}"
                          f"{C.ENDC}")
            except KeyboardInterrupt:
                break
    except Exception as e:
        print(f"\n{C.FAIL}Error: {e}{C.ENDC}")
        traceback.print_exc()
    finally:
        for fn, fd, atype in attached_cgroup:
            try:
                b.detach_func(fn, fd, atype)
            except Exception:
                pass
        if attach_latencies:
            print(f"{C.DIM}mean interface attach latency: "
                  f"{sum(attach_latencies) / len(attach_latencies):.2f}s{C.ENDC}")
        if CURRENT_LOG_HANDLE:
            try:
                CURRENT_LOG_HANDLE.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
