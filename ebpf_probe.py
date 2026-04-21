#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Full-Kernelspace eBPF Auditing System
# (Docker-Aware Edition with Cgroup ID Tracking & Auto-Discovery)
#
# ======================================================================================
# 1.  🐳 CONTAINER AWARE   : Tracks Cgroup ID to distinguish Docker vs Host processes.
# 2.  🚀 PROCESS EXECUTION : Real-time capture of 'execve' (CMD + Arguments).
# 3.  📁 FILE MONITORING   : Tracks file opening ('openat') and reading/writing.
# 4.  🔌 NETWORK AUDITING  : L3/L4 headers + L7 Payload (HTTP, DNS, MySQL, etc.).
# 5.  👻 FILELESS MALWARE  : Detects memory-only file creation ('memfd_create').
# 6.  💉 CODE INJECTION    : Detects dynamic process debugging/injection ('ptrace').
# 7.  🗑️  ANTI-FORENSICS   : Monitors file deletion attempts ('unlinkat').
# 8.  ⚠️  PRIVILEGE ESCALATION: Alerts on user ID changes/setuid calls ('setuid').
# 9.  🛡️  SMART FILTERING   : Automatically filters out its own PID.
# 10. 💾 LOG ROTATION      : Auto-creates "YYYY-MM-DD/audit_HH.json" logs.
# 11. 🔄 AUTO DISCOVERY    : Automatically attaches to new Docker interfaces (veth/docker0).
# ======================================================================================

import argparse
import ctypes as ct
from bcc import BPF
from datetime import datetime, timezone
import socket
import struct
import sys
import traceback
import os
import re
import time
import resource
import json
import threading  # <--- NEW: For background interface scanning

# ============================================================================
# Global Logging State
# ============================================================================
LOG_BASE_DIR = None
CURRENT_LOG_HANDLE = None
CURRENT_FILE_PATH = None


# ============================================================================
# UI Colors
# ============================================================================
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
    C_READ = '\033[96m'
    C_WRIT = '\033[94m'
    C_NET = '\033[96m\033[1m'
    C_MEMFD = '\033[91m\033[1m'
    C_INJECT = '\033[35m\033[1m'
    C_DEL = '\033[41m\033[37m'
    C_PRIV = '\033[43m\033[30m'


# ============================================================================
# C BPF Program
# ============================================================================
bpf_text_template = r"""
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <linux/compat.h>
#include <linux/binfmts.h>

// PID to filter (Injected by Python)
#define FILTER_PID YOUR_PID_GOES_HERE

#define TASK_COMM_LEN 16
#define DATA_BUF_LEN_MAX 256 
#define MAX_ARGS 6
#define ARG_LEN 32
#define MAX_PAYLOAD_CAP 1024 

struct exec_data_t { char filename[64]; char args[MAX_ARGS][ARG_LEN]; };
struct connect_data_t { u32 daddr; u16 dport; u16 pad; char _pad[DATA_BUF_LEN_MAX - 8]; };
struct open_data_t { char filename[DATA_BUF_LEN_MAX]; };
struct write_data_t { char buf[DATA_BUF_LEN_MAX]; };
struct unlink_data_t { char filename[DATA_BUF_LEN_MAX]; };
struct setuid_data_t { u32 target_uid; };
struct mmap_data_t {
    u64 addr;
    u64 len;
    u32 prot;
    u32 flags;
};

// --- Struct Updated with Cgroup ID ---
struct __attribute__((packed)) syscall_event_t {
    u64 pid; 
    u64 ppid; 
    u64 cgroup_id;     // <--- NEW: Unique Container ID
    u32 uid; 
    char comm[TASK_COMM_LEN];
    u32 event_type; 
    u32 arg_count;
    union {
        struct exec_data_t exec; 
        struct connect_data_t connect;
        struct open_data_t open; 
        struct write_data_t write_evt;
        struct unlink_data_t unlink;
        struct setuid_data_t setuid;
        struct mmap_data_t mmap_evt;
    } data;
};

struct read_args_t { int fd; const char *buf; };

BPF_PERF_OUTPUT(syscall_events);
BPF_PERCPU_ARRAY(syscall_buffer, struct syscall_event_t, 1);
BPF_HASH(read_tracing, u64, struct read_args_t);

static inline void fill_header(struct syscall_event_t *event) {
    u64 id_pid = bpf_get_current_pid_tgid();
    u64 id_uid_gid = bpf_get_current_uid_gid();
    event->pid = id_pid >> 32;
    event->uid = id_uid_gid & 0xFFFFFFFF;

    // --- Get Cgroup ID ---
    event->cgroup_id = bpf_get_current_cgroup_id(); 

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = 0;
    struct task_struct *parent_task = NULL;
    bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &task->parent);
    if (parent_task) {
        pid_t parent_tgid = 0;
        bpf_probe_read_kernel(&parent_tgid, sizeof(parent_tgid), &parent_task->tgid);
        event->ppid = (u64)parent_tgid;
    }
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

int trace_exec_syscall(struct tracepoint__syscalls__sys_enter_execve *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); event->event_type = 0; fill_header(event);
    bpf_probe_read_user_str(&event->data.exec.filename, sizeof(event->data.exec.filename), (void *)ctx->filename);
    const char __user *const __user *argp = ctx->argv; const char __user *arg = NULL;
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        if (bpf_probe_read_user(&arg, sizeof(arg), &argp[i]) != 0) break;
        if (!arg) break;
        bpf_probe_read_user_str(event->data.exec.args[i], ARG_LEN, arg);
        event->arg_count++;
    }
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_openat_syscall(struct tracepoint__syscalls__sys_enter_openat *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); event->event_type = 1; fill_header(event);
    bpf_probe_read_user_str(&event->data.open.filename, sizeof(event->data.open.filename), (const char __user *)ctx->filename);
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_connect_syscall(struct tracepoint__syscalls__sys_enter_connect *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    const struct sockaddr __user *uaddr = (const struct sockaddr __user *)ctx->uservaddr;
    if (!uaddr) return 0;
    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); event->event_type = 2; fill_header(event);
    struct sockaddr_in addr4 = {}; bpf_probe_read_user(&addr4, sizeof(addr4), uaddr);
    if (addr4.sin_family == AF_INET) {
        event->data.connect.daddr = addr4.sin_addr.s_addr;
        event->data.connect.dport = bpf_ntohs(addr4.sin_port);
        syscall_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

int trace_write_syscall(struct tracepoint__syscalls__sys_enter_write *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0; 

    int fd = (int)ctx->fd; if (fd != 1 && fd != 2) return 0; 
    const char __user *buf = (const char __user *)ctx->buf; size_t count = (size_t)ctx->count;
    if (!buf || count == 0) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); event->event_type = 3; fill_header(event);
    int read_size = (int)count < (int)sizeof(event->data.write_evt.buf) ? (int)count : (int)sizeof(event->data.write_evt.buf) - 1;
    if (read_size > 0) {
        bpf_probe_read_user_str(&event->data.write_evt.buf, read_size + 1, buf);
        syscall_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

int trace_read_enter(struct tracepoint__syscalls__sys_enter_read *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    if (pid == FILTER_PID) return 0;

    if (ctx->fd != 0) return 0; 
    struct read_args_t args = {}; args.fd = (int)ctx->fd; args.buf = (const char *)ctx->buf;
    read_tracing.update(&pid_tgid, &args);
    return 0;
}

int trace_read_exit(struct tracepoint__syscalls__sys_exit_read *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args_t *args = read_tracing.lookup(&pid_tgid);
    if (!args) return 0;

    long ret = ctx->ret;
    if (ret <= 0) { read_tracing.delete(&pid_tgid); return 0; }
    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) { read_tracing.delete(&pid_tgid); return 0; }
    __builtin_memset(event, 0, sizeof(*event)); event->event_type = 4; fill_header(event);
    int read_size = (int)ret < (int)sizeof(event->data.write_evt.buf) ? (int)ret : (int)sizeof(event->data.write_evt.buf) - 1;
    if (read_size > 0) {
        bpf_probe_read_user_str(&event->data.write_evt.buf, read_size + 1, args->buf);
        syscall_events.perf_submit(ctx, event, sizeof(*event));
    }
    read_tracing.delete(&pid_tgid);
    return 0;
}

int trace_memfd_create_syscall(struct tracepoint__syscalls__sys_enter_memfd_create *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); event->event_type = 5; fill_header(event);
    bpf_probe_read_user_str(&event->data.open.filename, sizeof(event->data.open.filename), (const char __user *)ctx->uname);
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_ptrace_syscall(struct tracepoint__syscalls__sys_enter_ptrace *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); 
    event->event_type = 6; 
    fill_header(event);

    u64 raw_data[2];
    raw_data[0] = (u64)ctx->request;
    raw_data[1] = (u64)ctx->pid;
    bpf_probe_read_kernel(event->data.open.filename, sizeof(raw_data), raw_data);

    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_unlinkat_syscall(struct tracepoint__syscalls__sys_enter_unlinkat *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); 
    event->event_type = 7; 
    fill_header(event);

    bpf_probe_read_user_str(&event->data.unlink.filename, sizeof(event->data.unlink.filename), (const char __user *)ctx->pathname);
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_setuid_syscall(struct tracepoint__syscalls__sys_enter_setuid *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event)); 
    event->event_type = 8; 
    fill_header(event);

    event->data.setuid.target_uid = (u32)ctx->uid;
    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int trace_mmap_syscall(struct tracepoint__syscalls__sys_enter_mmap *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u32 key = 0; struct syscall_event_t *event = syscall_buffer.lookup(&key);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = 9; // 定义 9 为 MMAP
    fill_header(event);

    event->data.mmap_evt.addr = (u64)ctx->addr;
    event->data.mmap_evt.len = (u64)ctx->len;
    event->data.mmap_evt.prot = (u32)ctx->prot;
    event->data.mmap_evt.flags = (u32)ctx->flags;

    syscall_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}


#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/in.h>
#include <linux/filter.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

struct __attribute__((packed)) network_event_t {
    u64 timestamp; u32 src_ip; u32 dst_ip; u16 src_port; u16 dst_port;
    u8 protocol; u8 app_protocol; u16 payload_len; u8 ip_ttl; u8 ip_tos; u8 tcp_flags; u16 tcp_window; u32 tcp_seq; u32 tcp_ack;
    u8 raw_payload[MAX_PAYLOAD_CAP];
};

BPF_PERF_OUTPUT(network_events);
BPF_PERCPU_ARRAY(network_buffer, struct network_event_t, 1);

static __always_inline u8 detect_http_sk(struct __sk_buff *skb, u32 offset) {
    u8 buf[4] = {}; if (bpf_skb_load_bytes(skb, offset, buf, 4) < 0) return 0;
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') return 1;
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S') return 1;
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T') return 1;
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L') return 1; 
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T') return 1; 
    return 0;
}
static __always_inline u8 detect_tls_sk(struct __sk_buff *skb, u32 offset) {
    u8 buf[3] = {}; if (bpf_skb_load_bytes(skb, offset, buf, 3) < 0) return 0;
    if (buf[0] == 22 && buf[1] == 3) return 1; return 0;
}
static __always_inline u8 detect_ssh_sk(struct __sk_buff *skb, u32 offset) {
    u8 buf[4] = {}; if (bpf_skb_load_bytes(skb, offset, buf, 4) < 0) return 0;
    if (buf[0] == 'S' && buf[1] == 'S' && buf[2] == 'H') return 1;
    return 0;
}

int socket_filter(struct __sk_buff *skb) {
    u32 zero = 0; struct network_event_t *event = network_buffer.lookup(&zero);
    if (!event) return 0;

    event->payload_len = 0; event->app_protocol = 0; 
    event->tcp_flags = 0; event->tcp_seq = 0; event->tcp_ack = 0;

    u32 nhoff = 0xFFFFFFFF; 
    u8 ip_ver_byte = 0;

    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 14, &ip_ver_byte, 1); if ((ip_ver_byte >> 4) == 4) nhoff = 14; }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 16, &ip_ver_byte, 1); if ((ip_ver_byte >> 4) == 4) nhoff = 16; }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 0,  &ip_ver_byte, 1); if ((ip_ver_byte >> 4) == 4) nhoff = 0; }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 4,  &ip_ver_byte, 1); if ((ip_ver_byte >> 4) == 4) nhoff = 4; }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 2,  &ip_ver_byte, 1); if ((ip_ver_byte >> 4) == 4) nhoff = 2; }
    if (nhoff == 0xFFFFFFFF) { bpf_skb_load_bytes(skb, 18, &ip_ver_byte, 1); if ((ip_ver_byte >> 4) == 4) nhoff = 18; }

    if (nhoff == 0xFFFFFFFF) {
        event->app_protocol = 255; 
        bpf_skb_load_bytes(skb, 0, event->raw_payload, 16); 
        network_events.perf_submit(skb, event, sizeof(*event));
        return 0;
    }

    u8 verlen = 0; bpf_skb_load_bytes(skb, nhoff, &verlen, 1); 
    u8 ihl = (verlen & 0x0F) * 4;
    u8 ip_proto = 0; bpf_skb_load_bytes(skb, nhoff + 9, &ip_proto, 1);

    bpf_skb_load_bytes(skb, nhoff + 12, &event->src_ip, 4); 
    bpf_skb_load_bytes(skb, nhoff + 16, &event->dst_ip, 4);
    event->timestamp = bpf_ktime_get_ns(); 
    event->protocol = ip_proto;

    u16 total_len = 0; 
    bpf_skb_load_bytes(skb, nhoff + 2, &total_len, 2); 
    total_len = bpf_ntohs(total_len);

    u32 l4_off = nhoff + ihl; 
    u32 payload_off = 0; 
    u32 payload_len = 0;

    if (ip_proto == IPPROTO_TCP) {
        u16 src = 0, dst = 0; 
        bpf_skb_load_bytes(skb, l4_off, &src, 2); bpf_skb_load_bytes(skb, l4_off + 2, &dst, 2);
        event->src_port = bpf_ntohs(src); event->dst_port = bpf_ntohs(dst);

        u8 doff_flags = 0; 
        bpf_skb_load_bytes(skb, l4_off + 12, &doff_flags, 1); 
        u8 doff = (doff_flags >> 4) * 4;
        bpf_skb_load_bytes(skb, l4_off + 13, &event->tcp_flags, 1);

        payload_off = l4_off + doff; 
        if (total_len > (ihl + doff)) payload_len = total_len - ihl - doff;

        if (payload_len > 0) {
            if (detect_http_sk(skb, payload_off)) event->app_protocol = 1;
            else if (detect_tls_sk(skb, payload_off)) event->app_protocol = 14;
            else if (detect_ssh_sk(skb, payload_off)) event->app_protocol = 3;
        }
    } 
    else if (ip_proto == IPPROTO_UDP) {
        u16 src = 0, dst = 0; 
        bpf_skb_load_bytes(skb, l4_off, &src, 2); bpf_skb_load_bytes(skb, l4_off + 2, &dst, 2);
        event->src_port = bpf_ntohs(src); event->dst_port = bpf_ntohs(dst);
        payload_off = l4_off + 8; 
        if (total_len > (ihl + 8)) payload_len = total_len - ihl - 8;
        if (payload_len > 0 && (event->dst_port == 53 || event->src_port == 53)) event->app_protocol = 7;
    } 
    else if (ip_proto == IPPROTO_ICMP) {
        event->app_protocol = 13; payload_off = l4_off;
        if (total_len > ihl) payload_len = total_len - ihl;
    }

    event->payload_len = payload_len;

    if (payload_len > 0) {
        u32 cap = payload_len > MAX_PAYLOAD_CAP ? MAX_PAYLOAD_CAP : payload_len;
        bpf_skb_load_bytes(skb, payload_off, event->raw_payload, cap);
    }

    if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP || ip_proto == IPPROTO_ICMP) {
        network_events.perf_submit(skb, event, sizeof(*event));
    }
    return 0;
}
"""


# ============================================================================
# Python Userspace Code
# ============================================================================
# [2.1] 新增 MmapData 结构体映射
class MmapData(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("addr", ct.c_uint64),
        ("len", ct.c_uint64),
        ("prot", ct.c_uint32),
        ("flags", ct.c_uint32)
    ]


class SyscallEvent(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("pid", ct.c_uint64),
        ("ppid", ct.c_uint64),
        ("cgroup_id", ct.c_uint64),  # <--- NEW FIELD
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("event_type", ct.c_uint32),
        ("arg_count", ct.c_uint32),
        ("data", ct.c_ubyte * 256)
    ]


class NetworkEvent(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("src_ip", ct.c_uint32), ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16), ("dst_port", ct.c_uint16),
        ("protocol", ct.c_uint8), ("app_protocol", ct.c_uint8), ("payload_len", ct.c_uint16),
        ("ip_ttl", ct.c_uint8), ("ip_tos", ct.c_uint8),
        ("tcp_flags", ct.c_uint8), ("tcp_window", ct.c_uint16), ("tcp_seq", ct.c_uint32), ("tcp_ack", ct.c_uint32),
        ("raw_payload", ct.c_ubyte * 1024),
    ]


PROTO_NAMES = {
    0: "UNKNOWN", 1: "HTTP", 2: "HTTPS", 3: "SSH", 4: "FTP",
    5: "Telnet", 6: "SMB", 7: "DNS", 8: "MySQL", 9: "PostgreSQL",
    10: "Redis", 11: "LDAP", 12: "SNMP", 13: "ICMP", 14: "TLS",
    255: "DEBUG_RAW"
}

PORT_MAP = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 8080: "HTTP", 443: "HTTPS", 8443: "HTTPS",
    110: "POP3", 995: "POP3", 139: "NetBIOS", 445: "SMB",
    143: "IMAP", 993: "IMAP", 161: "SNMP", 389: "LDAP", 636: "LDAP",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
}

FLUSH_INTERVAL = 0.15
MAX_BUFFER_SIZE = 4096
event_buffers = {}
seen_flows = {}
SHELL_NAMES = {'bash', 'sh', 'zsh', 'dash', 'fish'}
prompt_pattern = re.compile(r'.*@.*[:].*[#$]\s*$')
ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]|\x1B]0;.*?\x07')

# Tracks currently attached network interfaces to avoid duplicates
attached_interfaces = set()


def strip_ansi(text):
    return ansi_escape.sub('', text).replace('\x07', '')


def int_to_ip(addr_int):
    try:
        return socket.inet_ntoa(struct.pack("=I", addr_int))
    except:
        return "0.0.0.0"


def extract_cstr(buf, maxlen):
    s = bytes(buf[:maxlen]).split(b'\x00', 1)[0]
    try:
        return s.decode('utf-8', 'replace')
    except:
        return repr(s)


def decode_tcp_flags(flags):
    res = []
    if flags & 0x80: res.append("CWR")
    if flags & 0x40: res.append("ECE")
    if flags & 0x20: res.append("URG")
    if flags & 0x10: res.append("ACK")
    if flags & 0x08: res.append("PSH")
    if flags & 0x04: res.append("RST")
    if flags & 0x02: res.append("SYN")
    if flags & 0x01: res.append("FIN")
    return "[" + ", ".join(res) + "]" if res else "[NONE]"


# ============================================================================
# Dynamic JSON Logging (Rotated by Day/Hour)
# ============================================================================
def get_log_file_handle():
    global LOG_BASE_DIR, CURRENT_LOG_HANDLE, CURRENT_FILE_PATH

    if not LOG_BASE_DIR:
        return None

    now = datetime.now()
    # 1. Folder: logs/YYYY-MM-DD
    date_str = now.strftime("%Y-%m-%d")
    day_dir = os.path.join(LOG_BASE_DIR, date_str)

    # 2. File: audit_HH.json
    hour_str = now.strftime("%H")
    filename = f"audit_{hour_str}.json"
    full_path = os.path.join(day_dir, filename)

    # 3. Rotate if path changed
    if full_path != CURRENT_FILE_PATH:
        # Close old
        if CURRENT_LOG_HANDLE:
            try:
                CURRENT_LOG_HANDLE.close()
            except:
                pass
            CURRENT_LOG_HANDLE = None

        # Create dir
        if not os.path.exists(day_dir):
            try:
                os.makedirs(day_dir, exist_ok=True)
            except Exception as e:
                print(f"{C.FAIL}❌ Failed to create log dir: {e}{C.ENDC}")
                return None

        # Open new
        try:
            CURRENT_LOG_HANDLE = open(full_path, 'a', encoding='utf-8')
            CURRENT_FILE_PATH = full_path
            print(f"{C.OKCYAN}💾 Log rotated: {full_path}{C.ENDC}")
        except Exception as e:
            print(f"{C.FAIL}❌ Failed to open log file: {e}{C.ENDC}")
            return None

    return CURRENT_LOG_HANDLE


def log_json_event(data):
    """Writes a structured dict event to the rotated JSON log file."""
    handle = get_log_file_handle()
    if handle:
        try:
            if 'timestamp' not in data:
                # Use timezone-aware UTC time
                data['timestamp'] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            json.dump(data, handle)
            handle.write('\n')
            handle.flush()
        except Exception as e:
            pass


def flush_buffer(pid, force=False):
    if pid not in event_buffers: return
    entry = event_buffers[pid]
    now = time.time()

    if force or (now - entry['ts'] > FLUSH_INTERVAL) or (len(entry['data']) > MAX_BUFFER_SIZE):
        content = strip_ansi(entry['data']).strip()
        is_shell_output = (entry['type'] == "WRIT") and (entry['comm'] in SHELL_NAMES)
        is_prompt = prompt_pattern.match(content) or (content.endswith('#') and '@' in content)

        if content and not (is_shell_output and is_prompt):
            ts_str = datetime.now().strftime("%H:%M:%S")
            color = C.C_READ if entry['type'] == "READ" else C.C_WRIT
            icon = "📖" if entry['type'] == "READ" else "✍️ "

            uid = entry.get('uid', 0)
            ppid = entry.get('ppid', 0)
            cg = entry.get('cgroup_id', 0)
            comm = entry['comm']

            header = format_header(ts_str, entry['type'], color, pid, uid, ppid, cg, comm)
            lines = content.split('\n')
            if len(lines) == 1:
                print(f"{header} {icon} {lines[0]}")
            else:
                print(f"{header} {icon} {lines[0]}")
                for line in lines[1:]:
                    if len(line) > 120: line = line[:120] + "..."
                    if line.strip(): print(f"{' ' * 62} {C.DIM}│{C.ENDC} {line}")

            # --- LOG TO JSON ---
            log_json_event({
                "type": "SYSCALL",
                "subtype": entry['type'],
                "pid": pid,
                "uid": uid,
                "ppid": ppid,
                "cgroup_id": cg,
                "comm": comm,
                "data": content
            })

        del event_buffers[pid]


def format_header(ts, tag, color, pid, uid, ppid, cg, comm):
    # Added CG (Cgroup ID) column
    return f"{C.DIM}[{ts}]{C.ENDC} {color}[ {tag:<4} ]{C.ENDC} {C.DIM}UID:{uid:<5} PID:{pid:<6} PPID:{ppid:<6} CG:{cg:<8} {comm:<16}{C.ENDC}"


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


def handle_network_event(cpu, data, size):
    try:
        ev = ct.cast(data, ct.POINTER(NetworkEvent)).contents
        ts = datetime.now().strftime("%H:%M:%S")
        now = time.time()

        if ev.app_protocol == 255:
            # RAW Unknown
            return

        src = f"{int_to_ip(ev.src_ip)}:{ev.src_port}"
        dst = f"{int_to_ip(ev.dst_ip)}:{ev.dst_port}"
        flow_key = (ev.src_ip, ev.src_port, ev.dst_ip, ev.dst_port, ev.protocol)

        payload = bytes(ev.raw_payload)[:min(ev.payload_len, 1024)]
        proto_id = ev.app_protocol
        proto_name = PROTO_NAMES.get(proto_id, "UNKNOWN")
        l7_info = None

        if len(payload) > 0:
            if proto_id == 1:
                l7_info = parse_http_details(payload)
            elif proto_id == 14:
                l7_info = parse_tls_details(payload)
                if l7_info: proto_name = "TLS"
            elif proto_id == 7:
                l7_info = parse_dns_details(payload)
            elif proto_id == 3:
                if payload.startswith(b'SSH-'):
                    banner = payload.split(b'\r\n')[0].decode('utf-8', 'ignore')
                    l7_info = f"SSH Banner: {banner}"
            elif proto_id == 13:
                l7_info = parse_icmp_details(ev, payload)

        if proto_name == "UNKNOWN":
            if parse_smb_details(payload):
                proto_name, l7_info = "SMB", parse_smb_details(payload)
            elif ev.dst_port == 3306 or ev.src_port == 3306:
                if parse_mysql_details(payload): proto_name, l7_info = "MySQL", parse_mysql_details(payload)
            elif ev.dst_port == 6379 or ev.src_port == 6379:
                if parse_redis_details(payload): proto_name, l7_info = "Redis", parse_redis_details(payload)
            elif ev.dst_port == 5432 or ev.src_port == 5432:
                if parse_pgsql_details(payload): proto_name, l7_info = "PostgreSQL", parse_pgsql_details(payload)
            elif ev.dst_port == 21 or ev.src_port == 21:
                if parse_ftp_details(payload): proto_name, l7_info = "FTP", parse_ftp_details(payload)
            elif ev.dst_port == 23 or ev.src_port == 23:
                l7_info = f"Telnet Data: {payload.decode('utf-8', 'ignore').strip()}"
                proto_name = "Telnet"
            elif ev.dst_port == 389 or ev.src_port == 389:
                if parse_ldap_details(payload): proto_name, l7_info = "LDAP", parse_ldap_details(payload)
            elif ev.protocol == 1:
                proto_name, l7_info = "ICMP", parse_icmp_details(ev, payload)

            if proto_name == "UNKNOWN":
                if ev.dst_port in PORT_MAP:
                    proto_name = PORT_MAP[ev.dst_port] + "?"
                elif ev.src_port in PORT_MAP:
                    proto_name = PORT_MAP[ev.src_port] + "?"
                elif ev.protocol == 6:
                    proto_name = "TCP"
                elif ev.protocol == 17:
                    proto_name = "UDP"

                if not l7_info:
                    l7_info = parse_generic_text(payload)

        # Logging / Printing Logic
        should_print = l7_info is not None or (flow_key not in seen_flows or (now - seen_flows[flow_key] > 5))

        if should_print:
            seen_flows[flow_key] = now
            print(f"{C.DIM}────────────────────────────────────────────────────────────────────────────────{C.ENDC}")
            print(f"{C.C_NET}[ NET  ] {src} ──> {dst} ({proto_name}){C.ENDC}")
            if ev.protocol == 6:
                print(f"         {C.DIM}Flags: {decode_tcp_flags(ev.tcp_flags)}{C.ENDC}")
            if l7_info:
                for line in l7_info.split('\n'):
                    print(f"         {C.DIM}└─{C.ENDC} {line}")

            # --- LOG TO JSON ---
            try:
                # Decoded payload for JSON (strip Ansi colors if they leaked in parsers)
                json_payload_str = strip_ansi(l7_info) if l7_info else ""
                log_json_event({
                    "type": "NETWORK",
                    "subtype": proto_name,
                    "src_ip": int_to_ip(ev.src_ip),
                    "src_port": ev.src_port,
                    "dst_ip": int_to_ip(ev.dst_ip),
                    "dst_port": ev.dst_port,
                    "proto_id": ev.protocol,
                    "payload_info": json_payload_str
                })
            except:
                pass

        if len(seen_flows) > 2000: seen_flows.clear()
    except Exception:
        pass


def handle_syscall_event(cpu, data, size):
    try:
        ev = ct.cast(data, ct.POINTER(SyscallEvent)).contents
        ts_str = datetime.now().strftime("%H:%M:%S")
        comm = ev.comm.decode('utf-8', 'replace').rstrip('\x00')

        if ev.event_type == 0:  # EXEC
            filename = extract_cstr(ev.data, 64)
            args = [filename]
            for i in range(1, min(ev.arg_count, 6)):
                arg_start = 64 + (i * 32)
                arg = extract_cstr(ev.data[arg_start:arg_start + 32], 32)
                if arg: args.append(arg)
            flush_buffer(ev.pid, force=True)

            cmd = args[0]
            arguments = " ".join(args[1:])
            header = format_header(ts_str, "EXEC", C.C_EXEC, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)
            print(f"{header} 🚀 {C.BOLD}CMD: {cmd} ARG: {arguments}{C.ENDC}")

            log_json_event({
                "type": "SYSCALL",
                "subtype": "EXEC",
                "pid": ev.pid,
                "uid": ev.uid,
                "ppid": ev.ppid,
                "cgroup_id": ev.cgroup_id,
                "comm": comm,
                "cmd": cmd,
                "args": arguments
            })

        elif ev.event_type == 1:  # OPEN
            fname = extract_cstr(ev.data, 256)
            if fname and not fname.startswith(('/proc', '/sys', '/dev', '/lib', '/usr')):
                header = format_header(ts_str, "OPEN", C.C_OPEN, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)
                print(f"{header} 📁 {fname}")
                log_json_event({
                    "type": "SYSCALL",
                    "subtype": "OPEN",
                    "pid": ev.pid,
                    "uid": ev.uid,
                    "ppid": ev.ppid,
                    "cgroup_id": ev.cgroup_id,
                    "comm": comm,
                    "filename": fname
                })

        elif ev.event_type == 2:  # CONNECT
            daddr = int_to_ip(int.from_bytes(bytes(ev.data[0:4]), 'little'))
            dport = int.from_bytes(bytes(ev.data[4:6]), 'little')
            if dport != 0:
                flush_buffer(ev.pid, force=True)
                header = format_header(ts_str, "CONN", C.C_CONN, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)
                print(f"{header} 🔌 -> {daddr}:{dport}")
                log_json_event({
                    "type": "SYSCALL",
                    "subtype": "CONNECT",
                    "pid": ev.pid,
                    "uid": ev.uid,
                    "ppid": ev.ppid,
                    "cgroup_id": ev.cgroup_id,
                    "comm": comm,
                    "dst_ip": daddr,
                    "dst_port": dport
                })

        elif ev.event_type == 3 or ev.event_type == 4:  # WRITE / READ
            is_read = (ev.event_type == 4)
            raw = extract_cstr(ev.data, 256)

            if ev.pid not in event_buffers:
                event_buffers[ev.pid] = {
                    'data': "",
                    'ts': time.time(),
                    'comm': comm,
                    'type': "READ" if is_read else "WRIT",
                    'uid': ev.uid,
                    'ppid': ev.ppid,
                    'cgroup_id': ev.cgroup_id
                }

            current_type = "READ" if is_read else "WRIT"
            if event_buffers[ev.pid]['type'] != current_type:
                flush_buffer(ev.pid, force=True)
                event_buffers[ev.pid] = {
                    'data': "",
                    'ts': time.time(),
                    'comm': comm,
                    'type': current_type,
                    'uid': ev.uid,
                    'ppid': ev.ppid,
                    'cgroup_id': ev.cgroup_id
                }

            event_buffers[ev.pid]['data'] += raw
            event_buffers[ev.pid]['ts'] = time.time()

            if is_read and ('\r' in raw or '\n' in raw):
                flush_buffer(ev.pid, force=True)
            elif ev.pid in event_buffers and len(event_buffers[ev.pid]['data']) > MAX_BUFFER_SIZE:
                flush_buffer(ev.pid, force=True)

        elif ev.event_type == 5:  # MEMFD (Fileless Malware Detection)
            name = extract_cstr(ev.data, 256)
            header = format_header(ts_str, "MEMFD", C.C_MEMFD, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)
            print(f"{header} 👻 Fileless Storage: {name}")
            log_json_event({
                "type": "SYSCALL",
                "subtype": "MEMFD",
                "pid": ev.pid,
                "uid": ev.uid,
                "ppid": ev.ppid,
                "cgroup_id": ev.cgroup_id,
                "comm": comm,
                "name": name
            })

        elif ev.event_type == 6:  # INJECT (Ptrace Monitoring)
            raw_data = bytes(ev.data)[:16]
            req_code = 0
            target_pid = 0
            if len(raw_data) >= 16:
                try:
                    req_code, target_pid = struct.unpack("QQ", raw_data)
                except:
                    pass

            header = format_header(ts_str, "INJECT", C.C_INJECT, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)

            # Map req_code to name...
            req_name = f"PTRACE_CMD_{req_code}"
            # [FIX] 增加对 TRACEME 的解析
            if req_code == 0:
                req_name = "PTRACE_TRACEME"
                target_pid = ev.ppid  # 对于 TRACEME，目标其实是父进程，或者说自己将自己交给父进程
            if req_code == 1:
                req_name = "PTRACE_PEEKTEXT"
            elif req_code == 4:
                req_name = "PTRACE_POKETEXT"
            elif req_code == 16:
                req_name = "PTRACE_ATTACH"

            print(f"{header} 💉 Code Injection/Debug: {C.BOLD}{req_name}{C.ENDC} on PID {target_pid}")
            log_json_event({
                "type": "SYSCALL",
                "subtype": "INJECT",
                "pid": ev.pid,
                "uid": ev.uid,
                "ppid": ev.ppid,
                "cgroup_id": ev.cgroup_id,
                "comm": comm,
                "request_code": req_code,
                "target_pid": target_pid
            })

        elif ev.event_type == 7:  # DELETE (Unlinkat)
            fname = extract_cstr(ev.data, 256)
            header = format_header(ts_str, "DEL", C.C_DEL, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)
            print(f"{header} 🗑️  {C.BOLD}DELETED FILE:{C.ENDC} {fname}")
            log_json_event({
                "type": "SYSCALL",
                "subtype": "DELETE",
                "pid": ev.pid,
                "uid": ev.uid,
                "ppid": ev.ppid,
                "cgroup_id": ev.cgroup_id,
                "comm": comm,
                "filename": fname
            })

        elif ev.event_type == 8:  # PRIV ESC (Setuid)
            uid_data = bytes(ev.data)[:4]
            target_uid = struct.unpack("I", uid_data)[0]
            header = format_header(ts_str, "PRIV", C.C_PRIV, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)
            print(f"{header} ⚠️  {C.BOLD}PRIVILEGE ESCALATION ATTEMPT:{C.ENDC} Target UID {target_uid}")
            log_json_event({
                "type": "SYSCALL",
                "subtype": "SETUID",
                "pid": ev.pid,
                "uid": ev.uid,
                "ppid": ev.ppid,
                "cgroup_id": ev.cgroup_id,
                "comm": comm,
                "target_uid": target_uid
            })


        elif ev.event_type == 9:  # MMAP 解析 (只审计 EXEC)
            mmap_data = ct.cast(ev.data, ct.POINTER(MmapData)).contents
            prot = mmap_data.prot
            # [关键修改] 核心过滤器：如果权限中不包含 EXEC (0x4)，直接忽略
            # 这将屏蔽掉所有普通的库加载(RX)和文件读写(RW)操作
            if not (prot & 0x4):
                return
            addr = mmap_data.addr
            length = mmap_data.len
            # 解析权限位 (既然能运行到这里，肯定有 EXEC)
            prot_list = ["EXEC"]
            if prot & 0x1: prot_list.insert(0, "READ")
            if prot & 0x2: prot_list.insert(1, "WRITE")  # W+X 是最高危特征
            p_str = "|".join(prot_list)
            # 只有 W+X (可写可执行) 才是真正的红色警报，单纯的 RX (只读执行) 可能是加载代码段
            if (prot & 0x2) and (prot & 0x4):
                color = C.FAIL
                risk_label = f" {C.FAIL}{C.BOLD}[!] SHELLCODE (W+X){C.ENDC}"
            else:
                color = C.OKBLUE  # 或者是 OKGREEN，表示普通的加载可执行代码
                risk_label = " (Executable Code)"
            header = format_header(ts_str, "MMAP", color, ev.pid, ev.uid, ev.ppid, ev.cgroup_id, comm)
            print(f"{header} 🧠 Map: {hex(addr)} Size: {length} Prot: [{p_str}]{risk_label}")
            log_json_event({
                "type": "SYSCALL",
                "subtype": "MMAP",
                "pid": ev.pid,
                "uid": ev.uid,
                "ppid": ev.ppid,
                "cgroup_id": ev.cgroup_id,
                "comm": comm,
                "addr": hex(addr),
                "len": length,
                "prot": p_str,
                "is_exec": True  # 既然记录了，肯定是 True
            })

    except Exception:
        traceback.print_exc()


def main():
    global LOG_BASE_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", default="", help="Interface (Optional: auto-detection enabled)")
    # -o now designates the ROOT FOLDER for logs
    parser.add_argument("-o", "--output", default="", help="Base Directory to save logs (e.g., ./audit_logs)")
    args = parser.parse_args()

    print(f"{C.HEADER}{'=' * 80}{C.ENDC}")
    print(f"{C.HEADER}🔥 (01.17 newset docker) eBPF Auditing (Docker/Cgroup-Aware){C.ENDC}".center(90))
    print(f"{C.DIM}📡 Protocols: HTTP, TLS, SSH... | Auto-Folder: YYYY-MM-DD/audit_HH.json{C.ENDC}".center(90))
    print(f"{C.HEADER}{'=' * 80}{C.ENDC}")

    if args.output:
        LOG_BASE_DIR = args.output
        if not os.path.exists(LOG_BASE_DIR):
            try:
                os.makedirs(LOG_BASE_DIR, exist_ok=True)
                print(f"{C.OKCYAN}📂 Created base log directory: {LOG_BASE_DIR}{C.ENDC}")
            except Exception as e:
                print(f"{C.FAIL}❌ Error creating directory: {e}{C.ENDC}")
                sys.exit(1)
        else:
            print(f"{C.OKCYAN}📂 Logging to base directory: {LOG_BASE_DIR}{C.ENDC}")

    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except:
        pass

    my_pid = os.getpid()
    print(f"{C.OKCYAN}ℹ️  Self-PID: {my_pid} (Hiding this PID from logs){C.ENDC}")
    final_bpf_text = bpf_text_template.replace("YOUR_PID_GOES_HERE", str(my_pid))

    try:
        b = BPF(text=final_bpf_text)

        b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_exec_syscall")
        b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_openat_syscall")
        b.attach_tracepoint(tp="syscalls:sys_enter_connect", fn_name="trace_connect_syscall")
        b.attach_tracepoint(tp="syscalls:sys_enter_write", fn_name="trace_write_syscall")
        b.attach_tracepoint(tp="syscalls:sys_enter_read", fn_name="trace_read_enter")
        b.attach_tracepoint(tp="syscalls:sys_exit_read", fn_name="trace_read_exit")
        b.attach_tracepoint(tp="syscalls:sys_enter_memfd_create", fn_name="trace_memfd_create_syscall")
        b.attach_tracepoint(tp="syscalls:sys_enter_ptrace", fn_name="trace_ptrace_syscall")
        b.attach_tracepoint(tp="syscalls:sys_enter_unlinkat", fn_name="trace_unlinkat_syscall")
        b.attach_tracepoint(tp="syscalls:sys_enter_setuid", fn_name="trace_setuid_syscall")
        # 在 b.attach_tracepoint 列表中添加
        b.attach_tracepoint(tp="syscalls:sys_enter_mmap", fn_name="trace_mmap_syscall")

        fn = b.load_func("socket_filter", BPF.SOCKET_FILTER)

        interfaces_to_try = []
        if args.iface:
            interfaces_to_try.append(args.iface)
        else:
            try:
                for _, name in socket.if_nameindex():
                    interfaces_to_try.append(name)
            except:
                interfaces_to_try = ['eth0', 'lo', 'docker0', 'ens33', 'enp3s0']

        attached_count = 0
        print(f"{C.OKCYAN}ℹ️  Scanning interfaces: {', '.join(interfaces_to_try)}...{C.ENDC}")

        for iface in interfaces_to_try:
            try:
                BPF.attach_raw_socket(fn, iface)
                print(f"{C.OKGREEN}✅ Attached to {iface}{C.ENDC}")
                attached_interfaces.add(iface)
                attached_count += 1
            except Exception:
                pass

        if attached_count == 0:
            print(f"{C.FAIL}❌ Error: Could not attach to any network interface.{C.ENDC}")
            sys.exit(1)

        def lost_cb(count):
            print(f"{C.FAIL}[!] Lost {count} samples{C.ENDC}")

        b["syscall_events"].open_perf_buffer(handle_syscall_event, page_cnt=128, lost_cb=lost_cb)
        b["network_events"].open_perf_buffer(handle_network_event, page_cnt=128, lost_cb=lost_cb)

        print(f"\n{C.OKGREEN}✅ Monitoring active...{C.ENDC}\n")

        # --- NEW DYNAMIC DISCOVERY LOGIC ---
        def auto_discover():
            while True:
                time.sleep(3)
                try:
                    # Scan all current interfaces
                    current_ifaces = set()
                    for _, name in socket.if_nameindex():
                        current_ifaces.add(name)

                    # Find new ones
                    new_ifaces = current_ifaces - attached_interfaces

                    for iface in new_ifaces:
                        if iface == "lo": continue  # Optional skip
                        try:
                            BPF.attach_raw_socket(fn, iface)
                            attached_interfaces.add(iface)
                            print(f"{C.OKGREEN}✅ [Auto-Discovery] Attached to new interface: {iface}{C.ENDC}")
                        except:
                            pass
                except:
                    pass

        t = threading.Thread(target=auto_discover)
        t.daemon = True
        t.start()
        # -----------------------------------

        while True:
            try:
                b.perf_buffer_poll(timeout=50)
                current_pids = list(event_buffers.keys())
                for pid in current_pids: flush_buffer(pid, force=False)
            except KeyboardInterrupt:
                for pid in list(event_buffers.keys()): flush_buffer(pid, force=True)
                break
    except Exception as e:
        print(f"\n{C.FAIL}❌ Error: {e}{C.ENDC}")
        traceback.print_exc()
    finally:
        if CURRENT_LOG_HANDLE:
            try:
                CURRENT_LOG_HANDLE.close()
            except:
                pass


if __name__ == "__main__":
    main()
