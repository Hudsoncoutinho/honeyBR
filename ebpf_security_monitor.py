#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct
import time
import sys
import signal

class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("type", ct.c_char * 16),
        ("details", ct.c_char * 256)
    ]

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <net/sock.h>

struct event_t {
    u32 pid;
    char comm[16];
    char type[16];
    char details[256];
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read(&event.type, sizeof("open"), "open");
    if (bpf_probe_read_user_str(&event.details, sizeof(event.details), filename) > 0) {
        if (strstr(event.details, "secret") != NULL || 
            strstr(event.details, "/run/secrets/") != NULL ||
            strstr(event.details, ".env") != NULL ||
            strstr(event.details, "credentials") != NULL) {
            events.perf_submit(ctx, &event, sizeof(event));
        }
    }
    return 0;
}

int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read(&event.type, sizeof("exec"), "exec");
    if (bpf_probe_read_user_str(&event.details, sizeof(event.details), filename) > 0) {
        if (strstr(event.details, "sh") != NULL || 
            strstr(event.details, "bash") != NULL ||
            strstr(event.details, "git") != NULL || 
            strstr(event.details, "docker") != NULL ||
            strstr(event.details, "kubectl") != NULL ||
            strstr(event.details, "curl") != NULL ||
            strstr(event.details, "wget") != NULL) {
            events.perf_submit(ctx, &event, sizeof(event));
        }
    }
    return 0;
}

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read(&event.type, sizeof("net"), "net");
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    bpf_snprintf(event.details, sizeof(event.details), "Port: %d, Size: %lu", dport, size);
    if (dport != 80 && dport != 443 && dport != 8080 && dport != 8443) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
"""

running = True

def signal_handler(sig, frame):
    global running
    print("\n[INFO] Encerrando monitor honeyBR...")
    running = False
    sys.exit(0)

def print_event(cpu, data, size):
    try:
        event = ct.cast(data, ct.POINTER(Event)).contents
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [ALERTA SEGURANÇA CI/CD] "
              f"PID: {event.pid}, "
              f"Comm: {event.comm.decode('utf-8', errors='ignore')}, "
              f"Tipo: {event.type.decode('utf-8', errors='ignore')}, "
              f"Detalhes: {event.details.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"[ERRO] Falha ao processar evento: {e}")

def main():
    global running
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    print("=" * 60)
    print("honeyBR - Monitor de Segurança eBPF para CI/CD")
    print("=" * 60)
    print("[INFO] Inicializando programa eBPF...")
    try:
        b = BPF(text=bpf_text)
        print("[INFO] Anexando probes eBPF...")
        try:
            b.attach_kprobe(event="do_sys_openat2", fn_name="trace_openat")
        except:
            try:
                b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")
            except:
                b.attach_kprobe(event="sys_openat", fn_name="trace_openat")
        try:
            b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")
        except:
            b.attach_kprobe(event="sys_execve", fn_name="trace_execve")
        try:
            b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
        except Exception as e:
            print(f"[AVISO] Não foi possível anexar probe de rede: {e}")
        b["events"].open_perf_buffer(print_event)
        print("[INFO] Monitoramento ativo. Pressione Ctrl+C para parar.")
        print("-" * 60)
        while running:
            try:
                b.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception as e:
                if running:
                    print(f"[ERRO] Erro no polling: {e}")
                    time.sleep(1)
    except Exception as e:
        print(f"[ERRO CRÍTICO] Falha ao inicializar eBPF: {e}")
        print("[INFO] Verifique se:")
        print("  - O container está rodando com privilégios (privileged: true)")
        print("  - O kernel suporta eBPF (>= 4.17)")
        print("  - BCC está instalado corretamente")
        sys.exit(1)

if __name__ == "__main__":
    main()
