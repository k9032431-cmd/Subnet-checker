#!/usr/bin/env python3
"""
subcheck — быстро находит подсети, в которых пингуется хотя бы один IP.

Использование:
  subcheck                 # вставь список (из Telegram и т.п.) и нажми Enter на пустой строке
  subcheck list.txt        # взять подсети из файла
  subcheck -c              # взять подсети из буфера обмена (нужен Termux:API)
  cat list.txt | subcheck

Подсети ищутся в любом тексте: 104.105.1.0/24, 1.2.3.0/22, или просто IP (= /24).
"""
import argparse
import ipaddress
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:\s*/\s*(\d{1,2}))?(?![\d.])")

# ---------------------------------------------------------------- input


def parse_networks(text):
    nets, seen = [], set()
    for ip, prefix in IP_RE.findall(text):
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix or 24}", strict=False)
        except ValueError:
            continue
        if net not in seen:
            seen.add(net)
            nets.append(net)
    return nets


def read_interactive():
    """Читает вставленный текст. Ввод заканчивается сам через секунду
    после последней строки с подсетями (или по Ctrl+D)."""
    print("Вставь список подсетей и нажми Enter:", file=sys.stderr)
    fd = sys.stdin.fileno()
    buf, found = b"", False
    while True:
        if found and not select.select([fd], [], [], 1.0)[0]:
            break
        data = os.read(fd, 65536)
        if not data:
            break
        buf += data
        if IP_RE.search(buf.decode("utf-8", "ignore")):
            found = True
    return buf.decode("utf-8", "ignore")


def get_input(args):
    if args.clipboard:
        if not shutil.which("termux-clipboard-get"):
            sys.exit("Нужен Termux:API: pkg install termux-api (+ приложение Termux:API)")
        return subprocess.run(["termux-clipboard-get"], capture_output=True, text=True, timeout=10).stdout
    if args.files:
        text = ""
        for f in args.files:
            with open(f, encoding="utf-8", errors="ignore") as fh:
                text += fh.read() + "\n"
        return text
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return read_interactive()


# ---------------------------------------------------------------- probing order


def probe_order(net):
    """Порядок обхода адресов: сначала самые «живучие» (.1, .254, .2 ...)."""
    hosts = list(net) if net.num_addresses <= 2 else list(net.hosts())
    if not hosts:
        return []
    first = [hosts[0], hosts[-1]]
    rest = hosts[1:-1]
    order = first + rest
    if net.num_addresses > 2:
        order += [net.network_address, net.broadcast_address]
    out, seen = [], set()
    for h in order:
        if h not in seen:
            seen.add(h)
            out.append(str(h))
    return out


# ---------------------------------------------------------------- ICMP socket engine


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def make_packet(ident, seq):
    payload = b"subcheck" * 2
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    c = checksum(hdr + payload)
    return struct.pack("!BBHHH", 8, 0, c, ident, seq) + payload


def open_icmp():
    """ICMP-сокет без root (SOCK_DGRAM), если нет — raw (root)."""
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            s = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
            s.setblocking(False)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
            except OSError:
                pass
            return s, kind == socket.SOCK_RAW
        except OSError:
            continue
    return None, False


def icmp_scan(nets, rate, timeout, retries, find_all, progress):
    sock, raw = open_icmp()
    if sock is None:
        return None
    ident = os.getpid() & 0xFFFF

    owner = {}            # ip -> индекс подсети
    queues = []           # адреса для каждой подсети
    for i, net in enumerate(nets):
        q = probe_order(net)
        queues.append(q)
        for ip in q:
            owner[ip] = i
    alive = [set() for _ in nets]
    total = sum(len(q) for q in queues)
    sent = 0
    seq = 0
    interval = 1.0 / rate if rate > 0 else 0
    next_send = time.monotonic()

    def drain():
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            if raw:
                if len(data) < 20:
                    continue
                data = data[(data[0] & 0x0F) * 4:]
            if len(data) < 8 or data[0] != 0:   # 0 = echo reply
                continue
            if raw and struct.unpack("!H", data[4:6])[0] != ident:
                continue
            i = owner.get(addr[0])
            if i is not None:
                alive[i].add(addr[0])

    def done(i):
        return bool(alive[i]) and not find_all

    for attempt in range(retries + 1):
        # чередуем подсети: 1-й адрес всех подсетей, потом 2-й и т.д.
        pos = [0] * len(nets)
        active = [i for i in range(len(nets)) if not done(i)]
        while active:
            nxt = []
            for i in active:
                if done(i) or pos[i] >= len(queues[i]):
                    continue
                ip = queues[i][pos[i]]
                pos[i] += 1
                if ip in alive[i]:
                    nxt.append(i)
                    continue
                # пейсинг
                now = time.monotonic()
                if next_send > now:
                    r, _, _ = select.select([sock], [], [], next_send - now)
                    if r:
                        drain()
                next_send = max(next_send + interval, time.monotonic() - 0.05)
                seq = (seq + 1) & 0xFFFF
                pkt = make_packet(ident, seq)
                for _ in range(50):
                    try:
                        sock.sendto(pkt, (ip, 0))
                        break
                    except (BlockingIOError, InterruptedError):
                        select.select([sock], [sock], [], 0.01)
                        drain()
                    except OSError:
                        break
                sent += 1
                if sent % 256 == 0:
                    drain()
                    progress(attempt, sent, total, alive)
                nxt.append(i)
            active = nxt
        # ждём запоздавшие ответы
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([sock], [], [], left)
            if r:
                drain()
        progress(attempt, sent, total, alive)
        if all(done(i) for i in range(len(nets))):
            break
    sock.close()
    return alive


# ---------------------------------------------------------------- fallback: system ping


def ping_scan(nets, workers, timeout, find_all, progress):
    ping = shutil.which("ping") or ("/system/bin/ping" if os.path.exists("/system/bin/ping") else None)
    if not ping:
        sys.exit("Нет ни ICMP-сокета, ни команды ping. В Termux: pkg install inetutils")
    alive = [set() for _ in nets]
    w = str(max(1, int(round(timeout))))

    def one(i, ip):
        if alive[i] and not find_all:
            return
        r = subprocess.run([ping, "-c", "1", "-W", w, ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode == 0:
            alive[i].add(ip)

    jobs = []
    queues = [probe_order(n) for n in nets]
    total = sum(map(len, queues))
    for k in range(max(map(len, queues), default=0)):
        for i, q in enumerate(queues):
            if k < len(q):
                jobs.append((i, q[k]))
    with ThreadPoolExecutor(workers) as ex:
        for n, _ in enumerate(ex.map(lambda j: one(*j), jobs), 1):
            if n % 64 == 0:
                progress(0, n, total, alive)
    return alive


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description="Найти подсети, где пингуется хотя бы один IP")
    ap.add_argument("files", nargs="*", help="файл(ы) со списком подсетей")
    ap.add_argument("-c", "--clipboard", action="store_true", help="взять список из буфера обмена")
    ap.add_argument("-r", "--rate", type=int, default=3000, help="пакетов в секунду (по умолч. 3000)")
    ap.add_argument("-t", "--timeout", type=float, default=1.5, help="ждать ответы, сек (1.5)")
    ap.add_argument("-n", "--retries", type=int, default=1, help="доп. проходов для «мёртвых» (1)")
    ap.add_argument("-a", "--all", action="store_true", help="найти ВСЕ живые IP, а не первый")
    ap.add_argument("-o", "--output", default="alive.txt", help="куда сохранить (alive.txt)")
    ap.add_argument("--ping", action="store_true", help="использовать системный ping (медленно)")
    ap.add_argument("-w", "--workers", type=int, default=256, help="потоков для --ping (256)")
    args = ap.parse_args()

    nets = parse_networks(get_input(args))
    if not nets:
        sys.exit("Подсетей не найдено.")
    total_ips = sum(n.num_addresses for n in nets)
    print(f"Подсетей: {len(nets)}, адресов: {total_ips}", file=sys.stderr)

    tty = sys.stderr.isatty()
    t0 = time.monotonic()

    def progress(attempt, sent, total, alive):
        if tty:
            ok = sum(1 for a in alive if a)
            sys.stderr.write(f"\r  проход {attempt + 1}: отправлено {sent}  живых подсетей {ok}/{len(nets)}  ")
            sys.stderr.flush()

    alive = None
    if not args.ping:
        alive = icmp_scan(nets, args.rate, args.timeout, args.retries, args.all, progress)
        if alive is None:
            print("ICMP-сокет недоступен, переключаюсь на системный ping", file=sys.stderr)
    if alive is None:
        alive = ping_scan(nets, args.workers, args.timeout, args.all, progress)
    if tty:
        sys.stderr.write("\n")

    good = [(n, a) for n, a in zip(nets, alive) if a]
    dt = time.monotonic() - t0
    print(f"Готово за {dt:.1f} c. Живых подсетей: {len(good)} из {len(nets)}\n", file=sys.stderr)

    for n, a in good:
        ips = sorted(a, key=lambda x: ipaddress.ip_address(x))
        shown = ", ".join(ips[:5]) + (" …" if len(ips) > 5 else "")
        print(f"{n}", end="")
        if sys.stdout.isatty():
            print(f"   ({len(ips)} IP: {shown})", end="")
        print()

    plain = "\n".join(str(n) for n, _ in good)
    if args.output and good:
        with open(args.output, "w") as fh:
            fh.write(plain + "\n")
        print(f"\nСохранено в {os.path.abspath(args.output)}", file=sys.stderr)
    if good and shutil.which("termux-clipboard-set"):
        try:
            subprocess.run(["termux-clipboard-set"], input=plain, text=True, timeout=5)
            print("Скопировано в буфер обмена", file=sys.stderr)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nОстановлено.")
