#!/usr/bin/env python3
"""kzvpn — двойной VLESS-туннель (Обход#4 xhttp/reality -> kzVPN vision/reality) + TUN на всю систему.

Запуск:  ./kzvpn.py            — kzVPN, иконка в трее (логи открываются в браузере)
         ./kzvpn.py --console  — без трея, логи в терминале, Ctrl+C для выхода
         ./kzvpn.py --chain    — цепочка Обход #4 -> kzVPN
         ./kzvpn.py --hop1     — только Обход #4
         ./kzvpn.py --check    — проверить туннель без TUN и сказать, что не так
         ./kzvpn.py --lan      — не поднимать TUN, а отдать socks5 в локальную
                                 сеть: телефон ходит через ноут с готовой нарезкой
         ./kzvpn.py --url "vless://..."  — свой выходной сервер вместо kzVPN
         ./kzvpn.py --url1 "vless://..." — свой входной сервер вместо Обход #4
         ./kzvpn.py --nofrag   — выключить нарезку ClientHello (она нужна там,
                                 где DPI глотает рукопожатие; по умолчанию включена)

Xray строит цепочку hop1 -> hop2 и отдаёт SOCKS5 на 127.0.0.1:10808,
sing-box поднимает TUN и заворачивает туда весь трафик системы.
Бинарники качаются сами в ~/.local/share/kzvpn/bin при первом запуске.
"""
import hashlib
import io
import json
import os
import platform
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SB_VER = "1.13.21"
SOCKS_PORT = 10808
RELAY_PORT = 10801   # socks первого VPN, в него ходит второй
WEB_PORT = 8964
# ponytail: 1280 гарантированно проходит через двойную инкапсуляцию.
# Упирается скорость — крути вверх (1380/1420), пока большие пакеты не начнут рваться.
MTU = 1280

WIN = os.name == "nt"
MAC = sys.platform == "darwin"
FROZEN = getattr(sys, "frozen", False)  # собранное приложение (.app через PyInstaller)
EXE = ".exe" if WIN else ""
if WIN:
    DIR = os.path.join(os.environ["LOCALAPPDATA"], "kzvpn")
elif MAC:
    DIR = os.path.expanduser("~/Library/Application Support/kzvpn")
else:
    DIR = os.path.expanduser("~/.local/share/kzvpn")
BIN = os.path.join(DIR, "bin")
LOG = deque(maxlen=4000)
CONSOLE = any(a in sys.argv for a in ("--console", "--check", "--lan"))
CHECK = "--check" in sys.argv
# нарезка ClientHello включена всегда: без неё DPI глотает рукопожатие,
# а там где DPI нет — она ничего не портит (замерено 5/5 в обоих случаях)
FRAG = "--nofrag" not in sys.argv
LAN = "--lan" in sys.argv     # socks на всю локальную сеть (для телефона), без TUN
MODE = next((a[2:] for a in sys.argv if a in ("--hop1", "--hop2", "--chain")), "hop2")


def log(line):
    LOG.append(f"{time.strftime('%H:%M:%S')} {line.rstrip()}")
    if sys.stdout:  # в .app, запущенном из Finder, stdout нет
        print(LOG[-1], flush=True)


# ---------------------------------------------------------------- конфиги

# Ссылки как есть. Заменить/добавить свою: --url (выходной сервер) и --url1 (входной)
HOP1_URL = ("vless://9f7e9128-fe00-4336-b33f-151963fcba1c@46.243.234.117:1449"
            "?encryption=none&security=reality&sni=ads.x5.ru&fp=firefox"
            "&pbk=ma1sfxr9KLRlUY27L-P8femXtXkjB-NAb-24mZEX3Bo&type=xhttp&path=%2F&mode=auto"
            "#Обход #4")
HOP2_URL = ("vless://c40e0d7b-ba7c-48ef-a5d6-7978f33d40d7@5.129.223.183:443"
            "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com"
            "&fp=chrome&pbk=joDO8jWkCAuNMZ4cVzblUjdKM29oqQTtiQxlHJZUMSU&sid=552ccb92d1280375"
            "&type=tcp&headerType=none#kzVPN")


def arg(name, default=None):
    a = sys.argv
    return a[a.index(name) + 1] if name in a and a.index(name) + 1 < len(a) else default


def parse_vless(url, tag):
    """vless://uuid@host:port?параметры#имя -> outbound для Xray."""
    u = urllib.parse.urlparse(url.strip())
    if u.scheme != "vless" or not u.username or not u.hostname:
        sys.exit(f"не похоже на vless-ссылку: {url[:40]}...")
    q = dict(urllib.parse.parse_qsl(u.query))
    user = {"id": u.username, "encryption": q.get("encryption", "none")}
    if q.get("flow"):
        user["flow"] = q["flow"]
    net = q.get("type", "tcp")
    ss = {"network": net, "security": q.get("security", "none")}
    if ss["security"] == "reality":
        ss["realitySettings"] = {
            "serverName": q.get("sni", ""), "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
    elif ss["security"] == "tls":
        ss["tlsSettings"] = {"serverName": q.get("sni", u.hostname),
                             "fingerprint": q.get("fp", "chrome"),
                             "allowInsecure": q.get("allowInsecure") == "1"}
    path = urllib.parse.unquote(q.get("path", "/"))
    if net == "xhttp":
        ss["xhttpSettings"] = {"path": path, "mode": q.get("mode", "auto")}
    elif net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": q.get("host", "")}}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": q.get("host", "")}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    name = urllib.parse.unquote(u.fragment) or u.hostname
    return {"tag": tag, "protocol": "vless",
            "settings": {"vnext": [{"address": u.hostname, "port": u.port or 443,
                                    "users": [user]}]},
            "streamSettings": ss}, name


def host_ip(outbound):
    """IP входного сервера — он обязан ходить мимо TUN. Домен резолвим заранее."""
    host = outbound["settings"]["vnext"][0]["address"]
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        return socket.gethostbyname(host)


HOP1, HOP1_NAME = parse_vless(arg("--url1", HOP1_URL), "hop1")
HOP2, HOP2_NAME = parse_vless(arg("--url", HOP2_URL), "hop2")
HOP1_IP, HOP2_IP = host_ip(HOP1), host_ip(HOP2)


# ponytail: сервер Обход #4 подменяет адрес назначения по SNI, поэтому режем
# ClientHello на куски — его сниффер не собирает домен и IP остаётся нашим.
# Калибровочная ручка, замерено на живых серверах (успешных коннектов из 10):
# 30-50 -> 4, 60-80 -> 1, 100-100 -> 0; interval обязан быть "0", с задержкой хуже.
# Режим tlshello обязателен: raw-нарезка ("1-2" и т.п.) сниффер собирает обратно.
FRAGMENT = {"packets": "tlshello", "length": "30-50", "interval": "0"}


def frag_out(tag="frag", detour=None):
    """freedom с нарезкой ClientHello. detour — куда отдавать после нарезки."""
    o = {"tag": tag, "protocol": "freedom", "settings": {"fragment": FRAGMENT}}
    if detour:
        o["streamSettings"] = {"sockopt": {"dialerProxy": detour}}
    return o


def socks_in(tag, port, sniff, listen="127.0.0.1"):
    return {
        "tag": tag, "listen": listen, "port": port, "protocol": "socks",
        "settings": {"udp": True, "auth": "noauth"},
        "sniffing": {"enabled": sniff, "destOverride": ["http", "tls", "quic"]},
    }


def relay_cfg():
    """Первый VPN — отдельный процесс со своим socks. Конфиг hop1 как есть.

    sniffing выключен намеренно: с destOverride Xray подменил бы IP второго
    сервера на домен из его SNI (max.ru) и ушёл бы на настоящий max.ru.
    """
    return {"log": {"loglevel": "info"},
            "inbounds": [socks_in("relay-in", RELAY_PORT, False)],
            "outbounds": [HOP1]}


def xray_cfg():
    """Второй процесс. В режиме chain весь его интернет идёт в socks первого."""
    hop2 = json.loads(json.dumps(HOP2))
    if MODE == "chain":
        hop2["streamSettings"]["sockopt"] = {"dialerProxy": "frag"}
        outbounds = [
            hop2,
            frag_out(detour="via-relay"),
            {"tag": "via-relay", "protocol": "socks",
             "settings": {"servers": [{"address": "127.0.0.1", "port": RELAY_PORT}]}},
        ]
    else:
        hop2["streamSettings"].pop("sockopt", None)
        first = hop2 if MODE == "hop2" else json.loads(json.dumps(HOP1))
        outbounds = [first]
        if FRAG:
            first["streamSettings"]["sockopt"] = {"dialerProxy": "frag"}
            outbounds.append(frag_out())
    inbounds = [socks_in("socks-in", SOCKS_PORT, True, "0.0.0.0" if LAN else "127.0.0.1")]
    # http-прокси нужен всегда: им ходит --check и через него iPhone в режиме --lan
    inbounds.append({"tag": "http-in", "listen": "0.0.0.0" if LAN else "127.0.0.1",
                     "port": SOCKS_PORT + 1, "protocol": "http"})
    return {"log": {"loglevel": "info"}, "inbounds": inbounds, "outbounds": outbounds}


def sb_cfg():
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "tcp", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
                # sing-box 1.13 запрещает detour на пустой direct — local ходит напрямую сам
                {"type": "udp", "tag": "local", "server": "1.1.1.1"},
            ],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            **({} if MAC else {"interface_name": "kzvpn0"}),  # на macOS только utunN
            "address": ["172.19.0.1/30"], "mtu": MTU,
            "auto_route": True, "strict_route": True, "stack": "gvisor",
        }],
        "outbounds": [
            {"type": "socks", "tag": "proxy", "server": "127.0.0.1",
             "server_port": SOCKS_PORT, "version": "5"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "local",
            "final": "proxy",
            "rules": [
                # Первым и БЕЗ sniff: входной сервер идёт мимо TUN, иначе петля.
                # Если сюда доберётся sniff, он подменит IP на SNI из REALITY (max.ru),
                # direct полезет резолвить домен через DNS, а DNS ждёт этот же коннект.
                {"ip_cidr": [(HOP2_IP if MODE == "hop2" else HOP1_IP) + "/32"],
                 "outbound": "direct"},
                {"action": "sniff"},
                # hijack-dns строго до ip_is_private: резолвер системы теперь живёт
                # на адресе TUN, и direct на него = "loopback connection to TUN range"
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
        },
    }


# ---------------------------------------------------------------- бинарники

# platform.machine(): Linux даёт x86_64/aarch64, Windows — AMD64/ARM64
ARCH = {"x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
OSKEY = "windows" if WIN else "macos" if MAC else "linux"


def assets(oskey, arch):
    """(архив Xray, имя папки sing-box, расширение архива sing-box)."""
    xray = f"Xray-{oskey}-{'64' if arch == 'amd64' else 'arm64-v8a'}.zip"
    sb = f"sing-box-{SB_VER}-{'darwin' if oskey == 'macos' else oskey}-{arch}"
    return xray, sb, ".zip" if oskey == "windows" else ".tar.gz"


XRAY_ASSET, SB_BASE, SB_EXT = assets(OSKEY, ARCH) if ARCH else (None, None, None)
XRAY_VER = "v26.3.27"
# Версии закреплены вместе с SHA256: хэш надёжнее TLS, и если TLS на машине не
# проверяется (антивирус подменяет сертификаты, у Python нет корневых) — качаем
# без проверки TLS, а подмену файла ловит хэш. Хэши Xray сверены с его .dgst.
SHA256 = {
    "Xray-linux-64.zip": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    "Xray-linux-arm64-v8a.zip": "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
    "Xray-windows-64.zip": "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
    "Xray-windows-arm64-v8a.zip": "35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88",
    "sing-box-1.13.21-linux-amd64.tar.gz": "24f9ef8e7234e13e71e74c3598a4164c5fe07b7b67ccc6e96cf68b54789f72cd",
    "sing-box-1.13.21-linux-arm64.tar.gz": "3e30b876c9a93c19e503e2a2d6249cf05e6a26766553d4b61e1daf48223f304f",
    "sing-box-1.13.21-windows-amd64.zip": "a03291793d3a3c6e266447a58140657ac099ff278abf3b8ff678932356a62ced",
    "sing-box-1.13.21-windows-arm64.zip": "ef752d9bffd6d590dd6886b28819a7ae4efee70b8188f9198757d91570efd554",
    "Xray-macos-64.zip": "f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203",
    "Xray-macos-arm64-v8a.zip": "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf",
    "sing-box-1.13.21-darwin-amd64.tar.gz": "61093d79211a6ae7b707d30f07be35b1167ca8366bf0dbc06ee5fb35c90dc9e8",
    "sing-box-1.13.21-darwin-arm64.tar.gz": "62bca85bf08b9145288729cf010c98ea9877b8086f7369cde9e127012d509424",
}


def fetch(url, proxy=None):
    """Скачать и сверить с закреплённым SHA256."""
    name = url.rsplit("/", 1)[-1]
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    log(f"качаю {name}" + (" через туннель" if proxy else ""))
    for ctx in (None, ssl._create_unverified_context()):
        try:
            opener = urllib.request.build_opener(*handlers, urllib.request.HTTPSHandler(context=ctx))
            data = opener.open(url, timeout=120).read()
            break
        except urllib.error.URLError as e:
            if ctx is None and isinstance(e.reason, ssl.SSLCertVerificationError):
                log("TLS-сертификат не проверяется (антивирус или старый Python) — "
                    "качаю без проверки TLS, целостность сверю по SHA256")
                continue
            raise
    if hashlib.sha256(data).hexdigest() != SHA256[name]:
        raise RuntimeError(f"{name}: SHA256 не совпал — файл подменён или битый, не запускаю")
    return data


def ensure_bins():
    if not XRAY_ASSET:
        sys.exit(f"неподдерживаемая система: {sys.platform} {platform.machine()}")
    os.makedirs(BIN, exist_ok=True)
    xray = os.path.join(BIN, "xray" + EXE)
    sb = os.path.join(BIN, "sing-box" + EXE)
    dll = os.path.join(BIN, "wintun.dll")
    if not os.path.exists(xray) or (WIN and not os.path.exists(dll)):
        z = zipfile.ZipFile(io.BytesIO(fetch(
            f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VER}/{XRAY_ASSET}")))
        # wintun.dll (без неё sing-box не поднимет TUN на Windows) лежит прямо в архиве
        # Xray — побайтно та же, что на wintun.net, который у части провайдеров режется
        for name in ("xray" + EXE, "geosite.dat", "geoip.dat", "wintun.dll"):
            if name in z.namelist():
                open(os.path.join(BIN, name), "wb").write(z.read(name))
        os.chmod(xray, 0o755)
    if not os.path.exists(sb):
        base = SB_BASE
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{SB_VER}/{base}{SB_EXT}"
        if WIN:
            z = zipfile.ZipFile(io.BytesIO(fetch(url)))
            open(sb, "wb").write(z.read(f"{base}/sing-box.exe"))
        else:
            t = tarfile.open(fileobj=io.BytesIO(fetch(url)))
            open(sb, "wb").write(t.extractfile(f"{base}/sing-box").read())
        os.chmod(sb, 0o755)
    return xray, sb


# ---------------------------------------------------------------- процессы

def is_admin():
    if WIN:
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def sudo():
    if is_admin():
        return []
    if WIN:  # Windows сам права не повышает — запуск должен быть от админа
        return None
    return ["sudo"] if sys.stdin and sys.stdin.isatty() else ["pkexec"]


# Запускается от root через окно пароля macOS. Держит sing-box, пока живо
# приложение и нет файла-флага остановки: так TUN снимается без второго пароля,
# а закрытое или упавшее приложение не оставляет висеть root-процесс.
MAC_WRAPPER = r"""#!/bin/sh
# $1 sing-box  $2 конфиг  $3 лог  $4 pid-файл  $5 флаг остановки  $6 pid приложения
"$1" run -c "$2" >> "$3" 2>&1 &
p=$!
echo $p > "$4"
while kill -0 $p 2>/dev/null && kill -0 "$6" 2>/dev/null && [ ! -e "$5" ]; do sleep 1; done
kill $p 2>/dev/null
wait $p 2>/dev/null
rm -f "$5" "$4"
"""


class MacRootTun:
    """sing-box от root на macOS с интерфейсом Popen: poll(), terminate(), stdout."""

    def __init__(self, sb, cfg, sh=None, elevate=True):
        self.logf, self.pidf, self.flag = (
            os.path.join(DIR, n) for n in ("sing-box.log", "sing-box.pid", "sing-box.stop"))
        for f in (self.flag, self.pidf):
            if os.path.exists(f):
                os.remove(f)
        open(self.logf, "w").close()
        sh = sh or os.path.join(DIR, "tun.sh")
        open(sh, "w").write(MAC_WRAPPER)
        cmd = "/bin/sh " + " ".join(shlex.quote(a) for a in (
            sh, sb, cfg, self.logf, self.pidf, self.flag, str(os.getpid()))) + " >/dev/null 2>&1 &"
        if elevate:
            # ensure_ascii=False: AppleScript не понимает \uXXXX, а в пути бывает кириллица
            script = (f"do shell script {json.dumps(cmd, ensure_ascii=False)} "
                      f'with administrator privileges with prompt "kzVPN поднимает VPN для всей системы"')
            if subprocess.run(["osascript", "-e", script], capture_output=True).returncode:
                raise RuntimeError("пароль администратора не введён — TUN не поднят")
        else:  # для теста без macOS: та же оболочка, но без повышения прав
            subprocess.run(["/bin/sh", "-c", cmd])
        for _ in range(50):  # root-оболочка стартует в фоне — ждём её pid
            if os.path.exists(self.pidf):
                break
            time.sleep(0.1)
        self.stdout = self._tail()

    def _pid(self):
        try:
            return int(open(self.pidf).read())
        except (OSError, ValueError):
            return None

    def poll(self):
        pid = self._pid()
        if pid is None:  # оболочка убрала pid-файл — sing-box завершён
            return 0
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return 0
        except PermissionError:  # процесс root — значит жив
            pass
        return None

    def terminate(self):
        open(self.flag, "w").close()  # оболочка увидит флаг и сама погасит sing-box
        for _ in range(50):
            if self.poll() is not None:
                return
            time.sleep(0.1)

    def _tail(self):
        with open(self.logf, errors="replace") as f:
            while True:
                line = f.readline()
                if line:
                    yield line
                elif self.poll() is not None:
                    return
                else:
                    time.sleep(0.2)


class VPN:
    def __init__(self):
        self.xray = self.sb = self.relay = None

    @property
    def running(self):
        return self.sb is not None and self.sb.poll() is None

    def _pump(self, proc, tag):
        for line in proc.stdout:
            log(f"[{tag}] {line}")
            if "received real certificate" in line:
                log(f"!! сниффер {HOP1_NAME} всё-таки собрал SNI — уменьши FRAGMENT length "
                    "или запусти с --hop2 (см. README).")
        log(f"[{tag}] процесс завершился (код {proc.poll()})")

    def _spawn(self, cmd, tag):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
        threading.Thread(target=self._pump, args=(p, tag), daemon=True).start()
        return p

    def _wait_socks(self, port, proc, what):
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return True
            except OSError:
                if proc.poll() is not None:
                    log(f"{what} умер, смотри лог выше")
                    return False
                time.sleep(0.1)
        log(f"{what} не поднял socks за 10 с")
        return False

    def start_tunnel(self):
        """Поднять только Xray (цепочку или один хоп), без TUN."""
        xray, _ = ensure_bins()
        xc = os.path.join(DIR, "xray.json")
        json.dump(xray_cfg(), open(xc, "w"), indent=1)
        log({"chain": f"старт цепочки {HOP1_NAME} -> {HOP2_NAME} (два отдельных процесса)",
             "hop1": f"старт: только {HOP1_NAME}",
             "hop2": f"старт: только {HOP2_NAME}"}[MODE])
        if MODE == "chain":
            rc = os.path.join(DIR, "xray-relay.json")
            json.dump(relay_cfg(), open(rc, "w"), indent=1)
            self.relay = self._spawn([xray, "run", "-c", rc], "vpn1")
            if not self._wait_socks(RELAY_PORT, self.relay, "первый VPN"):
                return False
            log(f"первый VPN поднят, socks 127.0.0.1:{RELAY_PORT}")
        self.xray = self._spawn([xray, "run", "-c", xc], "vpn2" if MODE == "chain" else "xray")
        return self._wait_socks(SOCKS_PORT, self.xray, "второй VPN")

    def start(self):
        if self.running:
            return
        _, sb = ensure_bins()
        sc = os.path.join(DIR, "sing-box.json")
        json.dump(sb_cfg(), open(sc, "w"), indent=1)
        if not self.start_tunnel():
            return

        if MAC and not is_admin():
            log("поднимаю TUN — macOS спросит пароль администратора")
            try:
                self.sb = MacRootTun(sb, sc)
            except RuntimeError as e:
                log(str(e))
                return
            threading.Thread(target=self._pump, args=(self.sb, "tun"), daemon=True).start()
        else:
            pre = sudo()
            if pre is None:
                log("TUN на Windows требует прав администратора: запусти от имени "
                    "администратора, либо используй --lan (прокси без TUN)")
                return
            log("поднимаю TUN (нужны права администратора)" if WIN else "поднимаю TUN (нужен root)")
            self.sb = self._spawn(pre + [sb, "run", "-c", sc], "tun")
        time.sleep(1)
        log("готово, весь трафик системы идёт через туннель" if self.running
            else "TUN не поднялся")

    def stop(self):
        if self.sb:
            # ponytail: sudo не пробрасывает сигналы дочернему процессу — бьём по имени.
            if WIN or MAC or is_admin():  # на Mac terminate() — через флаг, без пароля
                self.sb.terminate()
            else:
                subprocess.run(sudo() + ["pkill", "-x", "sing-box"])
            self.sb = None
        for p in ("xray", "relay"):
            if getattr(self, p):
                getattr(self, p).terminate()
                setattr(self, p, None)
        log("отключено")


# ---------------------------------------------------------------- live-логи

PAGE = b"""<!doctype html><meta charset=utf-8><title>kzvpn logs</title>
<style>body{background:#111;color:#ddd;font:13px/1.45 monospace;margin:0;padding:10px}
pre{white-space:pre-wrap;margin:0}</style><pre id=l>...</pre><script>
let l=document.getElementById('l');
setInterval(async()=>{let stick=innerHeight+scrollY>=document.body.scrollHeight-40;
l.textContent=await(await fetch('/log')).text();
if(stick)scrollTo(0,document.body.scrollHeight)},1000)</script>"""


class Web(BaseHTTPRequestHandler):
    def do_GET(self):
        raw = self.path == "/log"
        body = "\n".join(LOG).encode() if raw else PAGE
        self.send_response(200)
        self.send_header("Content-Type",
                         ("text/plain" if raw else "text/html") + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# ---------------------------------------------------------------- трей

def gui_deps():
    if FROZEN:  # в собранном .app pystray и pillow уже внутри
        return True
    if not (WIN or MAC) and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    # именно find_spec: сам import pystray выбирает бэкенд и падает раньше,
    # чем мы успеваем этот бэкенд назначить
    import importlib.util
    if all(importlib.util.find_spec(m) for m in ("pystray", "PIL")):
        return True
    if os.environ.get("KZVPN_VENV"):
        return False
    try:
        venv = os.path.join(DIR, "venv")
        py = os.path.join(venv, "Scripts" if WIN else "bin", "python" + EXE)
        cfg = os.path.join(venv, "pyvenv.cfg")
        # gi/AppIndicator ставится системно, поэтому venv обязан его видеть
        if os.path.exists(cfg) and "system-site-packages = true" not in open(cfg).read():
            shutil.rmtree(venv)
        if not os.path.exists(py):
            subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", venv],
                           check=True)
        log("ставлю pystray и pillow для иконки в трее, это займёт полминуты")
        subprocess.run([py, "-m", "pip", "install", "-q", "pystray", "pillow"], check=True)
        os.environ["KZVPN_VENV"] = "1"
        cmd = [py, os.path.abspath(__file__)] + sys.argv[1:]
        if WIN:  # os.execv на Windows отпускает консоль, процесс выглядит "пропавшим"
            sys.exit(subprocess.call(cmd))
        os.execv(py, cmd)
    except Exception as e:
        print("трей недоступен:", e)
        return False


def tray_backend():
    """appindicator / xorg / win32 / darwin / None — что работает на этом рабочем столе."""
    if WIN:
        return "win32"
    if MAC:
        return "darwin"
    for mod in ("AyatanaAppIndicator3", "AppIndicator3"):
        try:
            import gi
            gi.require_version(mod, "0.1")
            __import__("gi.repository", fromlist=[mod])
            return "appindicator"
        except Exception:
            pass
    try:  # XEmbed-трей: если никто не держит _NET_SYSTEM_TRAY_S0, докаться некуда
        from Xlib import display
        d = display.Display()
        if d.get_selection_owner(d.intern_atom("_NET_SYSTEM_TRAY_S0")):
            return "xorg"
    except Exception:
        pass
    return None


NO_TRAY_HINT = """трея на этом рабочем столе нет (нужен AppIndicator):
  sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1
GNOME на Wayland вдобавок требует расширение AppIndicator/KStatusNotifier.
Работаю без трея, логи ниже и на http://127.0.0.1:%d/ , Ctrl+C для выхода."""


def tray(vpn):
    import pystray
    from PIL import Image, ImageDraw

    def icon_img(on):
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        ImageDraw.Draw(img).ellipse((6, 6, 58, 58), fill=(46, 204, 113) if on else (120, 120, 120))
        return img

    def refresh(ic):
        ic.icon = icon_img(vpn.running)
        ic.update_menu()

    def toggle(ic, _):
        (vpn.stop if vpn.running else vpn.start)()
        refresh(ic)

    def quit_(ic, _):
        vpn.stop()
        ic.stop()

    menu = pystray.Menu(
        pystray.MenuItem(lambda _: "● подключено" if vpn.running else "○ выключено",
                         None, enabled=False),
        pystray.MenuItem(lambda _: "Отключить" if vpn.running else "Подключить",
                         toggle, default=True),
        pystray.MenuItem("Live логи", lambda: webbrowser.open(f"http://127.0.0.1:{WEB_PORT}/")),
        pystray.MenuItem("Выход", quit_),
    )
    ic = pystray.Icon("kzvpn", icon_img(False), f"kzVPN ({MODE})", menu)

    def boot():
        try:
            vpn.start()
        except Exception as e:
            log(f"не удалось запустить: {type(e).__name__}: {e}")
        while ic.visible:  # процесс мог упасть сам — держим цвет иконки актуальным
            refresh(ic)
            time.sleep(2)

    threading.Thread(target=boot, daemon=True).start()
    ic.run()


def tcp_probe():
    """Отличить 'порт закрыт' от 'порт открыт, но сервер молчит'."""
    hops = [(HOP2_NAME, HOP2_IP, HOP2["settings"]["vnext"][0]["port"])]
    if MODE != "hop2":
        hops.insert(0, (HOP1_NAME, HOP1_IP, HOP1["settings"]["vnext"][0]["port"]))
    for name, ip, port in hops:
        t = time.time()
        try:
            socket.create_connection((ip, port), 6).close()
            log(f"TCP до {name} ({ip}:{port}): открыт, {time.time() - t:.2f} с")
        except OSError as e:
            log(f"TCP до {name} ({ip}:{port}): НЕ открыт — {e}")


def check(vpn):
    """Поднять только туннель (без TUN) и сказать, работает ли он."""
    tcp_probe()
    if not vpn.start_tunnel():
        return
    # сертификат ipinfo тут не важен — читаем только IP; с проверкой TLS на машине
    # с подменой сертификатов вышло бы ложное "НЕ работает"
    proxy = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{SOCKS_PORT + 1}",
         "https": f"http://127.0.0.1:{SOCKS_PORT + 1}"}),
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    for i in range(1, 6):
        try:
            ip = proxy.open("https://ipinfo.io/ip", timeout=15).read().decode().strip()
            log(f"попытка {i}: туннель работает, внешний IP {ip}")
        except Exception as e:
            log(f"попытка {i}: НЕ работает — {type(e).__name__}: {e}")
    if MODE == "chain":  # доказательство, что kz достаётся именно изнутри первого VPN
        n = sum("[relay-in >> hop1]" in l for l in LOG)
        log(f"первый VPN протащил внутри себя соединений до kz: {n}")
    bad = [l for l in LOG if "[Error]" in l or "ERROR" in l]
    log(f"ошибок в логах: {len(bad)}")
    for l in bad[-5:]:
        log("  " + l.split("] ", 1)[-1])


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return "адрес-этого-компа"
    finally:
        s.close()


def serve_lan(vpn):
    if not vpn.start_tunnel():
        return
    ip = lan_ip()
    log(f"socks5 для сети:      {ip}:{SOCKS_PORT}   (Android: тип socks5, remote DNS)")
    log(f"http-прокси для сети: {ip}:{SOCKS_PORT + 1}   (iPhone: Wi-Fi -> прокси -> вручную)")
    log("логина и пароля нет. Ноут должен быть включён и в этой же сети.")
    log("ВНИМАНИЕ: прокси открыт всем в этой сети, не включай в публичном Wi-Fi.")
    while vpn.xray.poll() is None:
        time.sleep(1)
    log("Xray завершился")


def main():
    global CONSOLE
    os.makedirs(DIR, exist_ok=True)
    who = HOP2_NAME if MODE == "hop2" else (HOP1_NAME if MODE == "hop1"
                                            else f"{HOP1_NAME} -> {HOP2_NAME}")
    log(f"kzvpn: {who}, нарезка {'вкл' if FRAG else 'выкл'}, файлы в {DIR}")
    vpn = VPN()
    if CHECK or LAN:
        try:
            (serve_lan if LAN else check)(vpn)
        except KeyboardInterrupt:
            pass
        finally:
            vpn.stop()
        return
    threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", WEB_PORT), Web).serve_forever,
                     daemon=True).start()
    if not CONSOLE and gui_deps():
        backend = tray_backend()
        if backend:
            os.environ["PYSTRAY_BACKEND"] = backend
            try:
                tray(vpn)
                return
            except Exception as e:
                print("трей не поднялся:", e)
        print(NO_TRAY_HINT % WEB_PORT)
    elif CONSOLE:
        print(f"логи также на http://127.0.0.1:{WEB_PORT}/ , Ctrl+C для выхода")
    # любой путь мимо трея = консольный режим, иначе логов не видно вообще
    CONSOLE = True
    try:
        vpn.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        vpn.stop()


if __name__ == "__main__":
    main()
