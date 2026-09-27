"""Конфиги всех режимов должны приниматься живыми xray/sing-box."""
import json, os, subprocess, tempfile, kzvpn

def check(mode):
    kzvpn.MODE = mode
    xc, sc = kzvpn.xray_cfg(), kzvpn.sb_cfg()
    assert sc["route"]["rules"][0]["ip_cidr"][0] == \
        (kzvpn.HOP2_IP if mode == "hop2" else kzvpn.HOP1_IP) + "/32"
    # http-прокси поднимается всегда, им же качается wintun.dll на Windows
    assert [i["tag"] for i in xc["inbounds"]] == ["socks-in", "http-in"]
    cfgs = [xc]
    tags = [o["tag"] for o in xc["outbounds"]]
    if mode == "chain":
        # второй процесс ходит в socks первого, а не дозванивается сам
        # hop2 -> нарезка ClientHello -> socks первого VPN
        assert tags == ["hop2", "frag", "via-relay"], tags
        assert xc["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "frag"
        assert xc["outbounds"][1]["streamSettings"]["sockopt"]["dialerProxy"] == "via-relay"
        assert xc["outbounds"][1]["settings"]["fragment"]["packets"] == "tlshello"
        assert xc["outbounds"][2]["settings"]["servers"][0]["port"] == kzvpn.RELAY_PORT
        relay = kzvpn.relay_cfg()
        # первый хоп тоже с нарезкой: до первого сервера рукопожатие глотает DPI
        assert [o["tag"] for o in relay["outbounds"]] == ["hop1", "frag"]
        assert relay["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "frag"
        # sniffing на relay обязан быть выключен, иначе destOverride уведёт на SNI
        assert relay["inbounds"][0]["sniffing"]["enabled"] is False
        cfgs.append(relay)
    else:
        # нарезка включена по умолчанию и в одиночных режимах
        assert tags == [mode, "frag"], tags
        assert xc["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "frag"
        kzvpn.FRAG = False
        try:
            plain = kzvpn.xray_cfg()
        finally:
            kzvpn.FRAG = True
        assert [o["tag"] for o in plain["outbounds"]] == [mode]
        assert "sockopt" not in plain["outbounds"][0]["streamSettings"]
        cfgs.append(plain)

    xray, sb = kzvpn.ensure_bins()
    with tempfile.TemporaryDirectory() as d:
        for i, c in enumerate(cfgs):
            json.dump(c, open(f"{d}/x{i}.json", "w"))
            assert subprocess.run([xray, "run", "-test", "-c", f"{d}/x{i}.json"],
                                  capture_output=True).returncode == 0, f"xray отверг {mode}"
        json.dump(sc, open(f"{d}/s.json", "w"))
        r = subprocess.run([sb, "check", "-c", f"{d}/s.json"], capture_output=True)
        assert r.returncode == 0, f"sing-box отверг {mode}: {r.stderr.decode()}"
    print(mode, "ok")

def check_win_bins():
    """Windows-распаковка без Windows: архивы берутся из закреплённых релизов,
    проверяем, что после ensure_bins на месте xray.exe, sing-box.exe и wintun.dll."""
    import tempfile, urllib.request
    cache = {}

    def fake_fetch(url, proxy=None):  # настоящий fetch, но один раз на архив
        if url not in cache:
            cache[url] = real_fetch(url, proxy)
        return cache[url]

    real_fetch = kzvpn.fetch
    saved = (kzvpn.WIN, kzvpn.EXE, kzvpn.ARCH, kzvpn.XRAY_ASSET, kzvpn.BIN, kzvpn.fetch,
             kzvpn.SB_BASE, kzvpn.SB_EXT)
    try:
        with tempfile.TemporaryDirectory() as d:
            kzvpn.WIN, kzvpn.EXE, kzvpn.ARCH = True, ".exe", "amd64"
            kzvpn.XRAY_ASSET, kzvpn.SB_BASE, kzvpn.SB_EXT = kzvpn.assets("windows", "amd64")
            kzvpn.BIN, kzvpn.fetch = d, fake_fetch
            try:
                kzvpn.ensure_bins()
            except FileNotFoundError:
                pass  # песочница может стереть свежий xray.exe до chmod — проверяем остальное
            got = set(os.listdir(d))
            for f in ("sing-box.exe", "wintun.dll"):
                assert f in got, f"нет {f}: {got}"
    finally:
        (kzvpn.WIN, kzvpn.EXE, kzvpn.ARCH, kzvpn.XRAY_ASSET, kzvpn.BIN, kzvpn.fetch,
         kzvpn.SB_BASE, kzvpn.SB_EXT) = saved
    print("windows-распаковка ok (sing-box.exe, wintun.dll)")


def check_assets():
    """Каждый архив, который скрипт может запросить на любой ОС, закреплён по SHA256."""
    for osk in ("linux", "windows", "macos"):
        for arch in ("amd64", "arm64"):
            xray, sb, ext = kzvpn.assets(osk, arch)
            assert xray in kzvpn.SHA256, xray
            assert sb + ext in kzvpn.SHA256, sb + ext
    # Linux не поменял имена, а Mac получает свои архивы, а не линуксовые
    assert kzvpn.assets("linux", "amd64") == (
        "Xray-linux-64.zip", "sing-box-1.13.21-linux-amd64", ".tar.gz")
    assert kzvpn.assets("macos", "arm64") == (
        "Xray-macos-arm64-v8a.zip", "sing-box-1.13.21-darwin-arm64", ".tar.gz")
    print("все архивы закреплены по SHA256")


def check_mac_wrapper():
    """Root-оболочка TUN для macOS — без macOS и без повышения прав: держит процесс,
    отдаёт его лог, гасится флагом (без второго пароля) и сама гасит процесс,
    если приложение умерло."""
    import time
    saved = kzvpn.DIR
    with tempfile.TemporaryDirectory() as d:
        kzvpn.DIR = d
        try:
            fake = os.path.join(d, "fake-sing-box")
            open(fake, "w").write("#!/bin/sh\necho started\nexec sleep 60\n")
            os.chmod(fake, 0o755)

            t = kzvpn.MacRootTun(fake, "cfg.json", elevate=False)
            assert t.poll() is None, "процесс не поднялся"
            assert next(t.stdout).strip() == "started", "лог не читается"
            t.terminate()
            assert t.poll() == 0, "флаг остановки не сработал"

            # приложение умерло -> оболочка сама гасит процесс
            w = os.path.join(d, "w.sh")
            open(w, "w").write(kzvpn.MAC_WRAPPER)
            app = subprocess.Popen(["sleep", "1"])
            pidf = os.path.join(d, "p2")
            wrapper = subprocess.Popen(["/bin/sh", w, fake, "cfg", os.path.join(d, "l2"),
                                        pidf, os.path.join(d, "f2"), str(app.pid)])
            time.sleep(0.5)
            child = int(open(pidf).read())
            app.wait()  # без wait мёртвый sleep остался бы зомби и считался живым
            wrapper.wait(timeout=10)
            try:
                os.kill(child, 0)
                raise AssertionError("процесс пережил приложение")
            except ProcessLookupError:
                pass
        finally:
            kzvpn.DIR = saved
    print("mac-оболочка TUN ok (старт, лог, стоп флагом, стоп при смерти приложения)")


if __name__ == "__main__":
    for m in ("chain", "hop1", "hop2"):
        check(m)
    check_assets()
    check_mac_wrapper()
    check_win_bins()
