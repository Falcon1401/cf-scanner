"""
Cloudflare IP Scanner & V2Ray/Xray Tester  v2.0
پشتیبانی از: VLESS · VMess · Trojan · SS
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading, ipaddress, subprocess, socket, json
import os, time, queue, random, re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

# ─── رنگ‌ها  (تم سایبرپانک نئونی) ───────────────────────────────────────────
BG_DARK  = "#05050d"; BG_CARD  = "#0d0f1e"; BG_INPUT = "#13162c"
ACCENT   = "#00f5ff"; ACCENT2  = "#39ff14"; WARN     = "#ff2e63"
TEXT_PRI = "#eafbff"; TEXT_SEC = "#7fa8c9"; BORDER   = "#2a2f55"
NEON_PINK = "#ff2bd1"; NEON_PURPLE = "#9d4dff"


# ════════════════════════════════════════════════════════════════════════════
#  Parser کانفیگ
# ════════════════════════════════════════════════════════════════════════════
class ConfigParser:
    """تبدیل لینک share به JSON قابل استفاده برای Xray"""

    @staticmethod
    def parse(link: str) -> dict:
        link = link.strip()
        if link.startswith("vless://"):
            return ConfigParser._parse_vless(link)
        elif link.startswith("vmess://"):
            return ConfigParser._parse_vmess(link)
        elif link.startswith("trojan://"):
            return ConfigParser._parse_trojan(link)
        else:
            raise ValueError(f"فرمت ناشناخته: {link[:20]}")

    @staticmethod
    def _parse_vless(link: str) -> dict:
        # vless://UUID@host:port?params#name
        rest  = link[8:]
        at    = rest.index("@")
        uuid  = rest[:at]
        rest2 = rest[at+1:]
        q     = rest2.index("?") if "?" in rest2 else len(rest2)
        hp    = rest2[:q]
        # host:port  (IPv6 در براکت)
        if hp.startswith("["):
            br = hp.index("]")
            host = hp[1:br]; port = int(hp[br+2:])
        else:
            parts = hp.rsplit(":", 1)
            host = parts[0]; port = int(parts[1].split("#")[0])

        params = {}
        if "?" in rest2:
            qs = rest2[rest2.index("?")+1:]
            params = ConfigParser._parse_params(qs)

        net      = params.get("type", "tcp")
        security = params.get("security", "none")
        sni      = params.get("sni", host)
        fp       = params.get("fp", "")
        path     = params.get("path", "/")
        hdr_host = params.get("host", host)
        flow     = params.get("flow", "")

        stream = ConfigParser._stream(net, security, sni, fp, path, hdr_host, params)

        return {
            "_meta": {"proto": "vless", "orig_host": host, "orig_port": port},
            "log": {"loglevel": "warning"},
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{"id": uuid, "encryption": "none",
                                   "flow": flow}]
                    }]
                },
                "streamSettings": stream
            }]
        }

    @staticmethod
    def _parse_vmess(link: str) -> dict:
        import base64
        b64 = link[8:].split("#")[0]
        b64 += "=" * (-len(b64) % 4)
        try:
            data = json.loads(base64.b64decode(b64))
        except Exception as e:
            raise ValueError(f"VMess base64 نامعتبر: {e}")

        host = data.get("add", "")
        port = int(data.get("port", 443))
        net  = data.get("net", "tcp")
        tls  = "tls" if data.get("tls") == "tls" else "none"
        sni  = data.get("sni", host)
        path = data.get("path", "/")
        hh   = data.get("host", host)
        fp   = data.get("fp", "")
        params = {}
        stream = ConfigParser._stream(net, tls, sni, fp, path, hh, params)

        return {
            "_meta": {"proto": "vmess", "orig_host": host, "orig_port": port},
            "log": {"loglevel": "warning"},
            "outbounds": [{
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{"id": data.get("id",""),
                                   "alterId": int(data.get("aid", 0)),
                                   "security": data.get("scy", "auto")}]
                    }]
                },
                "streamSettings": stream
            }]
        }

    @staticmethod
    def _parse_trojan(link: str) -> dict:
        rest   = link[9:]
        at     = rest.index("@")
        passwd = rest[:at]
        rest2  = rest[at+1:]
        q      = rest2.index("?") if "?" in rest2 else len(rest2)
        hp     = rest2[:q]
        parts  = hp.rsplit(":", 1)
        host   = parts[0]; port = int(parts[1].split("#")[0])

        params = {}
        if "?" in rest2:
            qs = rest2[rest2.index("?")+1:]
            params = ConfigParser._parse_params(qs)

        net  = params.get("type", "tcp")
        sni  = params.get("sni", host)
        fp   = params.get("fp", "")
        path = params.get("path", "/")
        hh   = params.get("host", host)
        stream = ConfigParser._stream(net, "tls", sni, fp, path, hh, params)

        return {
            "_meta": {"proto": "trojan", "orig_host": host, "orig_port": port},
            "log": {"loglevel": "warning"},
            "outbounds": [{
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host, "port": port,
                        "password": passwd
                    }]
                },
                "streamSettings": stream
            }]
        }

    @staticmethod
    def _stream(net, security, sni, fp, path, host, params):
        ss = {"network": net, "security": security}

        # allowInsecure — هم از insecure هم از allowInsecure می‌خونیم
        allow_insecure = (
            params.get("allowInsecure", "0") == "1" or
            params.get("insecure", "0") == "1"
        )

        if security == "tls":
            tls_cfg = {
                "serverName": sni,
                "allowInsecure": allow_insecure
            }
            if fp:
                tls_cfg["fingerprint"] = fp
            # alpn — مثلاً h2,http/1.1,h3
            alpn_raw = params.get("alpn", "")
            if alpn_raw:
                tls_cfg["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()]
            ss["tlsSettings"] = tls_cfg

        elif security == "reality":
            ss["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp or "chrome",
                "shortId": params.get("sid", ""),
                "publicKey": params.get("pbk", ""),
                "spiderX": params.get("spx", "")
            }

        if net == "ws":
            ss["wsSettings"] = {
                "path": path,
                "headers": {"Host": host}
            }
        elif net == "grpc":
            ss["grpcSettings"] = {"serviceName": params.get("serviceName", path)}
        elif net == "h2":
            ss["httpSettings"] = {"path": path, "host": [host]}
        elif net == "httpupgrade":
            ss["httpupgradeSettings"] = {"path": path, "host": host}
        elif net == "splithttp":
            ss["splithttpSettings"] = {"path": path, "host": host}

        return ss

    @staticmethod
    def inject_ip(cfg: dict, new_ip: str) -> dict:
        """جایگذاری IP جدید در کانفیگ"""
        import copy
        c = copy.deepcopy(cfg)
        for ob in c.get("outbounds", []):
            s = ob.get("settings", {})
            for lst in [s.get("vnext", []), s.get("servers", [])]:
                for srv in lst:
                    srv["address"] = new_ip
        return c

    @staticmethod
    def rebuild_link(orig_link: str, new_ip: str) -> str:
        """
        لینک share (vless/vmess/trojan) اصلی را می‌گیرد و فقط آدرس هاست را
        با IP تمیز جدید جایگزین می‌کند؛ بقیه پارامترها (uuid، پسورد، پورت،
        SNI، path و ...) دقیقاً همان لینک اصلی باقی می‌مانند.
        """
        import base64
        link = orig_link.strip()

        if link.startswith("vmess://"):
            body, _, frag = link.partition("#")
            b64 = body[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64))
            data["add"] = new_ip
            new_b64 = base64.b64encode(
                json.dumps(data, separators=(",", ":")).encode()
            ).decode().rstrip("=")
            return "vmess://" + new_b64 + (("#" + frag) if frag else "")

        # vless:// و trojan:// هر دو ساختار  scheme://userinfo@host:port?query#name  دارند
        if "://" not in link:
            raise ValueError("فرمت لینک ناشناخته است")
        scheme, _, rest = link.partition("://")
        body, _, frag = rest.partition("#")
        if "@" not in body:
            raise ValueError("لینک فاقد بخش userinfo@host است")
        userinfo, _, hp_query = body.partition("@")
        hostport, _, query = hp_query.partition("?")

        if hostport.startswith("["):
            close = hostport.index("]")
            port_part = hostport[close+1:]            # مثلاً ":443"
        elif ":" in hostport:
            port_part = ":" + hostport.rsplit(":", 1)[1]
        else:
            port_part = ""

        new_body = f"{userinfo}@{new_ip}{port_part}"
        if query:
            new_body += "?" + query
        return f"{scheme}://{new_body}" + (("#" + frag) if frag else "")

    @staticmethod
    def summary(cfg: dict) -> str:
        meta  = cfg.get("_meta", {})
        proto = meta.get("proto", "?").upper()
        host  = meta.get("orig_host", "?")
        port  = meta.get("orig_port", "?")
        ob    = cfg.get("outbounds", [{}])[0]
        net   = ob.get("streamSettings", {}).get("network", "?")
        sec   = ob.get("streamSettings", {}).get("security", "none")
        return f"{proto}  •  {host}:{port}  •  {net}/{sec}"

    @staticmethod
    def _parse_params(qs_with_fragment: str) -> dict:
        """
        parse پارامترهای URL — fragment (#name) رو از آخر جدا می‌کنه
        ولی مراقبه که # داخل value های encode نشده رو اشتباه نبره
        """
        # fragment فقط اولین # بعد از ? است
        # ولی چون ممکنه value‌ها # داشته باشن، از urllib استفاده می‌کنیم
        from urllib.parse import parse_qs, urlparse
        # یه URL ساختگی می‌سازیم تا urlparse درست کار کنه
        fake = "x://x?" + qs_with_fragment
        parsed = urlparse(fake)
        params = {}
        for k, v_list in parse_qs(parsed.query, keep_blank_values=True).items():
            params[k] = unquote(v_list[0]) if v_list else ""
        return params
        meta  = cfg.get("_meta", {})
        proto = meta.get("proto", "?").upper()
        host  = meta.get("orig_host", "?")
        port  = meta.get("orig_port", "?")
        ob    = cfg.get("outbounds", [{}])[0]
        net   = ob.get("streamSettings", {}).get("network", "?")
        sec   = ob.get("streamSettings", {}).get("security", "none")
        return f"{proto}  •  {host}:{port}  •  {net}/{sec}"


# ════════════════════════════════════════════════════════════════════════════
#  اپلیکیشن اصلی
# ════════════════════════════════════════════════════════════════════════════
class CFScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CF SCANNER v3.0 // V2Ray-Xray Tester  —  ساخته شده توسط عرشیا کوهیان محمد آبادی")
        self.geometry("1150x780")
        self.minsize(900, 620)
        self.configure(bg=BG_DARK)

        self.result_queue = queue.Queue()
        self.running      = False
        self.results      = []
        self.parsed_cfg   = None   # کانفیگ parse شده

        self._build_ui()
        self._poll_queue()

    # ── UI ───────────────────────────────────────────────────────────────────
    def _build_ui(self):
        hdr = tk.Frame(self, bg=BG_DARK)
        hdr.pack(fill="x", padx=20, pady=(14,0))
        tk.Label(hdr, text="⚡ CF SCANNER", font=("Consolas",20,"bold"),
                 bg=BG_DARK, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text=" // v3.0 — VLESS · VMess · Trojan",
                 font=("Consolas",10), bg=BG_DARK, fg=NEON_PINK).pack(side="left", padx=10)
        tk.Label(hdr, text="⟦ سازنده: عرشیا کوهیان محمد آبادی ⟧",
                 font=("Consolas",8,"bold"), bg=BG_DARK, fg=NEON_PURPLE).pack(side="right", padx=10)
        tk.Frame(self, height=2, bg=NEON_PINK).pack(fill="x", padx=20, pady=(8,0))
        tk.Frame(self, height=1, bg=ACCENT).pack(fill="x", padx=20, pady=(0,8))

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_CARD, foreground=TEXT_SEC,
                        padding=[14,6], font=("Segoe UI",10))
        style.map("TNotebook.Tab",
                  background=[("selected", BG_INPUT)],
                  foreground=[("selected", ACCENT)])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=20, pady=4)

        self.tab_config = tk.Frame(nb, bg=BG_DARK)
        self.tab_ping   = tk.Frame(nb, bg=BG_DARK)
        self.tab_v2ray  = tk.Frame(nb, bg=BG_DARK)
        nb.add(self.tab_config, text="  ⚙  کانفیگ  ")
        nb.add(self.tab_ping,   text="  🌐  تست Ping  ")
        nb.add(self.tab_v2ray,  text="  🔒  تست V2Ray/Xray  ")

        self._build_config_tab()
        self._build_ping_tab()
        self._build_v2ray_tab()

        # Status bar
        self.status_var = tk.StringVar(value="آماده")
        sb = tk.Frame(self, bg=BG_CARD, height=28)
        sb.pack(fill="x", side="bottom")
        tk.Label(sb, textvariable=self.status_var, bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI",9), anchor="w", padx=10).pack(side="left", fill="y")
        tk.Label(sb, text="⟦ عرشیا کوهیان محمد آبادی ⟧",
                 bg=BG_CARD, fg=NEON_PURPLE, font=("Consolas",8), anchor="e",
                 padx=10).pack(side="right", fill="y")
        self.prog_var = tk.DoubleVar()
        ttk.Progressbar(sb, variable=self.prog_var, maximum=100,
                        length=220).pack(side="right", padx=10, pady=4)

    # ════ تب کانفیگ ════
    def _build_config_tab(self):
        p = self.tab_config

        # ── paste لینک ──
        card1 = self._card(p, "📋  لینک کانفیگ  (VLESS / VMess / Trojan)")
        card1.pack(fill="x", padx=12, pady=(12,4))

        tk.Label(card1, text="لینک کانفیگ خود را اینجا paste کنید:",
                 bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI",10)).pack(anchor="w", padx=10, pady=(8,2))

        self.link_text = scrolledtext.ScrolledText(
            card1, height=5, wrap="word",
            bg=BG_INPUT, fg=TEXT_PRI, insertbackground=TEXT_PRI,
            font=("Consolas",9), relief="flat", bd=6)
        self.link_text.pack(fill="x", padx=10, pady=(0,4))
        self.link_text.insert("1.0", "vless://  یا  vmess://  یا  trojan://  را اینجا paste کنید")
        self.link_text.bind("<FocusIn>", self._clear_hint)

        bf = tk.Frame(card1, bg=BG_CARD)
        bf.pack(fill="x", padx=10, pady=(0,10))
        self._btn(bf, "⚡  تجزیه‌ی کانفیگ", self._parse_config, ACCENT2).pack(side="left", padx=(0,8))
        self._btn(bf, "🗑  پاک کردن", lambda: (self.link_text.delete("1.0","end"),
                  self.info_var.set("—")), TEXT_SEC).pack(side="left")

        # ── اطلاعات parse شده ──
        card2 = self._card(p, "✅  اطلاعات کانفیگ")
        card2.pack(fill="x", padx=12, pady=4)

        self.info_var = tk.StringVar(value="هنوز کانفیگی پردازش نشده است")
        tk.Label(card2, textvariable=self.info_var, bg=BG_CARD, fg=ACCENT2,
                 font=("Consolas",11), anchor="w", padx=10).pack(fill="x", pady=(8,4))

        # جدول جزئیات
        detail_f = tk.Frame(card2, bg=BG_CARD)
        detail_f.pack(fill="x", padx=10, pady=(0,10))
        self.detail_labels = {}
        fields = [("پروتکل","proto"), ("سرور اصلی","host"), ("پورت","port"),
                  ("شبکه","net"), ("امنیت","sec"), ("SNI","sni")]
        for i, (lbl, key) in enumerate(fields):
            col = (i % 3) * 2
            tk.Label(detail_f, text=lbl+":", bg=BG_CARD, fg=TEXT_SEC,
                     font=("Segoe UI",9)).grid(row=i//3, column=col, sticky="w", padx=(0,4), pady=2)
            v = tk.StringVar(value="—")
            self.detail_labels[key] = v
            tk.Label(detail_f, textvariable=v, bg=BG_CARD, fg=TEXT_PRI,
                     font=("Consolas",9)).grid(row=i//3, column=col+1, sticky="w", padx=(0,20), pady=2)

        # ── JSON خروجی ──
        card3 = self._card(p, "🔧  JSON تولید شده  (قابل ویرایش)")
        card3.pack(fill="both", expand=True, padx=12, pady=4)

        jbf = tk.Frame(card3, bg=BG_CARD)
        jbf.pack(fill="x", padx=10, pady=(6,2))
        self._btn(jbf, "💾  ذخیره JSON", self._save_json, ACCENT).pack(side="left", padx=(0,8))
        self._btn(jbf, "📂  بارگذاری JSON", self._load_json, TEXT_SEC).pack(side="left")
        self._btn(jbf, "▶  ارسال به تب V2Ray", self._send_to_v2ray, ACCENT2).pack(side="right")

        self.json_text = scrolledtext.ScrolledText(
            card3, height=10, wrap="none",
            bg=BG_INPUT, fg="#c9d1d9", insertbackground=TEXT_PRI,
            font=("Consolas",9), relief="flat", bd=8)
        self.json_text.pack(fill="both", expand=True, padx=10, pady=(0,8))

    # ════ تب Ping ════
    def _build_ping_tab(self):
        p = self.tab_ping
        card = self._card(p, "تنظیمات اسکن")
        card.pack(fill="x", padx=12, pady=(12,4))

        row1 = tk.Frame(card, bg=BG_CARD); row1.pack(fill="x", padx=10, pady=(8,4))
        fields1 = [("رنج IP (CIDR):", "cidr_var", "104.16.0.0/16", 22),
                   ("حداکثر IP:", "max_ip_var", "200", 7),
                   ("Timeout (ms):", "timeout_var", "1000", 7),
                   ("Thread:", "threads_var", "50", 7),
                   ("پورت:", "port_var", "443", 7)]
        for i, (lbl, attr, val, w) in enumerate(fields1):
            tk.Label(row1, text=lbl, bg=BG_CARD, fg=TEXT_SEC,
                     font=("Segoe UI",10)).grid(row=0, column=i*2, sticky="w", padx=(0,4))
            v = tk.StringVar(value=val)
            setattr(self, attr, v)
            tk.Entry(row1, textvariable=v, width=w, bg=BG_INPUT, fg=TEXT_PRI,
                     insertbackground=TEXT_PRI, relief="flat",
                     font=("Consolas",11), bd=6).grid(row=0, column=i*2+1, padx=(0,12))

        # رنج‌های پیش‌فرض کلادفلر — برای دامنه‌های دیگر می‌توانید رنج IP همان سرویس‌دهنده را وارد کنید
        cf_frame = tk.Frame(card, bg=BG_CARD); cf_frame.pack(fill="x", padx=10, pady=(0,4))
        tk.Label(cf_frame, text="رنج‌های آماده کلادفلر:", bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI",9)).pack(side="left", padx=(0,6))
        cf_ranges = ["104.16.0.0/13","172.64.0.0/13","162.158.0.0/15","103.21.244.0/22","141.101.64.0/18"]
        for r in cf_ranges:
            self._btn(cf_frame, r, lambda x=r: self.cidr_var.set(x), TEXT_SEC, (6,2)).pack(side="left", padx=2)

        bf = tk.Frame(card, bg=BG_CARD); bf.pack(fill="x", padx=10, pady=(0,4))
        self._btn(bf, "▶  شروع اسکن", self._start_ping_scan, ACCENT2).pack(side="left", padx=(0,8))
        self._btn(bf, "⏹  توقف", self._stop_scan, WARN).pack(side="left", padx=(0,8))
        self._btn(bf, "🗑  پاک کردن", self._clear_results, TEXT_SEC).pack(side="left", padx=(0,8))
        self._btn(bf, "💾  ذخیره CSV", self._save_results, ACCENT).pack(side="right")

        bf2 = tk.Frame(card, bg=BG_CARD); bf2.pack(fill="x", padx=10, pady=(0,10))
        self._btn(bf2, "💾  ذخیره IP های تمیز", self._save_clean_ips, ACCENT2).pack(side="left", padx=(0,8))
        self._btn(bf2, "📋  کپی کانفیگ برای IP های تمیز", self._copy_configs_for_clean_ips, NEON_PINK).pack(side="left", padx=(0,8))
        self._btn(bf2, "💾  ذخیره کانفیگ‌ها در فایل", self._save_configs_for_clean_ips, NEON_PURPLE).pack(side="left")

        # جدول
        tcard = self._card(p, "نتایج  —  (روی یک IP دوبار کلیک کن تا کانفیگ همان IP کپی شود)")
        tcard.pack(fill="both", expand=True, padx=12, pady=4)
        style = ttk.Style()
        style.configure("Dark.Treeview", background=BG_INPUT, fieldbackground=BG_INPUT,
                        foreground=TEXT_PRI, rowheight=26, font=("Consolas",10))
        style.configure("Dark.Treeview.Heading", background=BG_CARD, foreground=ACCENT,
                        font=("Segoe UI",10,"bold"), relief="flat")
        style.map("Dark.Treeview", background=[("selected","#1f4068")])

        cols = ("rank","ip","ping","status")
        self.tree = ttk.Treeview(tcard, columns=cols, show="headings", style="Dark.Treeview")
        for col, hdr, w in [("rank","#",45),("ip","آدرس IP",160),
                              ("ping","Ping (ms)",110),("status","وضعیت",120)]:
            self.tree.heading(col, text=hdr)
            self.tree.column(col, width=w, anchor="center")
        vsb = ttk.Scrollbar(tcard, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8,0), pady=8)
        vsb.pack(side="right", fill="y", pady=8, padx=(0,8))
        self.tree.tag_configure("good", foreground="#3fb950")
        self.tree.tag_configure("med",  foreground="#d29922")
        self.tree.tag_configure("bad",  foreground="#f85149")
        self.tree.tag_configure("fail", foreground="#484f58")
        self.tree.bind("<Double-1>", self._on_tree_double_click)

    # ════ تب V2Ray ════
    def _build_v2ray_tab(self):
        v = self.tab_v2ray
        top = tk.Frame(v, bg=BG_DARK); top.pack(fill="both", expand=True, padx=12, pady=8)
        top.columnconfigure(0, weight=2); top.columnconfigure(1, weight=1); top.rowconfigure(0, weight=1)

        # چپ: لاگ
        lcrd = self._card(top, "📊  لاگ تست")
        lcrd.grid(row=0, column=0, sticky="nsew", padx=(0,6))
        self.v2_log = scrolledtext.ScrolledText(
            lcrd, wrap="word", bg=BG_INPUT, fg="#c9d1d9",
            insertbackground=TEXT_PRI, font=("Consolas",9), relief="flat", bd=8, state="disabled")
        self.v2_log.pack(fill="both", expand=True, padx=8, pady=8)
        for tag, fg in [("ok","#3fb950"),("fail","#f85149"),("info","#58a6ff"),("warn","#d29922"),("time","#484f58")]:
            self.v2_log.tag_config(tag, foreground=fg)

        # راست: تنظیمات
        rcrd = self._card(top, "⚙  تنظیمات")
        rcrd.grid(row=0, column=1, sticky="nsew", padx=(6,0))

        # وضعیت کانفیگ
        cf_status = self._card(rcrd, "کانفیگ فعال")
        cf_status.pack(fill="x", padx=8, pady=(8,4))
        self.cfg_status_var = tk.StringVar(value="❌  هنوز کانفیگی بارگذاری نشده")
        tk.Label(cf_status, textvariable=self.cfg_status_var, bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI",9), wraplength=200, justify="right").pack(padx=6, pady=6)
        self._btn(cf_status, "⚙  رفتن به تب کانفیگ", lambda: None, ACCENT, (6,3)).pack(pady=(0,6))

        # لیست IP
        ip_crd = self._card(rcrd, "آدرس‌های IP")
        ip_crd.pack(fill="both", expand=True, padx=8, pady=4)
        ib = tk.Frame(ip_crd, bg=BG_CARD); ib.pack(fill="x", padx=6, pady=(6,2))
        self._btn(ib, "🔄 از Ping", self._import_from_ping, ACCENT2).pack(side="left")
        self._btn(ib, "✏ دستی", self._manual_ip_entry, TEXT_SEC).pack(side="left", padx=4)

        self.ip_listbox = tk.Listbox(ip_crd, bg=BG_INPUT, fg=TEXT_PRI,
                                     selectbackground="#1f4068", font=("Consolas",10),
                                     relief="flat", activestyle="none", bd=6)
        self.ip_listbox.pack(fill="both", expand=True, padx=6, pady=(0,6))

        # تنظیمات xray
        xray_crd = self._card(rcrd, "مسیر Xray")
        xray_crd.pack(fill="x", padx=8, pady=4)
        xr = tk.Frame(xray_crd, bg=BG_CARD); xr.pack(fill="x", padx=6, pady=6)
        self.xray_path_var = tk.StringVar(value="xray.exe")
        tk.Entry(xr, textvariable=self.xray_path_var, width=18,
                 bg=BG_INPUT, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                 relief="flat", font=("Consolas",9), bd=4).pack(side="left")
        self._btn(xr, "...", self._browse_xray, TEXT_SEC, (4,4)).pack(side="left", padx=4)

        pr = tk.Frame(xray_crd, bg=BG_CARD); pr.pack(fill="x", padx=6, pady=(0,6))
        tk.Label(pr, text="پورت:", bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI",9)).pack(side="left")
        self.local_port_var = tk.StringVar(value="10808")
        tk.Entry(pr, textvariable=self.local_port_var, width=7, bg=BG_INPUT, fg=TEXT_PRI,
                 insertbackground=TEXT_PRI, relief="flat", font=("Consolas",9), bd=4).pack(side="left", padx=6)
        tk.Label(pr, text="Timeout:", bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI",9)).pack(side="left")
        self.v2_timeout_var = tk.StringVar(value="8")
        tk.Entry(pr, textvariable=self.v2_timeout_var, width=5, bg=BG_INPUT, fg=TEXT_PRI,
                 insertbackground=TEXT_PRI, relief="flat", font=("Consolas",9), bd=4).pack(side="left", padx=4)

        # دامنه تست — برای دامنه‌های غیر کلادفلر یا وقتی SNI با دامنه واقعی فرق دارد
        tdf = tk.Frame(xray_crd, bg=BG_CARD); tdf.pack(fill="x", padx=6, pady=(0,6))
        tk.Label(tdf, text="دامنه تست (اختیاری):", bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI",9)).pack(anchor="w")
        self.test_domain_var = tk.StringVar(value="")
        tk.Entry(tdf, textvariable=self.test_domain_var, bg=BG_INPUT, fg=TEXT_PRI,
                 insertbackground=TEXT_PRI, relief="flat", font=("Consolas",9), bd=4).pack(fill="x", pady=(2,0))
        tk.Label(tdf, text="خالی بماند تا خودکار از SNI کانفیگ خوانده شود",
                 bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI",7)).pack(anchor="w", pady=(2,0))

        # دکمه‌ها
        bb = tk.Frame(rcrd, bg=BG_CARD); bb.pack(fill="x", padx=8, pady=(0,8))
        self._btn(bb, "▶  شروع تست", self._start_v2ray_test, ACCENT2).pack(fill="x", padx=6, pady=2)
        self._btn(bb, "⏹  توقف", self._stop_scan, WARN).pack(fill="x", padx=6, pady=2)
        self._btn(bb, "💾  ذخیره لاگ", self._save_v2ray_results, ACCENT).pack(fill="x", padx=6, pady=2)

    # ── ابزارهای UI ──────────────────────────────────────────────────────────
    def _card(self, parent, title=""):
        return tk.LabelFrame(parent, text=f"  {title}  ", bg=BG_CARD, fg=ACCENT,
                             font=("Segoe UI",10,"bold"), relief="flat", bd=1,
                             highlightbackground=BORDER, highlightthickness=1)

    def _btn(self, parent, text, cmd, color=ACCENT, pad=(6,4)):
        b = tk.Button(parent, text=text, command=cmd, bg=BG_INPUT, fg=color,
                      activebackground=BG_CARD, activeforeground=TEXT_PRI,
                      font=("Segoe UI",9,"bold"), relief="flat", bd=0,
                      cursor="hand2", padx=pad[0], pady=pad[1])
        b.bind("<Enter>", lambda e: b.configure(bg=BORDER))
        b.bind("<Leave>", lambda e: b.configure(bg=BG_INPUT))
        return b

    # ── Parse کانفیگ ─────────────────────────────────────────────────────────
    def _clear_hint(self, e):
        txt = self.link_text.get("1.0","end").strip()
        if "paste" in txt or not txt:
            self.link_text.delete("1.0","end")

    def _parse_config(self):
        link = self.link_text.get("1.0","end").strip()
        if not link or "paste" in link:
            messagebox.showwarning("هشدار", "لطفاً لینک کانفیگ را paste کنید.")
            return
        try:
            cfg = ConfigParser.parse(link)
            cfg["_meta"]["orig_link"] = link
            self.parsed_cfg = cfg
            meta = cfg.get("_meta", {})
            ob   = cfg.get("outbounds",[{}])[0]
            ss   = ob.get("streamSettings", {})

            self.info_var.set("✅  " + ConfigParser.summary(cfg))
            self.detail_labels["proto"].set(meta.get("proto","?").upper())
            self.detail_labels["host"].set(meta.get("orig_host","?"))
            self.detail_labels["port"].set(str(meta.get("orig_port","?")))
            self.detail_labels["net"].set(ss.get("network","?"))
            self.detail_labels["sec"].set(ss.get("security","none"))
            sni_cfg = ss.get("tlsSettings", ss.get("realitySettings",{}))
            self.detail_labels["sni"].set(sni_cfg.get("serverName","—"))

            # نمایش JSON
            out = {k:v for k,v in cfg.items() if k != "_meta"}
            self.json_text.delete("1.0","end")
            self.json_text.insert("1.0", json.dumps(out, indent=2, ensure_ascii=False))

            self.cfg_status_var.set(f"✅  {meta.get('proto','?').upper()}  •  {meta.get('orig_host','?')}")
            self.status_var.set(f"کانفیگ با موفقیت پردازش شد:  {ConfigParser.summary(cfg)}")
        except Exception as ex:
            messagebox.showerror("خطای parse", str(ex))

    def _save_json(self):
        if not self.parsed_cfg:
            messagebox.showwarning("هشدار","ابتدا یک کانفیگ را پردازش کنید.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
               filetypes=[("JSON","*.json"),("All","*.*")], title="ذخیره JSON")
        if not path: return
        out = {k:v for k,v in self.parsed_cfg.items() if k != "_meta"}
        with open(path,"w",encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("ذخیره شد", path)

    def _load_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
        if not path: return
        with open(path,"r",encoding="utf-8") as f:
            data = f.read()
        try:
            cfg = json.loads(data)
            cfg["_meta"] = {"proto":"json","orig_host":"loaded","orig_port":0}
            self.parsed_cfg = cfg
            self.json_text.delete("1.0","end")
            self.json_text.insert("1.0", data)
            self.info_var.set("✅  کانفیگ از فایل JSON بارگذاری شد")
            self.cfg_status_var.set("✅  JSON بارگذاری شد")
        except Exception as ex:
            messagebox.showerror("خطا", str(ex))

    def _send_to_v2ray(self):
        if not self.parsed_cfg:
            messagebox.showwarning("هشدار","ابتدا کانفیگ را پردازش کنید.")
            return
        messagebox.showinfo("آماده",
            "کانفیگ آماده است.\nبه تب «تست V2Ray/Xray» برو و شروع کن.")

    # ── Ping scan ────────────────────────────────────────────────────────────
    def _start_ping_scan(self):
        if self.running: return
        try:
            net     = ipaddress.ip_network(self.cidr_var.get().strip(), strict=False)
            max_ip  = int(self.max_ip_var.get())
            timeout = int(self.timeout_var.get())
            threads = int(self.threads_var.get())
            port    = int(self.port_var.get())
        except Exception as ex:
            messagebox.showerror("خطا", str(ex)); return

        all_ips = [str(ip) for ip in net.hosts()]
        if len(all_ips) > max_ip:
            random.shuffle(all_ips)
            all_ips = all_ips[:max_ip]

        self.running = True; self.results = []
        self._clear_results(); self.prog_var.set(0)
        self.status_var.set(f"اسکن {len(all_ips)} IP ...")
        threading.Thread(target=self._ping_worker,
                         args=(all_ips, timeout, threads, port), daemon=True).start()

    def _ping_worker(self, ips, timeout_ms, max_threads, port):
        sem = threading.Semaphore(max_threads)
        lock = threading.Lock(); done = [0]; total = len(ips)
        def test(ip):
            if not self.running: return
            with sem:
                t = time.time()
                ok = self._tcp_ping(ip, port, timeout_ms/1000)
                ms = int((time.time()-t)*1000) if ok else None
                with lock:
                    done[0] += 1
                    self.result_queue.put(("ping_result", ip, ms, done[0]/total*100))
        ts = [threading.Thread(target=test, args=(ip,), daemon=True) for ip in ips]
        for t in ts: t.start()
        for t in ts: t.join()
        self.result_queue.put(("ping_done", None, None, 100))

    @staticmethod
    def _tcp_ping(ip, port, timeout):
        try:
            s = socket.socket(); s.settimeout(timeout)
            s.connect((ip, port)); s.close(); return True
        except: return False

    # ── V2Ray test ───────────────────────────────────────────────────────────
    def _start_v2ray_test(self):
        if self.running: return
        if not self.parsed_cfg:
            messagebox.showwarning("هشدار","ابتدا در تب «کانفیگ» لینک خود را پردازش کنید.")
            return
        ips = list(self.ip_listbox.get(0,"end"))
        if not ips:
            messagebox.showwarning("هشدار","لطفاً IP هایی برای تست وارد کنید.")
            return

        xray = self.xray_path_var.get().strip()
        if not os.path.isfile(xray):
            messagebox.showerror("خطا",
                f"فایل xray پیدا نشد:\n{xray}\n\n"
                "لطفاً مسیر xray.exe را با دکمه «...» انتخاب کنید.")
            return

        try:
            timeout = int(self.v2_timeout_var.get())
            lport   = int(self.local_port_var.get())
        except:
            messagebox.showerror("خطا","پورت/timeout نامعتبر"); return

        # بررسی آزاد بودن پورت
        if not self._port_is_free(lport):
            messagebox.showerror("خطا",
                f"پورت {lport} در حال استفاده است.\n"
                "یک پورت دیگر انتخاب کنید یا برنامه‌ای که روی آن پورت هست ببندید.")
            return

        self.running = True
        self._v2_log("info", f"▶  شروع تست {len(ips)} IP با Xray\n")
        self._v2_log("info", f"   پورت محلی: {lport}  |  timeout: {timeout}s\n\n")
        self.prog_var.set(0)
        threading.Thread(target=self._v2ray_worker,
                         args=(ips, lport, timeout), daemon=True).start()

    @staticmethod
    def _port_is_free(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            return False

    @staticmethod
    def _find_free_port(base):
        """یک پورت آزاد پیدا می‌کند از base به بالا"""
        for p in range(base, base + 200):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(("127.0.0.1", p))
                s.close()
                return p
            except OSError:
                continue
        return None

    def _v2ray_worker(self, ips, base_port, timeout):
        total = len(ips)
        good  = []
        used_port = base_port
        for idx, ip in enumerate(ips, 1):
            if not self.running:
                break
            self.result_queue.put(("v2log","info", f"[{idx}/{total}]  تست  {ip} ...\n"))

            # پورت آزاد پیدا می‌کنیم (از جایی که قبلاً بودیم ادامه می‌دیم)
            port = self._find_free_port(used_port)
            if port is None:
                self.result_queue.put(("v2log","warn","  ⚠  پورت آزاد پیدا نشد\n"))
                continue

            ok, ms, detail = self._test_with_xray(ip, port, timeout)
            used_port = port + 1   # دفعه بعد از پورت بالاتر شروع کن
            pct = idx / total * 100

            if ok:
                good.append((ip, ms))
                self.result_queue.put(("v2log","ok",   f"  ✔  {ip}  –  {ms} ms\n"))
            else:
                self.result_queue.put(("v2log","fail", f"  ✘  {ip}  –  {detail}\n"))

            self.result_queue.put(("v2prog", None, None, pct))

        self.result_queue.put(("v2done", good, None, 100))

    def _test_with_xray(self, ip, local_port, timeout):
        """
        ۱) کانفیگ با IP جدید می‌سازیم
        ۲) xray رو روی پورت socks5 محلی اجرا می‌کنیم
        ۳) منتظر می‌مونیم xray listen کنه (poll می‌کنیم)
        ۴) از طریق socks5 یه HTTP request می‌زنیم
        ۵) xray رو می‌کشیم و فایل موقت رو پاک می‌کنیم
        """
        import tempfile, sys

        # ── ساخت کانفیگ ──
        cfg  = ConfigParser.inject_ip(self.parsed_cfg, ip)
        cfg2 = {k: v for k, v in cfg.items() if k != "_meta"}

        # inbound socks5 محلی
        cfg2["inbounds"] = [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "sniffing": {"enabled": False}
        }]

        # routing صریح: همه ترافیک → outbound اصلی
        # بدون این، Xray ترافیک رو به جایی نمی‌فرسته
        cfg2["routing"] = {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}
            ]
        }

        # tag اضافه کردن به outbound
        if cfg2.get("outbounds"):
            cfg2["outbounds"][0]["tag"] = "proxy"

        cfg2["log"] = {"loglevel": "none"}   # لاگ xray رو خاموش می‌کنیم

        # فایل موقت — کراس‌پلتفرم (ویندوز + لینوکس)
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(cfg2, tmp, ensure_ascii=False)
        tmp.close()
        cfg_file = tmp.name

        proc = None
        try:
            xray = self.xray_path_var.get().strip()

            # روی ویندوز: مخفی کردن پنجره cmd
            kwargs = {}
            if sys.platform == "win32":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
                kwargs["startupinfo"] = si
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

            proc = subprocess.Popen(
                [xray, "run", "-config", cfg_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **kwargs
            )

            # ── منتظر می‌مونیم xray listen کنه ──
            ready = False
            deadline = time.time() + 8   # حداکثر ۸ ثانیه صبر
            while time.time() < deadline:
                if proc.poll() is not None:
                    # xray بلافاصله crash کرد
                    err = proc.stderr.read().decode("utf-8","ignore")[:200]
                    return False, 0, f"xray crash: {err.strip()}"
                # بررسی اینکه پورت باز شده
                try:
                    s = socket.socket()
                    s.settimeout(0.3)
                    s.connect(("127.0.0.1", local_port))
                    s.close()
                    ready = True
                    break
                except:
                    time.sleep(0.2)

            if not ready:
                return False, 0, "xray راه‌اندازی نشد (timeout)"

            # کمی صبر می‌کنیم تا xray کاملاً آماده بشه
            # (پورت باز شده ولی ممکنه هنوز SOCKS5 آماده نباشه)
            time.sleep(0.4)

            # ── تست HTTP از طریق socks5 ──
            # اول دامنه‌ای که کاربر دستی وارد کرده، بعد SNI کانفیگ، در نهایت هاست اصلی
            meta = self.parsed_cfg.get("_meta", {})
            ob   = self.parsed_cfg.get("outbounds", [{}])[0]
            ss   = ob.get("streamSettings", {})
            tls_cfg = ss.get("tlsSettings", ss.get("realitySettings", {}))
            manual_domain = getattr(self, "test_domain_var", None)
            manual_domain = manual_domain.get().strip() if manual_domain else ""
            test_host = manual_domain or tls_cfg.get("serverName", "") or meta.get("orig_host", "")
            test_port = int(meta.get("orig_port", 443))

            t0 = time.time()
            ok, detail = self._socks5_http_test("127.0.0.1", local_port,
                                                 test_host, test_port, timeout)
            ms = int((time.time() - t0) * 1000)
            return ok, ms, detail

        except FileNotFoundError:
            return False, 0, "xray.exe پیدا نشد"
        except Exception as ex:
            return False, 0, str(ex)[:60]
        finally:
            # ── حتماً xray کشته می‌شه (ویندوز نیاز به kill داره نه terminate) ──
            if proc:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except:
                    pass
            try:
                os.unlink(cfg_file)
            except:
                pass

    @staticmethod
    def _socks5_http_test(proxy_host, proxy_port, target_host, target_port, timeout):
        """
        تست از طریق SOCKS5 — Xray خودش TLS رو handle می‌کنه
        ما فقط باید plain HTTP بزنیم (نه TLS مجدد)
        """
        import struct

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((proxy_host, proxy_port))

            # ── SOCKS5 handshake ──
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
                s.close()
                return False, "SOCKS5 auth رد شد"

            # connect request به target
            host_bytes = target_host.encode()
            req = (b"\x05\x01\x00\x03" +
                   bytes([len(host_bytes)]) +
                   host_bytes +
                   struct.pack(">H", target_port))
            s.sendall(req)

            # خواندن جواب SOCKS5 (ممکنه بیشتر از 10 بایت باشه)
            resp2 = b""
            while len(resp2) < 4:
                chunk = s.recv(16)
                if not chunk:
                    break
                resp2 += chunk
            # بقیه response رو بخون (اگه ATYP=1 → 6 بایت بیشتر، ATYP=3 → متغیر)
            if len(resp2) >= 4:
                atyp = resp2[3]
                if atyp == 1:    # IPv4
                    remaining = 4 + 2 - (len(resp2) - 4)
                    if remaining > 0: s.recv(remaining)
                elif atyp == 4:  # IPv6
                    remaining = 16 + 2 - (len(resp2) - 4)
                    if remaining > 0: s.recv(remaining)

            if len(resp2) < 2 or resp2[1] != 0:
                s.close()
                code = resp2[1] if len(resp2) > 1 else -1
                return False, f"SOCKS5 connect رد شد (کد {code})"

            # ── HTTP request — بدون TLS چون Xray خودش handle کرده ──
            # درخواست به مسیر ریشه می‌زنیم تا برای هر دامنه‌ای (نه فقط کلادفلر) کار کند
            req_http = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"Connection: close\r\n"
                f"User-Agent: Mozilla/5.0\r\n\r\n"
            ).encode()
            s.sendall(req_http)

            # خواندن response
            data = b""
            while len(data) < 1024:
                try:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n" in data:
                        break
                except socket.timeout:
                    break
            s.close()

            if not data:
                return False, "پاسخی دریافت نشد"

            first_line = data.split(b"\r\n")[0].decode("utf-8", "ignore")
            if "HTTP/" in first_line:
                return True, "OK"
            return False, first_line[:60] if first_line else "پاسخ نامعتبر"

        except socket.timeout:
            return False, "timeout"
        except ConnectionRefusedError:
            return False, "connection refused"
        except Exception as ex:
            return False, str(ex)[:60]

    # ── Poll queue ────────────────────────────────────────────────────────────
    def _poll_queue(self):
        try:
            while True:
                msg = self.result_queue.get_nowait()
                k = msg[0]
                if k == "ping_result":
                    _, ip, ms, pct = msg
                    self._add_ping_row(ip, ms)
                    self.prog_var.set(pct)
                    self.status_var.set(f"اسکن ...  {int(pct)}%")
                elif k == "ping_done":
                    self.running = False; self.prog_var.set(100)
                    g = sum(1 for _,ms,_ in self.results if ms is not None)
                    self.status_var.set(f"تمام.  {g} IP فعال از {len(self.results)}")
                    self._sort_results()
                elif k == "v2log":
                    self._v2_log(msg[1], msg[2])
                elif k == "v2prog":
                    self.prog_var.set(msg[3])
                elif k == "v2done":
                    self.running = False; self.prog_var.set(100)
                    good = msg[1]
                    self._v2_log("info", f"\n══ تمام.  {len(good)} IP موفق ══\n")
                    for ip, ms in sorted(good, key=lambda x:x[1]):
                        self._v2_log("ok", f"  ✔  {ip}  –  {ms} ms\n")
        except queue.Empty: pass
        self.after(80, self._poll_queue)

    # ── کمکی‌ها ───────────────────────────────────────────────────────────────
    def _add_ping_row(self, ip, ms):
        self.results.append((ip, ms, "فعال" if ms else "قطع"))
        rank = len(self.results)
        if ms is None: tag, lbl = "fail", "—"
        elif ms < 150: tag, lbl = "good", str(ms)
        elif ms < 400: tag, lbl = "med",  str(ms)
        else:          tag, lbl = "bad",  str(ms)
        self.tree.insert("","end",
            values=(rank, ip, lbl, "✔ فعال" if ms else "✘ قطع"), tags=(tag,))

    def _sort_results(self):
        rows = [(self.tree.set(i,"ping"), i) for i in self.tree.get_children()]
        rows.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 99999)
        for new_rank, (_, item) in enumerate(rows, 1):
            self.tree.set(item,"rank",new_rank)
            self.tree.move(item,"",new_rank-1)

    def _v2_log(self, tag, text):
        self.v2_log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.v2_log.insert("end", f"[{ts}] ", "time")
        self.v2_log.insert("end", text, tag)
        self.v2_log.see("end")
        self.v2_log.configure(state="disabled")

    def _stop_scan(self):
        self.running = False
        self.status_var.set("توقف داده شد.")

    def _clear_results(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        self.results = []

    def _save_results(self):
        if not self.results: return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
               filetypes=[("CSV","*.csv"),("Text","*.txt")])
        if not path: return
        with open(path,"w",encoding="utf-8") as f:
            f.write("IP,Ping(ms),Status\n")
            for ip,ms,st in sorted(self.results, key=lambda x:x[1] or 99999):
                f.write(f"{ip},{ms or ''},{ st}\n")
        messagebox.showinfo("ذخیره شد", path)

    # ── کمکی: لیست IP های تمیز (فعال) به ترتیب کمترین پینگ ──────────────────
    def _get_clean_ips(self):
        return sorted(
            [(ip, ms) for ip, ms, _ in self.results if ms is not None],
            key=lambda x: x[1]
        )

    def _save_clean_ips(self):
        clean = self._get_clean_ips()
        if not clean:
            messagebox.showwarning("هشدار", "هیچ IP تمیزی پیدا نشد. اول اسکن Ping را اجرا کن.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
               filetypes=[("Text","*.txt")], title="ذخیره IP های تمیز")
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            for ip, _ in clean:
                f.write(ip + "\n")
        messagebox.showinfo("ذخیره شد", f"{len(clean)} IP تمیز در فایل ذخیره شد:\n{path}")

    # ── کمکی: ساخت لیست کانفیگ برای هر IP تمیز، روی همان کانفیگی که در تب «کانفیگ» وارد شده ──
    def _build_configs_for_clean_ips(self):
        """
        برمی‌گرداند: (لیست لینک‌های ساخته‌شده, پیام خطا یا None)
        """
        if not self.parsed_cfg:
            return None, "ابتدا در تب «کانفیگ» یک لینک را paste و پردازش کن."
        orig_link = self.parsed_cfg.get("_meta", {}).get("orig_link")
        if not orig_link:
            return None, ("این قابلیت فقط برای لینک‌های vless/vmess/trojan کار می‌کند "
                          "(نه برای JSON بارگذاری‌شده).\nلطفاً لینک کانفیگ را در تب «کانفیگ» paste کن.")
        clean = self._get_clean_ips()
        if not clean:
            return None, "هیچ IP تمیزی پیدا نشد. اول اسکن Ping را اجرا کن."

        links = []
        for ip, ms in clean:
            try:
                links.append(ConfigParser.rebuild_link(orig_link, ip))
            except Exception:
                continue
        if not links:
            return None, "ساخت کانفیگ برای IP ها با خطا مواجه شد."
        return links, None

    def _copy_configs_for_clean_ips(self):
        links, err = self._build_configs_for_clean_ips()
        if err:
            messagebox.showwarning("هشدار", err)
            return
        blob = "\n".join(links)
        self.clipboard_clear()
        self.clipboard_append(blob)
        self.update()
        self.status_var.set(f"✅  {len(links)} کانفیگ با IP های تمیز در کلیپ‌بورد کپی شد")
        messagebox.showinfo("کپی شد", f"{len(links)} کانفیگ ساخته شد و در کلیپ‌بورد کپی شد.")

    def _save_configs_for_clean_ips(self):
        links, err = self._build_configs_for_clean_ips()
        if err:
            messagebox.showwarning("هشدار", err)
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
               filetypes=[("Text","*.txt")], title="ذخیره کانفیگ‌ها")
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(links) + "\n")
        self.status_var.set(f"✅  {len(links)} کانفیگ ذخیره شد")
        messagebox.showinfo("ذخیره شد", f"{len(links)} کانفیگ در فایل ذخیره شد:\n{path}")

    # ── دوبار کلیک روی یک ردیف IP → کپی کانفیگ همان IP در کلیپ‌بورد ────────
    def _on_tree_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item: return
        vals = self.tree.item(item, "values")
        if not vals or len(vals) < 2: return
        ip = vals[1]

        if not self.parsed_cfg:
            # کانفیگی پردازش نشده — فقط خود IP را کپی کن
            self.clipboard_clear(); self.clipboard_append(ip); self.update()
            self.status_var.set(f"✅  IP  {ip}  کپی شد (برای کپی کانفیگ کامل، اول در تب «کانفیگ» لینک را پردازش کن)")
            return

        orig_link = self.parsed_cfg.get("_meta", {}).get("orig_link")
        if not orig_link:
            self.clipboard_clear(); self.clipboard_append(ip); self.update()
            self.status_var.set(f"✅  IP  {ip}  کپی شد (کانفیگ JSON بارگذاری‌شده قابل بازسازی به لینک نیست)")
            return

        try:
            link = ConfigParser.rebuild_link(orig_link, ip)
        except Exception as ex:
            messagebox.showerror("خطا", f"ساخت کانفیگ برای این IP ممکن نشد:\n{ex}")
            return

        self.clipboard_clear(); self.clipboard_append(link); self.update()
        self.status_var.set(f"✅  کانفیگ IP  {ip}  کپی شد در کلیپ‌بورد")

    def _save_v2ray_results(self):
        txt = self.v2_log.get("1.0","end")
        path = filedialog.asksaveasfilename(defaultextension=".txt",
               filetypes=[("Text","*.txt")])
        if not path: return
        with open(path,"w",encoding="utf-8") as f: f.write(txt)
        messagebox.showinfo("ذخیره شد", path)

    def _import_from_ping(self):
        good = [(ip,ms) for ip,ms,_ in self.results if ms is not None]
        if not good:
            messagebox.showwarning("هشدار","ابتدا اسکن Ping انجام بده."); return
        good.sort(key=lambda x:x[1])
        self.ip_listbox.delete(0,"end")
        for ip,_ in good: self.ip_listbox.insert("end", ip)
        messagebox.showinfo("وارد شد", f"{len(good)} IP وارد شد.")

    def _manual_ip_entry(self):
        win = tk.Toplevel(self, bg=BG_DARK)
        win.title("وارد کردن IP"); win.geometry("320x280"); win.grab_set()
        tk.Label(win, text="هر خط یک IP:", bg=BG_DARK, fg=TEXT_PRI,
                 font=("Segoe UI",10)).pack(padx=10,pady=8)
        txt = scrolledtext.ScrolledText(win, bg=BG_INPUT, fg=TEXT_PRI,
                                        font=("Consolas",10), relief="flat", bd=6)
        txt.pack(fill="both",expand=True,padx=10)
        txt.insert("1.0", "\n".join(self.ip_listbox.get(0,"end")))
        def ok():
            lines = [l.strip() for l in txt.get("1.0","end").splitlines() if l.strip()]
            self.ip_listbox.delete(0,"end")
            for ln in lines:
                try: ipaddress.ip_address(ln); self.ip_listbox.insert("end",ln)
                except: pass
            win.destroy()
        self._btn(win,"✔  تأیید",ok,ACCENT2,(10,5)).pack(pady=8)

    def _browse_xray(self):
        path = filedialog.askopenfilename(filetypes=[("Executable","*.exe xray"),("All","*.*")])
        if path: self.xray_path_var.set(path)


if __name__ == "__main__":
    CFScanner().mainloop()
