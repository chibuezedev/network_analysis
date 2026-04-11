import logging
import random
import socket
import threading
import time
from collections import defaultdict
from typing import Callable, Dict, Optional

import numpy as np
import requests

logger = logging.getLogger(__name__)

ML_API_URL = "http://127.0.0.1:8000/predict"

ATTACK_TYPES = [
    "Benign",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
]


def _random_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _get_host_info():
    try:
        from scapy.all import conf, get_if_hwaddr

        ip = socket.gethostbyname(socket.gethostname())
        mac = get_if_hwaddr(conf.iface).lower()
        return ip, mac
    except Exception:
        ip = socket.gethostbyname(socket.gethostname())
        return ip, "00:00:00:00:00:00"


def _list_interfaces():
    """Return list of (name, ip, description) for all active interfaces."""
    ifaces = []
    try:
        from scapy.all import get_if_addr, get_if_list

        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0":
                    ifaces.append((iface, ip))
            except Exception:
                pass
    except Exception:
        pass
    return ifaces


def _best_interface():
    """
    Pick the best interface for monitoring.
    Prefers interfaces on 192.168.x.x or 172.x.x.x subnets (LAN/hotspot).
    Falls back to scapy default.
    """
    try:
        from scapy.all import conf

        ifaces = _list_interfaces()
        for name, ip in ifaces:
            if (
                ip.startswith("192.168.")
                or ip.startswith("10.")
                or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
            ):
                logger.info(f"Auto-selected interface: {name} ({ip})")
                return name
        logger.info(f"Using default interface: {conf.iface}")
        return conf.iface
    except Exception:
        return None


class RealCapture:
    def __init__(
        self,
        on_device: Callable[[str, str], None],
        on_alert: Callable[[str, str, str, float], None],
    ):
        self.on_device = on_device
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._mac_table: Dict[str, str] = {}
        self._flows: Dict = {}
        self._arp_devices: Dict[str, float] = {}
        self._arp_analyzed: Dict[str, float] = {}
        self.FLOW_TIMEOUT = 10
        self.ARP_ANALYZE_INTERVAL = 15
        self.ARP_COOLDOWN = 60
        self._analyzed_flows: set = set()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _capture_loop(self):
        from scapy.all import sniff

        iface = _best_interface()
        logger.info(f"Sniffing on: {iface} (promiscuous)")

        def handler(pkt):
            if not self._running:
                return
            self._process_arp(pkt)
            self._process_dhcp(pkt)
            self._process_packet(pkt)
            self._cleanup_flows()
            self._analyze_arp_only_devices()

        sniff(
            iface=iface,
            prn=handler,
            store=False,
            promisc=True,
            stop_filter=lambda _: not self._running,
        )

    def _process_dhcp(self, pkt):
        """
        Snoop DHCP ACK packets to learn phone IP→MAC mappings.
        DHCP happens before ARP — phones reveal their MAC here first.
        Works even under NAT since DHCP is layer-2 broadcast.
        """
        try:
            from scapy.all import BOOTP, DHCP, Ether

            if DHCP not in pkt:
                return
            opts = dict(pkt[DHCP].options) if hasattr(pkt[DHCP], "options") else {}  # noqa: F841
            msg_type = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    msg_type = opt[1]
            if msg_type not in (2, 5):
                return
            ip = pkt[BOOTP].yiaddr
            mac = pkt[Ether].src.lower()
            if ip and ip != "0.0.0.0" and mac != "ff:ff:ff:ff:ff:ff":
                logger.info(f"DHCP: assigned {ip} to {mac}")
                self._mac_table[ip] = mac
                self._arp_devices[ip] = time.time()
                self.on_device(ip, mac)
        except Exception as e:
            logger.debug(f"DHCP snoop error: {e}")

    def _process_arp(self, pkt):
        try:
            from scapy.all import ARP

            if ARP in pkt:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc.lower()
                if ip == "0.0.0.0" or mac == "ff:ff:ff:ff:ff:ff":
                    return
                self._mac_table[ip] = mac
                self._arp_devices[ip] = time.time()
                self.on_device(ip, mac)
                logger.debug(f"ARP: {ip} / {mac}")
        except Exception as e:
            logger.debug(f"ARP error: {e}")

    def _process_packet(self, pkt):
        from scapy.all import IP, TCP, UDP

        if IP not in pkt:
            return
        key = self._flow_key(pkt)
        if not key:
            return

        now = time.time()
        ip_layer = pkt[IP]
        proto_layer = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None

        src_ip = ip_layer.src
        is_local = (
            src_ip.startswith("192.168.")
            or src_ip.startswith("10.")
            or (src_ip.startswith("172.") and 16 <= int(src_ip.split(".")[1]) <= 31)
        )
        if not is_local:
            return
        if src_ip not in self._mac_table:
            self._mac_table[src_ip] = "unknown"
        self.on_device(src_ip, self._mac_table[src_ip])

        dst_ip = ip_layer.dst
        dst_is_local = (
            dst_ip.startswith("192.168.")
            or dst_ip.startswith("10.")
            or (dst_ip.startswith("172.") and 16 <= int(dst_ip.split(".")[1]) <= 31)
        )
        if dst_is_local and dst_ip in self._mac_table:
            self.on_device(dst_ip, self._mac_table[dst_ip])

        if key not in self._flows:
            self._flows[key] = {
                "start_time": now,
                "last_seen": now,
                "fwd_packets": 0,
                "bwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "src": key[0],
                "dst": key[1],
                "fwd_pkt_lengths": [],
                "bwd_pkt_lengths": [],
                "fwd_iats": [],
                "bwd_iats": [],
                "last_pkt_time": None,
                "fwd_flags": defaultdict(int),
                "bwd_flags": defaultdict(int),
                "fwd_seg_sizes": [],
                "bwd_seg_sizes": [],
                "subflow_fwd_pkts": 0,
                "subflow_bwd_pkts": 0,
                "subflow_fwd_bytes": 0,
                "subflow_bwd_bytes": 0,
                "fwd_init_win": 0,
                "bwd_init_win": 0,
                "active_periods": [],
                "idle_periods": [],
            }

        flow = self._flows[key]
        flow["last_seen"] = now
        size = len(pkt)

        direction = "fwd" if ip_layer.src == flow["src"] else "bwd"
        if direction == "fwd":
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += size
            flow["fwd_pkt_lengths"].append(size)
            flow["fwd_seg_sizes"].append(size)
            flow["subflow_fwd_pkts"] += 1
            flow["subflow_fwd_bytes"] += size
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += size
            flow["bwd_pkt_lengths"].append(size)
            flow["bwd_seg_sizes"].append(size)
            flow["subflow_bwd_pkts"] += 1
            flow["subflow_bwd_bytes"] += size

        if flow["last_pkt_time"] is not None:
            iat = now - flow["last_pkt_time"]
            if direction == "fwd":
                flow["fwd_iats"].append(iat)
            else:
                flow["bwd_iats"].append(iat)
            flow["active_periods"].append(iat)
            if iat > 1:
                flow["idle_periods"].append(iat)
        flow["last_pkt_time"] = now

        if TCP in pkt and proto_layer:
            for flag in ["F", "S", "R", "P", "A", "U", "E", "C"]:
                if getattr(proto_layer.flags, flag, 0):
                    if direction == "fwd":
                        flow["fwd_flags"][flag] += 1
                    else:
                        flow["bwd_flags"][flag] += 1
            if flow["fwd_init_win"] == 0 and direction == "fwd":
                flow["fwd_init_win"] = proto_layer.window
            if flow["bwd_init_win"] == 0 and direction == "bwd":
                flow["bwd_init_win"] = proto_layer.window

    def _analyze_arp_only_devices(self):
        """
        Phones visible only via ARP (NAT'd through hotspot host).
        Sends a synthesized feature vector once per cooldown period.
        """
        now = time.time()
        for ip, last_seen in list(self._arp_devices.items()):
            if now - last_seen > self.ARP_ANALYZE_INTERVAL:
                continue
            if any(k[0] == ip for k in self._flows):
                continue
            last_analysis = self._arp_analyzed.get(ip, 0)
            if now - last_analysis < self.ARP_COOLDOWN:
                continue
            self._arp_analyzed[ip] = now
            mac = self._mac_table.get(ip, "unknown")
            features = [0.0] * 76
            features[1] = 1.0
            features[14] = 1.0
            logger.info(f"ARP-only device {ip} ({mac}) — sending to model")
            self._send_to_model(
                features, {"src": ip, "dst": "network"}, mac_override=mac
            )

    def _extract_features(self, flow):
        dur = flow["last_seen"] - flow["start_time"] + 1e-6
        fwd_len = (
            np.array(flow["fwd_pkt_lengths"])
            if flow["fwd_pkt_lengths"]
            else np.zeros(1)
        )
        bwd_len = (
            np.array(flow["bwd_pkt_lengths"])
            if flow["bwd_pkt_lengths"]
            else np.zeros(1)
        )
        fwd_iat = np.array(flow["fwd_iats"]) if flow["fwd_iats"] else np.zeros(1)
        bwd_iat = np.array(flow["bwd_iats"]) if flow["bwd_iats"] else np.zeros(1)
        active = (
            np.array(flow["active_periods"]) if flow["active_periods"] else np.zeros(1)
        )
        idle = np.array(flow["idle_periods"]) if flow["idle_periods"] else np.zeros(1)
        fwd_seg = (
            np.array(flow["fwd_seg_sizes"]) if flow["fwd_seg_sizes"] else np.zeros(1)
        )
        bwd_seg = (
            np.array(flow["bwd_seg_sizes"]) if flow["bwd_seg_sizes"] else np.zeros(1)
        )

        features = [0.0] * 76
        features[0] = dur
        features[1] = flow["fwd_packets"]
        features[2] = flow["bwd_packets"]
        features[3] = flow["fwd_bytes"]
        features[4] = flow["bwd_bytes"]
        features[5] = fwd_len.max()
        features[6] = fwd_len.min()
        features[7] = fwd_len.mean()
        features[8] = fwd_len.std()
        features[9] = bwd_len.max()
        features[10] = bwd_len.min()
        features[11] = bwd_len.mean()
        features[12] = bwd_len.std()
        features[13] = (flow["fwd_bytes"] + flow["bwd_bytes"]) / dur
        features[14] = (flow["fwd_packets"] + flow["bwd_packets"]) / dur
        features[15] = fwd_iat.mean()
        features[16] = fwd_iat.std()
        features[17] = fwd_iat.max()
        features[18] = fwd_iat.min()
        features[19] = fwd_iat.sum()
        features[20] = bwd_iat.mean()
        features[21] = bwd_iat.std()
        features[22] = bwd_iat.max()
        features[23] = bwd_iat.min()
        features[24] = bwd_iat.sum()

        flags_order = ["F", "S", "R", "P", "A", "U", "E", "C"]
        for i, flag in enumerate(flags_order):
            features[25 + i] = flow["fwd_flags"].get(flag, 0)
            features[33 + i] = flow["bwd_flags"].get(flag, 0)

        features[41] = flow["fwd_packets"] / dur
        features[42] = flow["bwd_packets"] / dur

        all_len = np.concatenate([fwd_len, bwd_len])
        features[43] = all_len.min()
        features[44] = all_len.max()
        features[45] = all_len.mean()
        features[46] = all_len.std()
        features[47] = np.var(all_len)
        features[48] = (
            (flow["bwd_bytes"] / flow["fwd_bytes"]) if flow["fwd_bytes"] > 0 else 0
        )
        features[49] = all_len.mean()
        features[50] = fwd_seg.mean()
        features[51] = bwd_seg.mean()
        features[52] = flow["fwd_bytes"] / max(1, flow["subflow_fwd_pkts"])
        features[53] = flow["fwd_packets"] / max(1, flow["subflow_fwd_pkts"])
        features[54] = features[52] / dur
        features[55] = flow["bwd_bytes"] / max(1, flow["subflow_bwd_pkts"])
        features[56] = flow["bwd_packets"] / max(1, flow["subflow_bwd_pkts"])
        features[57] = features[55] / dur
        features[58] = flow["subflow_fwd_pkts"]
        features[59] = flow["subflow_fwd_bytes"]
        features[60] = flow["subflow_bwd_pkts"]
        features[61] = flow["subflow_bwd_bytes"]
        features[62] = flow["fwd_init_win"]
        features[63] = flow["bwd_init_win"]
        features[64] = active.mean()
        features[65] = active.std()
        features[66] = active.max()
        features[67] = active.min()
        features[68] = idle.mean()
        features[69] = idle.std()
        features[70] = idle.max()
        features[71] = idle.min()
        features[72:76] = [0, 0, 0, 0]
        return features

    def _flow_key(self, pkt):
        from scapy.all import IP, TCP, UDP

        if IP not in pkt:
            return None
        ip = pkt[IP]
        proto, sport, dport = "OTHER", 0, 0
        if TCP in pkt:
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        return (ip.src, ip.dst, sport, dport, proto)

    def _cleanup_flows(self):
        now = time.time()
        to_delete = [
            k
            for k, v in self._flows.items()
            if now - v["last_seen"] > self.FLOW_TIMEOUT
        ]
        for key in to_delete:
            flow = self._flows.pop(key)
            features = self._extract_features(flow)
            logger.info(
                f"Flow expired: {flow['src']} → {flow['dst']} | "
                f"fwd={flow['fwd_packets']} bwd={flow['bwd_packets']}"
            )
            if key not in self._analyzed_flows:
                self._analyzed_flows.add(key)
                self._send_to_model(features, flow)
            if len(self._analyzed_flows) > 1000:
                self._analyzed_flows.clear()

    def _send_to_model(self, features, flow, mac_override=None):
        try:
            features_clean = [float(f) for f in features]
            res = requests.post(
                ML_API_URL, json={"features": features_clean}, timeout=2
            )
            data = res.json()
            src_ip = flow["src"]
            mac = mac_override or self._mac_table.get(src_ip, "unknown")
            attack = data.get("prediction", "Unknown")
            conf = data.get("confidence", 0.0)
            logger.info(f"Model result: {src_ip} → {attack} ({conf:.2f})")
            if attack != "Benign" and conf >= 0.60:
                self.on_alert(src_ip, mac, attack, conf)
            elif attack != "Benign" and conf < 0.60:
                logger.info(
                    f"Low-confidence result ignored: {src_ip} → {attack} ({conf:.2f}) < 0.55 threshold"
                )
        except Exception as e:
            logger.warning(f"ML API error: {e}")


SIMULATED_POOL = [("192.168.1." + str(i), _random_mac()) for i in range(2, 12)]


class SimulatedCapture:
    def __init__(self, on_device, on_alert):
        self.on_device = on_device
        self.on_alert = on_alert
        self._running = False
        self._thread = None
        self._tick = 0

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        for ip, mac in SIMULATED_POOL[:6]:
            self.on_device(ip, mac)
            time.sleep(0.05)
        while self._running:
            self._tick += 1
            ip, mac = random.choice(SIMULATED_POOL)
            self.on_device(ip, mac)
            if self._tick % 4 == 0:
                attack_ip, attack_mac = random.choice(SIMULATED_POOL)
                attack = random.choices(
                    ATTACK_TYPES[1:],
                    weights=[5, 8, 15, 10, 8, 12, 6, 5, 3],
                    k=1,
                )[0]
                confidence = round(random.uniform(0.55, 0.99), 3)
                self.on_alert(attack_ip, attack_mac, attack, confidence)
            time.sleep(random.uniform(1.5, 3.5))


class MonitorService:
    def __init__(self, db, use_simulation: bool = False):
        self.db = db
        self._use_sim = use_simulation
        self._capture = None
        self._running = False
        self._stats = {"packets": 0, "flows": 0, "alerts": 0}
        self._stats_lock = threading.Lock()

        self.on_device_update: Optional[Callable] = None
        self.on_alert_update: Optional[Callable] = None
        self.on_stats_update: Optional[Callable] = None

        host_ip, host_mac = _get_host_info()
        self.db.upsert_device(host_ip, host_mac, "Whitelisted")
        if not self.db.is_whitelisted(host_ip):
            self.db.add_to_whitelist(host_ip, host_mac, "Host Machine")
        logger.info(f"Host: {host_ip} / {host_mac}")

    def start(self):
        if self._running:
            return
        self._running = True
        if self._use_sim:
            self._capture = SimulatedCapture(self._handle_device, self._handle_alert)
        else:
            try:
                self._capture = RealCapture(self._handle_device, self._handle_alert)
            except Exception:
                logger.warning("Scapy unavailable — falling back to simulation")
                self._capture = SimulatedCapture(
                    self._handle_device, self._handle_alert
                )
        self._capture.start()
        logger.info("MonitorService started")

    def stop(self):
        if not self._running:
            return
        self._running = False
        if self._capture:
            self._capture.stop()
        logger.info("MonitorService stopped")

    @property
    def is_running(self):
        return self._running

    def _handle_device(self, ip: str, mac: str):
        with self._stats_lock:
            self._stats["packets"] += 1

        if mac == "unknown":
            wl = self.db.get_whitelist()
            for entry in wl:
                if entry["ip"] == ip and entry["mac"] not in ("unknown", ""):
                    mac = entry["mac"]
                    break
        status = None
        if self.db.is_blocked(ip):
            status = "Blocked"
        elif self.db.is_whitelisted(ip):
            status = "Whitelisted"
        self.db.upsert_device(ip, mac, status)
        if self.on_device_update:
            self.on_device_update()
        if self.on_stats_update:
            self.on_stats_update(dict(self._stats))

    def _handle_alert(self, ip: str, mac: str, attack: str, confidence: float):
        if self.db.is_whitelisted(ip):
            return
        with self._stats_lock:
            self._stats["alerts"] += 1
        self.db.add_alert(ip, mac, attack, confidence)
        if self.on_alert_update:
            self.on_alert_update()
        if self.on_stats_update:
            self.on_stats_update(dict(self._stats))

    def block_ip(self, ip, mac="unknown", reason="Manual block"):
        self.db.add_blocked_ip(ip, mac, reason)
        self._apply_firewall_block(ip)
        if self.on_device_update:
            self.on_device_update()

    def unblock_ip(self, ip):
        self.db.remove_blocked_ip(ip)
        self._remove_firewall_block(ip)
        if self.on_device_update:
            self.on_device_update()

    def whitelist_ip(self, ip, mac, label=""):
        self.db.add_to_whitelist(ip, mac, label)
        if self.on_device_update:
            self.on_device_update()

    def remove_whitelist(self, ip):
        self.db.remove_from_whitelist(ip)
        if self.on_device_update:
            self.on_device_update()

    def _apply_firewall_block(self, ip):
        import subprocess
        import sys

        if sys.platform == "win32":
            try:
                subprocess.run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=NIDS_BLOCK_{ip}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip}",
                        "enable=yes",
                    ],
                    check=True,
                    capture_output=True,
                )
            except Exception as e:
                logger.warning(f"Firewall block failed: {e}")

    def _remove_firewall_block(self, ip):
        import subprocess
        import sys

        if sys.platform == "win32":
            try:
                subprocess.run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=NIDS_BLOCK_{ip}",
                    ],
                    check=True,
                    capture_output=True,
                )
            except Exception as e:
                logger.warning(f"Firewall unblock failed: {e}")
