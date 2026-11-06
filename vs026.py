#!/usr/bin/env python3
import sys, os
# Support for local package installation (mitigation for sudo/venv conflicts)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path: 
    sys.path.insert(0, SCRIPT_DIR)
import time, threading, queue, re, socket, struct, argparse, logging, hashlib
from datetime import datetime, timezone
from collections import deque
from typing import Dict, List, Optional, Any, Tuple, Callable, Set, FrozenSet
try: import fcntl
except ImportError:
    fcntl = None
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    hashes = None
    default_backend = None
import urwid
import dpkt
import json
import csv
import zlib
import base64
import string
import unicodedata
from functools import lru_cache
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Generator, Iterator

# Optional dpkt submodules - not all builds ship every protocol module
try: import dpkt.ntp  # noqa: F401
except Exception as E: print(f"[^] Failed to import `dpkt.ntp`.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}")
try: import dpkt.icmp6  # noqa: F401
except Exception as E: print(f"[^] Failed to import `dpkt.icmp6`.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}") 
try: import dpkt.ssl  # noqa: F401
except Exception as E: print(f"[^] Failed to import `dpkt.ssl`.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}") 
try: import pcapy
except ImportError:
    print("[!] pcapy-ng is required: pip install pcapy-ng");sys.exit(1)

try:
    from scapy.all import ARP as ScapyARP, Ether as ScapyEther, srp as scapy_srp;SCAPY_AVAILABLE = True
except Exception as E: 
    SCAPY_AVAILABLE = False;print(f"[^] Failed to import `scapy` modules.\n\t-> [{str(E.__class__.__name__)}]:\n\t\t- {str(E)}")
__version__ = "0.2.6"
__author__ = "J4ck3LSyN"
logging.basicConfig(filename=os.path.join(SCRIPT_DIR, "vimshark.log"),level=logging.WARNING,format="%(asctime)s [%(levelname)s] %(message)s",)
logger = logging.getLogger("vimshark")
THEMES:Dict[str, List[Tuple]] = {
    "y_researchers": [
        ('bg', 'default', 'default', 'default', '#F5F7FA', '#05070A'),
        ('header', 'white', 'light blue', 'bold', '#F5F7FA', '#1E6BFF'),
        ('footer', 'light gray', 'black', None, '#AEB6C2', '#061A3A'),
        ('border', 'dark magenta', 'default', 'default', '#8A2CFF', '#05070A'),

        ('selected', 'black', 'light green', 'standout', '#05070A', '#39FF88'),

        ('pkt_tcp', 'light cyan', 'default', 'default', '#00C8FF', '#05070A'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#FF3BBE', '#14000D'),
        ('pkt_arp', 'yellow', 'default', 'default', '#FFD84D', '#05070A'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#9FD8FF', '#05070A'),
        ('pkt_icmp', 'light red', 'default', 'default', '#E0182D', '#052E1A'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#E0182D', '#052E1A'),
        ('pkt_http', 'light green', 'default', 'default', '#39FF88', '#05070A'),
        ('pkt_tls', 'light blue', 'default', 'default', '#1E6BFF', '#05070A'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#FFD84D', '#05070A'),
        ('pkt_other', 'light gray', 'default', 'default', '#6B7280', '#05070A'),

        ('spark_bar', 'light green', 'default', None, '#39FF88', '#05070A'),
        ('text_focus', 'black', 'light magenta', None, '#05070A', '#FF3BBE'),
        ('warn', 'light red', 'default', 'bold', '#E0182D', '#05070A'),
        ('good', 'light green', 'default', 'bold', '#39FF88', '#05070A'),
        ('ja3', 'black', 'yellow', 'standout', '#05070A', '#FFD84D'),
        ('dim', 'dark gray', 'default', 'default', '#6B7280', '#05070A'),
    ],
    "nullsecurityx":[
        ('bg', 'default', 'default', 'default', '#e0e0e0', '#0a0a0f'),          
        ('header', 'white', 'dark red', 'bold', '#ffffff', '#8b0000'),      
        ('footer', 'light gray', 'black', None, '#a8a8a8', '#1c1c1c'),            
        ('border', 'dark red', 'default', 'default', '#ff1a4d', '#0a0a0f'),
        ('selected', 'black', 'light red', 'standout', '#0a0a0f', '#ff2a2a'),
        ('pkt_tcp', 'light cyan', 'default', 'default', '#00f0ff', '#0a0a0f'),    
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff00aa', '#0a0a0f'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffd700', '#0a0a0f'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#40e0ff', '#0a0a0f'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff3333', '#0a0a0f'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff3333', '#0a0a0f'),
        ('pkt_http', 'light green', 'default', 'default', '#00ff9f', '#0a0a0f'),
        ('pkt_tls', 'light blue', 'default', 'default', '#00b7ff', '#0a0a0f'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffd700', '#0a0a0f'),
        ('pkt_other', 'light gray', 'default', 'default', '#777777', '#0a0a0f'),
        ('spark_bar', 'light red', 'default', None, '#ff2a2a', '#0a0a0f'),
        ('text_focus', 'black', 'light red', None, '#0a0a0f', '#ff2a2a'),
        ('warn', 'light red', 'default', 'bold', '#ff5555', '#0a0a0f'),
        ('good', 'light green', 'default', 'bold', '#00ff9f', '#0a0a0f'),
        ('ja3', 'black', 'yellow', 'standout', '#0a0a0f', '#ffd700'),
        ('dim', 'dark gray', 'default', 'default', '#555555', '#0a0a0f'),
    ],
    "arch_yuki": [
        ('bg', 'default', 'default', 'default', '#e0def4', '#1a1625'),
        ('header', 'black', 'light magenta', 'bold', '#1a1625', '#c4a7e7'),
        ('footer', 'light gray', 'black', None, '#908caa', '#15101f'),
        ('border', 'dark magenta', 'default', 'default', '#6e6a86', '#1a1625'),
        ('selected', 'black', 'light cyan', 'standout', '#1a1625', '#ebbcba'),
        ('pkt_tcp', 'light cyan', 'default', 'default', '#9ccfd8', '#1a1625'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#c4a7e7', '#1a1625'),
        ('pkt_arp', 'yellow', 'default', 'default', '#f6c177', '#1a1625'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#ebbcba', '#1a1625'),
        ('pkt_icmp', 'light red', 'default', 'default', '#eb6f92', '#1a1625'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#eb6f92', '#1a1625'),
        ('pkt_http', 'light green', 'default', 'default', '#31748f', '#1a1625'),
        ('pkt_tls', 'light blue', 'default', 'default', '#c4a7e7', '#1a1625'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#f6c177', '#1a1625'),
        ('pkt_other', 'light gray', 'default', 'default', '#908caa', '#1a1625'),
        ('spark_bar', 'light magenta', 'default', None, '#c4a7e7', '#1a1625'),
        ('text_focus', 'black', 'light magenta', None, '#1a1625', '#c4a7e7'),
        ('warn', 'light red', 'default', 'bold', '#eb6f92', '#1a1625'),
        ('good', 'light green', 'default', 'bold', '#9ccfd8', '#1a1625'),
        ('ja3', 'black', 'yellow', 'standout', '#1a1625', '#f6c177'),
        ('dim', 'dark gray', 'default', 'default', '#6e6a86', '#1a1625'),
    ],
    "neon_sakura": [
        ('bg', 'default', 'default', 'default', '#ffe6f2', '#0d0a1f'),
        ('header', 'white', 'dark magenta', 'bold', '#ffffff', '#d672ff'),
        ('footer', 'light gray', 'black', None, '#a78bcf', '#100c24'),
        ('border', 'light magenta', 'default', 'default', '#6e4b9e', '#0d0a1f'),
        ('selected', 'black', 'light green', 'standout', '#0d0a1f', '#7effc0'),
        ('pkt_tcp', 'light cyan', 'default', 'default', '#7ee8fa', '#0d0a1f'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff6ec7', '#0d0a1f'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffe066', '#0d0a1f'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#9af7e0', '#0d0a1f'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff5f9e', '#0d0a1f'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff4f8b', '#0d0a1f'),
        ('pkt_http', 'light green', 'default', 'default', '#9dffb0', '#0d0a1f'),
        ('pkt_tls', 'light blue', 'default', 'default', '#b6a3ff', '#0d0a1f'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffd6a5', '#0d0a1f'),
        ('pkt_other', 'light gray', 'default', 'default', '#8e7fb5', '#0d0a1f'),
        ('spark_bar', 'light cyan', 'default', None, '#7ee8fa', '#0d0a1f'),
        ('text_focus', 'black', 'light cyan', None, '#0d0a1f', '#7ee8fa'),
        ('warn', 'light red', 'default', 'bold', '#ff5f9e', '#0d0a1f'),
        ('good', 'light green', 'default', 'bold', '#9dffb0', '#0d0a1f'),
        ('ja3', 'black', 'yellow', 'standout', '#0d0a1f', '#ffe066'),
        ('dim', 'dark gray', 'default', 'default', '#8e7fb5', '#0d0a1f'),
    ],
    "vapor_noir": [
        ('bg', 'default', 'default', 'default', '#e8e0ff', '#120e1e'),
        ('header', 'black', 'light blue', 'bold', '#120e1e', '#8ad7ff'),
        ('footer', 'dark gray', 'black', None, '#7a6f99', '#0e0a18'),
        ('border', 'dark blue', 'default', 'default', '#4b3f73', '#120e1e'),
        ('selected', 'black', 'light magenta', 'standout', '#120e1e', '#ff8de0'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#8ad7ff', '#120e1e'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff8de0', '#120e1e'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffe9a8', '#120e1e'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#aef0ff', '#120e1e'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff7a93', '#120e1e'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff6688', '#120e1e'),
        ('pkt_http', 'light green', 'default', 'default', '#b3ffd9', '#120e1e'),
        ('pkt_tls', 'light blue', 'default', 'default', '#bcaaff', '#120e1e'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffd6f0', '#120e1e'),
        ('pkt_other', 'light gray', 'default', 'default', '#8c80ad', '#120e1e'),
        ('spark_bar', 'light magenta', 'default', None, '#ff8de0', '#120e1e'),
        ('text_focus', 'black', 'light blue', None, '#120e1e', '#8ad7ff'),
        ('warn', 'light red', 'default', 'bold', '#ff7a93', '#120e1e'),
        ('good', 'light green', 'default', 'bold', '#b3ffd9', '#120e1e'),
        ('ja3', 'black', 'yellow', 'standout', '#120e1e', '#ffe9a8'),
        ('dim', 'dark gray', 'default', 'default', '#8c80ad', '#120e1e'),
    ],
    "btop_classic": [
        ('bg', 'default', 'default', 'default', '#ffffff', '#0f1419'),
        ('header', 'white', 'dark blue', 'bold', '#ffffff', '#005f87'),
        ('footer', 'light gray', 'black', None, '#aaaaaa', '#121820'),
        ('border', 'dark gray', 'default', 'default', '#3a4454', '#0f1419'),
        ('selected', 'black', 'light green', 'standout', '#0f1419', '#00ff87'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#00afff', '#0f1419'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#d700ff', '#0f1419'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffaf00', '#0f1419'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#00ffd7', '#0f1419'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff5555', '#0f1419'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff8787', '#0f1419'),
        ('pkt_http', 'dark green', 'default', 'default', '#00af5f', '#0f1419'),
        ('pkt_tls', 'light blue', 'default', 'default', '#5fafff', '#0f1419'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffaf00', '#0f1419'),
        ('pkt_other', 'light gray', 'default', 'default', '#8a95a5', '#0f1419'),
        ('spark_bar', 'light green', 'default', None, '#00ff87', '#0f1419'),
        ('text_focus', 'white', 'dark cyan', None, '#ffffff', '#0087af'),
        ('warn', 'light red', 'default', 'bold', '#ff5555', '#0f1419'),
        ('good', 'light green', 'default', 'bold', '#00af5f', '#0f1419'),
        ('ja3', 'black', 'yellow', 'standout', '#0f1419', '#ffaf00'),
        ('dim', 'dark gray', 'default', 'default', '#8a95a5', '#0f1419'),
    ],
    "gruvbox_dark": [
        ('bg', 'default', 'default', 'default', '#ebdbb2', '#282828'),
        ('header', 'black', 'yellow', 'bold', '#282828', '#fabd2f'),
        ('footer', 'dark gray', 'black', None, '#928374', '#1d2021'),
        ('border', 'brown', 'default', 'default', '#504945', '#282828'),
        ('selected', 'black', 'light green', 'standout', '#282828', '#b8bb26'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#83a598', '#282828'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#d3869b', '#282828'),
        ('pkt_arp', 'yellow', 'default', 'default', '#fe8019', '#282828'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#8ec07c', '#282828'),
        ('pkt_icmp', 'light red', 'default', 'default', '#fb4934', '#282828'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#fb4934', '#282828'),
        ('pkt_http', 'dark green', 'default', 'default', '#b8bb26', '#282828'),
        ('pkt_tls', 'light blue', 'default', 'default', '#83a598', '#282828'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#fabd2f', '#282828'),
        ('pkt_other', 'light gray', 'default', 'default', '#a89984', '#282828'),
        ('spark_bar', 'light green', 'default', None, '#b8bb26', '#282828'),
        ('text_focus', 'white', 'dark blue', None, '#ffffff', '#458588'),
        ('warn', 'light red', 'default', 'bold', '#fb4934', '#282828'),
        ('good', 'light green', 'default', 'bold', '#b8bb26', '#282828'),
        ('ja3', 'black', 'yellow', 'standout', '#282828', '#fabd2f'),
        ('dim', 'dark gray', 'default', 'default', '#928374', '#282828'),
    ],
    "dracula": [
        ('bg', 'default', 'default', 'default', '#f8f8f2', '#282a36'),
        ('header', 'white', 'light magenta', 'bold', '#f8f8f2', '#bd93f9'),
        ('footer', 'light gray', 'black', None, '#6272a4', '#1e1f29'),
        ('border', 'light magenta', 'default', 'default', '#44475a', '#282a36'),
        ('selected', 'black', 'light green', 'standout', '#282a36', '#50fa7b'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#8be9fd', '#282a36'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff79c6', '#282a36'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffb86c', '#282a36'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#a4ffff', '#282a36'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff5555', '#282a36'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff5555', '#282a36'),
        ('pkt_http', 'dark green', 'default', 'default', '#50fa7b', '#282a36'),
        ('pkt_tls', 'light blue', 'default', 'default', '#8be9fd', '#282a36'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#f1fa8c', '#282a36'),
        ('pkt_other', 'light gray', 'default', 'default', '#f8f8f2', '#282a36'),
        ('spark_bar', 'light green', 'default', None, '#50fa7b', '#282a36'),
        ('text_focus', 'white', 'dark magenta', None, '#ffffff', '#bd93f9'),
        ('warn', 'light red', 'default', 'bold', '#ff5555', '#282a36'),
        ('good', 'light green', 'default', 'bold', '#50fa7b', '#282a36'),
        ('ja3', 'black', 'yellow', 'standout', '#282a36', '#f1fa8c'),
        ('dim', 'dark gray', 'default', 'default', '#6272a4', '#282a36'),
    ],
    "midnight_blue": [
        ('bg',          'dark blue',      'black'),
        ('header',      'white',          'dark blue'),
        ('footer',      'white',          'dark blue'),
        ('border',      'light blue',     'black'),
        ('selected',    'black',          'light cyan'),
        ('pkt_tcp',     'light cyan',     'black'),
        ('pkt_udp',     'dark cyan',      'black'),
        ('pkt_arp',     'yellow',         'black'),
        ('pkt_dns',     'light green',    'black'),
        ('pkt_icmp',    'brown',          'black'),
        ('pkt_icmp6',   'light magenta',  'black'),
        ('pkt_http',    'light blue',     'black'),
        ('pkt_tls',     'light green',    'black'),
        ('pkt_ntp',     'dark green',     'black'),
        ('pkt_other',   'dark gray',      'black'),
        ('spark_bar',   'light blue',     'black'),
        ('text_focus',  'white',          'black'),
        ('warn',        'light red',      'black'),
        ('good',        'light green',    'black'),
        ('ja3',         'light magenta',  'black'),
        ('dim',         'dark gray',      'black'),
        ('default',     'light gray',     'black'),
    ],
    "solarized": [
        ('bg',          'dark gray',      'black'),
        ('header',      'dark blue',      'dark gray'),
        ('footer',      'dark blue',      'dark gray'),
        ('border',      'dark cyan',      'black'),
        ('selected',    'black',          'dark yellow'),
        ('pkt_tcp',     'dark cyan',      'black'),
        ('pkt_udp',     'dark green',     'black'),
        ('pkt_arp',     'dark yellow',    'black'),
        ('pkt_dns',     'dark blue',      'black'),
        ('pkt_icmp',    'dark magenta',   'black'),
        ('pkt_icmp6',   'dark red',       'black'),
        ('pkt_http',    'dark cyan',      'black'),
        ('pkt_tls',     'dark green',     'black'),
        ('pkt_ntp',     'dark blue',      'black'),
        ('pkt_other',   'dark gray',      'black'),
        ('spark_bar',   'dark cyan',      'black'),
        ('text_focus',  'light gray',     'black'),
        ('warn',        'dark red',       'black'),
        ('good',        'dark green',     'black'),
        ('ja3',         'dark magenta',   'black'),
        ('dim',         'dark gray',      'black'),
        ('default',     'light gray',     'black'),
    ],
    "cyberpunk": [
        ('bg', 'default', 'default', 'default', '#00ff00', '#000b1e'),
        ('header', 'white', 'dark magenta', 'bold', '#ffffff', '#ff0055'),
        ('footer', 'dark gray', 'black', None, '#00ffff', '#001a33'),
        ('border', 'dark magenta', 'default', 'default', '#ff0055', '#000b1e'),
        ('selected', 'black', 'light green', 'standout', '#000b1e', '#00ff00'),
        ('pkt_tcp', 'light blue', 'default', 'default', '#00afff', '#000b1e'),
        ('pkt_udp', 'light magenta', 'default', 'default', '#ff00ff', '#000b1e'),
        ('pkt_arp', 'yellow', 'default', 'default', '#ffff00', '#000b1e'),
        ('pkt_dns', 'light cyan', 'default', 'default', '#00ffff', '#000b1e'),
        ('pkt_icmp', 'light red', 'default', 'default', '#ff0000', '#000b1e'),
        ('pkt_icmp6', 'light red', 'default', 'default', '#ff0055', '#000b1e'),
        ('pkt_http', 'dark green', 'default', 'default', '#00ff00', '#000b1e'),
        ('pkt_tls', 'light blue', 'default', 'default', '#00afff', '#000b1e'),
        ('pkt_ntp', 'yellow', 'default', 'default', '#ffff00', '#000b1e'),
        ('pkt_other', 'white', 'default', 'default', '#00ff00', '#000b1e'),
        ('spark_bar', 'light green', 'default', None, '#00ff00', '#000b1e'),
        ('text_focus', 'black', 'light cyan', None, '#000000', '#00ffff'),
        ('warn', 'light red', 'default', 'bold', '#ff0000', '#000b1e'),
        ('good', 'light green', 'default', 'bold', '#00ff00', '#000b1e'),
        ('ja3', 'black', 'yellow', 'standout', '#000b1e', '#ffff00'),
        ('dim', 'dark gray', 'default', 'default', '#00ffff', '#000b1e'),
    ],
}

# -----------------------------------------------------------------
# Utils

def mac_to_str(address: bytes) -> str:
    return ':'.join('%02x' % b for b in address)


def ip_to_str(address: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, address)


def ip6_to_str(address: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, address)


# ioctl request codes (Linux)
_SIOCGIFHWADDR = 0x8927
_SIOCGIFADDR = 0x8915


def get_iface_mac(iface: str) -> bytes:
    """Return the raw 6-byte MAC address for an interface via ioctl."""
    if sys.platform != 'linux' or fcntl is None:
        return b'\x00' * 6
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), _SIOCGIFHWADDR, struct.pack('256s', iface[:15].encode()))
        return info[18:24]
    except Exception as e:
        logger.debug("get_iface_mac failed: %s", e)
        return b'\x00' * 6
    finally:
        s.close()


def get_iface_ip(iface: str) -> bytes:
    """Return the raw 4-byte IPv4 address for an interface via ioctl."""
    if sys.platform != 'linux' or fcntl is None:
        return b'\x00' * 4
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), _SIOCGIFADDR, struct.pack('256s', iface[:15].encode()))
        return info[20:24]
    except Exception as e:
        logger.debug("get_iface_ip failed: %s", e)
        return b'\x00' * 4
    finally:
        s.close()


def load_arp_cache() -> Dict[str, str]:
    """Pre-seed the ARP table from the kernel's neighbor cache (/proc/net/arp)."""
    table: Dict[str, str] = {}
    try:
        with open('/proc/net/arp') as f:
            next(f, None)  # header line
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip_addr, mac = parts[0], parts[3]
                    if mac and mac != '00:00:00:00:00:00':
                        table[ip_addr] = mac
    except Exception as e:
        logger.debug("ARP cache preload failed: %s", e)
    return table


def fmt_ts(iso_dt: Optional[str]) -> str:
    """Pretty-format an ISO datetime string for display, tolerating None."""
    if not iso_dt:
        return "Unknown"
    return iso_dt.replace("T", " ").split("+")[0].split(".")[0] + "Z"

    return iso_dt.replace("T", " ").split("+")[0].split(".")[0] + "Z"


# -----------------------------------------------------------------
# Traffic Telemetry

class TrafficTelemetry:
    """Tracks rolling packet/byte rates with EMA smoothing and sparkline history."""

    def __init__(self, max_history: int = 40):
        self.packet_history: deque = deque([0] * max_history, maxlen=max_history)
        self.byte_history: deque = deque([0] * max_history, maxlen=max_history)
        self.p_acc = 0
        self.b_acc = 0
        self.last_tick = time.time()
        self.blocks = ' ▂▃▄▅▆▇█'
        self.p_rate = 0.0
        self.b_rate = 0.0
        self.total_packets = 0
        self.total_bytes = 0

    def accumulate(self, length: int) -> None:
        self.p_acc += 1
        self.b_acc += length
        self.total_packets += 1
        self.total_bytes += length

    def tick(self) -> Tuple[float, float]:
        """Update rates with smoothing. Returns (packets/s, bytes/s)."""
        now = time.time()
        elapsed = now - self.last_tick
        if elapsed >= 0.1:
            p_inst = self.p_acc / elapsed
            b_inst = self.b_acc / elapsed
            alpha = 0.6
            self.p_rate = (alpha * p_inst) + ((1.0 - alpha) * self.p_rate) if self.p_rate > 0 else p_inst
            self.b_rate = (alpha * b_inst) + ((1.0 - alpha) * self.b_rate) if self.b_rate > 0 else b_inst
            self.packet_history.append(int(p_inst))
            self.byte_history.append(int(b_inst))
            self.p_acc = 0
            self.b_acc = 0
            self.last_tick = now
        return self.p_rate, self.b_rate

    @staticmethod
    def format_unit(val: float, is_bytes: bool = False) -> str:
        if not is_bytes:
            if val >= 1_000_000:
                return f"{val / 1_000_000:.1f}M"
            if val >= 1_000:
                return f"{val / 1_000:.1f}K"
            return str(int(val))
        for unit in ('', 'K', 'M', 'G', 'T'):
            if val < 1024:
                return f"{val:.1f}{unit}B" if unit else f"{int(val)}B"
            val /= 1024
        return f"{val:.1f}PB"

    def get_sparkline(self, metric: str = "p") -> str:
        h = list(self.packet_history if metric == "p" else self.byte_history)
        m_max = max(h) if h and max(h) > 0 else 1
        return "".join(self.blocks[min(7, int(v * 7 / m_max))] for v in h)
        
        
class HostnameCache:
    """Passive DNS resolver: maps IP->hostname from observed DNS responses.
    Thread-safe. Never makes live queries — purely observational."""
    
    _MAX = 8192
    
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._fwd: Dict[str, str] = {}   # ip -> hostname
        self._rev: Dict[str, str] = {}   # host -> ip
        
    def learn(self, ip: str, hostname: str) -> None:
        if not ip or not hostname:
            return
        with self._lock:
            if len(self._fwd) >= self._MAX:
                # Evict 10 % oldest (insertion-order dict >= 3.7)
                evict = list(self._fwd.keys())[:self._MAX // 10]
                for k in evict:
                    h = self._fwd.pop(k, None)
                    if h:
                        self._rev.pop(h, None)
            self._fwd[ip] = hostname
            self._rev[hostname] = ip
            
    def resolve(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._fwd.get(ip)

    def reverse(self, hostname: str) -> Optional[str]:
        with self._lock:
            return self._rev.get(hostname)

    def annotate(self, ip: str) -> str:
        """Return 'ip (hostname)' if known, else just 'ip'."""
        h = self.resolve(ip)
        return f"{ip} ({h})" if h else ip

    def dump(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._fwd)

    def __len__(self) -> int:
        with self._lock:
            return len(self._fwd)
            
            
@dataclass
class _StreamBuffer:
    data:      bytearray = field(default_factory=bytearray)
    seq_next:  int       = 0          # expected next seq number
    gaps:      int       = 0          # out-of-order segments dropped
    segments:  int       = 0
    first_ts:  float     = 0.0
    last_ts:   float     = 0.0
    
    
class TCPStreamReassembler:
    """Maintains per-flow ordered byte streams for content reconstruction.
    Keyed by (src_ip, src_port, dst_ip, dst_port) 4-tuple — directional.
    Bidirectional follow uses both directions concatenated by timestamp."""

    _MAX_STREAMS   = 512
    _MAX_STREAM_SZ = 2 * 1024 * 1024   # 2 MiB per direction

    def __init__(self) -> None:
        self._lock    = threading.RLock()
        self._streams: Dict[Tuple, _StreamBuffer] = {}
        self._order:   List[Tuple]                = []   # LRU eviction

    def _key(self, src_ip: str, sport: int, dst_ip: str, dport: int) -> Tuple:
        return (src_ip, sport, dst_ip, dport)

    def feed(self, src_ip: str, sport: int, dst_ip: str, dport: int,
             seq: int, payload: bytes, ts: float) -> None:
        if not payload:
            return
        key = self._key(src_ip, sport, dst_ip, dport)
        with self._lock:
            if key not in self._streams:
                if len(self._streams) >= self._MAX_STREAMS:
                    oldest = self._order.pop(0)
                    self._streams.pop(oldest, None)
                buf = _StreamBuffer(first_ts=ts, last_ts=ts)
                buf.seq_next = seq
                self._streams[key] = buf
                self._order.append(key)
            else:
                if key in self._order:
                    self._order.remove(key)
                self._order.append(key)

            buf = self._streams[key]
            buf.last_ts = ts

            if len(buf.data) + len(payload) > self._MAX_STREAM_SZ:
                # Ring-trim: drop oldest half
                half = len(buf.data) // 2
                del buf.data[:half]

            # Simple in-order: accept seq == expected or beyond (gaps logged)
            if seq == buf.seq_next or buf.seq_next == 0:
                buf.data.extend(payload)
                buf.seq_next = seq + len(payload)
                buf.segments += 1
            elif seq > buf.seq_next:
                # Gap: pad with zero-bytes placeholder
                gap = min(seq - buf.seq_next, 65535)
                buf.data.extend(b'\x00' * gap)
                buf.data.extend(payload)
                buf.seq_next = seq + len(payload)
                buf.gaps += 1
                buf.segments += 1
            # seq < seq_next → retransmit, ignore

    def get_stream(self, src_ip: str, sport: int,
                   dst_ip: str, dport: int) -> Optional[bytes]:
        key = self._key(src_ip, sport, dst_ip, dport)
        with self._lock:
            buf = self._streams.get(key)
            return bytes(buf.data) if buf else None

    def get_bidirectional(self, ip_a: str, port_a: int,
                          ip_b: str, port_b: int) -> bytes:
        """Merge A→B and B→A streams, returning all payload bytes."""
        with self._lock:
            fwd = self._streams.get(self._key(ip_a, port_a, ip_b, port_b))
            rev = self._streams.get(self._key(ip_b, port_b, ip_a, port_a))
            parts: List[bytes] = []
            if fwd:
                parts.append(bytes(fwd.data))
            if rev:
                parts.append(bytes(rev.data))
            return b''.join(parts)
            
    def stream_stats(self, src_ip: str, sport: int,
                     dst_ip: str, dport: int) -> Dict[str, Any]:
        key = self._key(src_ip, sport, dst_ip, dport)
        with self._lock:
            buf = self._streams.get(key)
            if not buf:
                return {}
            return {
                'bytes':    len(buf.data),
                'segments': buf.segments,
                'gaps':     buf.gaps,
                'first_ts': buf.first_ts,
                'last_ts':  buf.last_ts,
                'duration': buf.last_ts - buf.first_ts,
            }
            
    def clear_stream(self, src_ip: str, sport: int,
                     dst_ip: str, dport: int) -> None:
        key = self._key(src_ip, sport, dst_ip, dport)
        with self._lock:
            self._streams.pop(key, None)
            if key in self._order:
                self._order.remove(key)

    def clear(self) -> None:
        with self._lock:
            self._streams.clear()
            self._order.clear()

    def active_stream_count(self) -> int:
        with self._lock:
            return len(self._streams)

    def top_streams_by_size(self, n: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            ranked = sorted(
                self._streams.items(),
                key=lambda kv: len(kv[1].data),
                reverse=True
            )[:n]
            return [
                {
                    'src': f"{k[0]}:{k[1]}",
                    'dst': f"{k[2]}:{k[3]}",
                    'bytes': len(v.data),
                    'segments': v.segments,
                    'gaps': v.gaps,
                }
                for k, v in ranked
            ]
            
            
class ProtocolStats:
    """Counts packets and bytes per protocol, tracks top talkers, port usage."""
    
    def __init__(self) -> None:
        self._lock         = threading.RLock()
        self._proto_pkts:  Dict[str, int]        = {}
        self._proto_bytes: Dict[str, int]        = {}
        self._src_bytes:   Dict[str, int]        = {}
        self._dst_bytes:   Dict[str, int]        = {}
        self._port_counts: Dict[int, int]        = {}
        self._total_pkts:  int                   = 0
        self._total_bytes: int                   = 0
        self._window_pkts: deque                 = deque(maxlen=3600)  # 1 h @ 1pps
        
    def record(self, summary: Dict[str, Any]) -> None:
        proto  = summary.get('proto', 'OTHER')
        length = summary.get('len', 0)
        src    = summary.get('src', '')
        dst    = summary.get('dst', '')

        # Strip port suffix from addresses for top-talker tracking
        src_host = src.split(':')[0] if ':' in src else src
        dst_host = dst.split(':')[0] if ':' in dst else dst
        
        with self._lock:
            self._proto_pkts[proto] = self._proto_pkts.get(proto, 0)  + 1
            self._proto_bytes[proto] = self._proto_bytes.get(proto, 0) + length
            if src_host:
                self._src_bytes[src_host] = self._src_bytes.get(src_host, 0) + length
            if dst_host:
                self._dst_bytes[dst_host] = self._dst_bytes.get(dst_host, 0) + length
                
            # Port tracking (TCP/UDP)
            layers = summary.get('layers', [])
            for layer in layers:
                lname = layer.get('name', '')
                if lname in ('TCP', 'UDP'):
                    for field_name in ('dport', 'dst_port'):
                        port = layer.get(field_name)
                        if isinstance(port, int):
                            self._port_counts[port] = \
                                self._port_counts.get(port, 0) + 1
            self._total_pkts += 1
            self._total_bytes += length
            self._window_pkts.append(time.monotonic())
            
    def proto_distribution(self) -> List[Tuple[str, int, int, float]]:
        """Returns list of (proto, pkts, bytes, pct_of_total_bytes)."""
        with self._lock:
            total = self._total_bytes or 1
            return sorted(
                [
                    (p, self._proto_pkts[p], self._proto_bytes[p],
                     100.0 * self._proto_bytes[p] / total)
                    for p in self._proto_pkts
                ],
                key=lambda x: x[2], reverse=True
            )

    def top_talkers_src(self, n: int = 10) -> List[Tuple[str, int]]:
        with self._lock:
            return sorted(self._src_bytes.items(),
                          key=lambda x: x[1], reverse=True)[:n]

    def top_talkers_dst(self, n: int = 10) -> List[Tuple[str, int]]:
        with self._lock:
            return sorted(self._dst_bytes.items(),
                          key=lambda x: x[1], reverse=True)[:n]

    def top_ports(self, n: int = 15) -> List[Tuple[int, int]]:
        with self._lock:
            return sorted(self._port_counts.items(),
                          key=lambda x: x[1], reverse=True)[:n]

    def pps_last_n_seconds(self, seconds: int = 60) -> float:
        now = time.monotonic()
        cutoff = now - seconds
        with self._lock:
            count = sum(1 for t in self._window_pkts if t >= cutoff)
        return count / max(seconds, 1)

    def totals(self) -> Tuple[int, int]:
        with self._lock:
            return self._total_pkts, self._total_bytes

    def clear(self) -> None:
        with self._lock:
            self._proto_pkts.clear()
            self._proto_bytes.clear()
            self._src_bytes.clear()
            self._dst_bytes.clear()
            self._port_counts.clear()
            self._total_pkts  = 0
            self._total_bytes = 0
            self._window_pkts.clear()
            
            
class BaselineDetector:
    """Builds a rolling EMA baseline of pps/bps and fires alerts on deviation.
    Uses a two-phase approach: learn phase (silent) -> monitor phase (alerts)."""
    
    _LEARN_SECONDS = 120    # 2-minute warm-up before alerting
    _ALERT_MULT    = 4.0    # alert if current > baseline * multiplier
    _ALERT_COOLDOWN = 30.0  # minimum seconds between same-type alerts

    def __init__(self, alert_cb: Callable[[str], None]) -> None:
        self._alert_cb    = alert_cb
        self._alpha       = 0.05          # EMA smoothing factor
        self._ema_pps     = 0.0
        self._ema_bps     = 0.0
        self._ema_var_pps = 0.0           # variance EMA for adaptive threshold
        self._ema_var_bps = 0.0
        self._start_ts    = time.monotonic()
        self._last_pps_alert = 0.0
        self._last_bps_alert = 0.0
        self._lock        = threading.Lock()

    def _in_learn_phase(self) -> bool:
        return (time.monotonic() - self._start_ts) < self._LEARN_SECONDS

    def update(self, pps: float, bps: float) -> None:
        with self._lock:
            if self._ema_pps == 0.0:
                self._ema_pps = pps
                self._ema_bps = bps
                return

            # Update EMA
            prev_pps, prev_bps = self._ema_pps, self._ema_bps
            self._ema_pps = self._alpha * pps + (1 - self._alpha) * self._ema_pps
            self._ema_bps = self._alpha * bps + (1 - self._alpha) * self._ema_bps

            # Update variance EMA (Welford-lite)
            self._ema_var_pps = self._alpha * (pps - prev_pps) ** 2 + \
                                (1 - self._alpha) * self._ema_var_pps
            self._ema_var_bps = self._alpha * (bps - prev_bps) ** 2 + \
                                (1 - self._alpha) * self._ema_var_bps

            if self._in_learn_phase():
                return

            now = time.monotonic()
            # Adaptive threshold: use 3-sigma if variance is meaningful
            pps_sigma = max(self._ema_var_pps ** 0.5, self._ema_pps * 0.1)
            bps_sigma = max(self._ema_var_bps ** 0.5, self._ema_bps * 0.1)
            pps_thresh = max(self._ema_pps * self._ALERT_MULT,
                             self._ema_pps + 3 * pps_sigma)
            bps_thresh = max(self._ema_bps * self._ALERT_MULT,
                             self._ema_bps + 3 * bps_sigma)

            if pps > pps_thresh and (now - self._last_pps_alert) > self._ALERT_COOLDOWN:
                self._last_pps_alert = now
                self._alert_cb(
                    f"[ANOMALY] Packet rate spike: {pps:.0f} pps "
                    f"(baseline {self._ema_pps:.0f}, threshold {pps_thresh:.0f})"
                )

            if bps > bps_thresh and (now - self._last_bps_alert) > self._ALERT_COOLDOWN:
                self._last_bps_alert = now
                self._alert_cb(
                    f"[ANOMALY] Bandwidth spike: "
                    f"{TrafficTelemetry.format_unit(bps, True)}/s "
                    f"(baseline {TrafficTelemetry.format_unit(self._ema_bps, True)}/s)"
                )

    def baseline_summary(self) -> Dict[str, float]:
        with self._lock:
            return {
                'ema_pps':     self._ema_pps,
                'ema_bps':     self._ema_bps,
                'var_pps':     self._ema_var_pps,
                'var_bps':     self._ema_var_bps,
                'learning':    self._in_learn_phase(),
                'uptime':      time.monotonic() - self._start_ts,
            }

    def reset(self) -> None:
        with self._lock:
            self._ema_pps     = 0.0
            self._ema_bps     = 0.0
            self._ema_var_pps = 0.0
            self._ema_var_bps = 0.0
            self._start_ts    = time.monotonic()


# -----------------------------------------------------------------
# Packet Store

class PacketStore:
    """Owns all captured packet bytes/summaries. Capture thread writes via
    add(); UI thread reads via get()/all_indices(). Widgets only ever carry
    an integer index - never raw bytes or dpkt objects - eliminating the
    cross-thread / dangling-reference patterns that caused crashes."""

    def __init__(self, max_packets: int = 5000):
        self._lock = threading.Lock()
        self._packets: Dict[int, Tuple[bytes, Dict[str, Any], float]] = {}
        self._order: deque = deque()
        self._next_idx = 0
        self.max_packets = max_packets

    def add(self, raw: bytes, summary: Dict[str, Any], ts: float = 0.0) -> int:
        with self._lock:
            idx = self._next_idx
            self._next_idx += 1
            self._packets[idx] = (raw, summary, ts)
            self._order.append(idx)
            while len(self._order) > self.max_packets:
                old = self._order.popleft()
                self._packets.pop(old, None)
            return idx

    def get(self, idx: int) -> Optional[Tuple[bytes, Dict[str, Any], float]]:
        with self._lock:
            return self._packets.get(idx)

    def all_indices(self) -> List[int]:
        with self._lock:
            return list(self._order)

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()
            self._order.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._order)


# -----------------------------------------------------------------
# Dissection Engine (v0.3 - Enhanced TLS + JA3/JA3S + Certificate Intelligence)


# GREASE values (RFC 8701) must be ignored when computing JA3/JA3S
_GREASE_VALUES: FrozenSet[int] = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})

# TLS extension numbers worth recognizing for SNI / ALPN / supported groups, etc.
_EXT_SERVER_NAME = 0
_EXT_SUPPORTED_GROUPS = 10
_EXT_EC_POINT_FORMATS = 11
_EXT_ALPN = 16
_EXT_SUPPORTED_VERSIONS = 43

_TLS_VERSION_NAMES: Dict[int, str] = {
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# IANA cipher‑suite names (partial – enough for common traffic)
_CIPHER_SUITES: Dict[int, str] = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}


class FastDissector:
    """High-performance, multi-protocol packet dissector with robust TLS
    parsing, JA3/JA3S fingerprinting, enriched certificate details, and
    lightweight credential leakage detection."""

    _CRED_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(rb'(?i)authorization:\s*basic\s+\S+'), 'HTTP Basic Auth'),
        (re.compile(rb'(?i)authorization:\s*bearer\s+\S+'), 'Bearer token'),
        (re.compile(rb'(?i)\b(pass(word)?|pwd|passwd|secret|token)\s*[:=]\s*[^&\s]+'), 'Cleartext credential'),
        (re.compile(rb'(?i)cookie:[^\r\n]*sess[^\r\n]*=\S+'), 'Session cookie'),
        (re.compile(rb'(?i)^USER\s+\S+', re.MULTILINE), 'FTP/IMAP/SMTP USER'),
        (re.compile(rb'(?i)^PASS\s+\S+', re.MULTILINE), 'FTP/IMAP/SMTP PASS'),
        (re.compile(rb'(?i)api[-_]?key[:=]\s*\S+'), 'API Key'),
    ]

    # --------------------------------------------------------------- 
    # helpers

    @staticmethod
    def _scan_credentials(data: bytes) -> List[str]:
        if not data or len(data) > 8192:
            return []
        findings: List[str] = []
        for pattern, label in FastDissector._CRED_PATTERNS:
            try:
                if pattern.search(data):
                    findings.append(label)
            except Exception:
                continue
        return findings
        
    @staticmethod
    def _decode_dhcp(data: bytes) -> Optional[Dict[str, Any]]:
        """Minimal DHCP decoder (RFC 2131). Returns dict or None."""
        if len(data) < 236:
            return None
        try:
            op     = data[0]   # 1=request, 2=reply
            htype  = data[1]
            hlen   = data[2]
            xid    = struct.unpack_from('>I', data, 4)[0]
            ciaddr = socket.inet_ntoa(data[12:16])
            yiaddr = socket.inet_ntoa(data[16:20])
            siaddr = socket.inet_ntoa(data[20:24])
            chaddr = ':'.join(f'{b:02x}' for b in data[28:28 + min(hlen, 6)])

            info: Dict[str, Any] = {
                'op':     'REQUEST' if op == 1 else 'REPLY',
                'xid':    f'0x{xid:08x}',
                'ciaddr': ciaddr,
                'yiaddr': yiaddr,
                'siaddr': siaddr,
                'chaddr': chaddr,
                'options': {},
            }

            # Parse options (magic cookie at offset 236)
            if data[236:240] != b'\x63\x82\x53\x63':
                return info
                
            i = 240
            while i < len(data):
                opt = data[i]
                i += 1
                if opt == 255:  # END
                    break
                if opt == 0:
                    continue
                if i >= len(data):
                    break
                length = data[i]
                i += 1
                val = data[i:i + length]
                i += length
                
                if opt == 53 and length == 1:    # DHCP message type
                    _types = {1:'DISCOVER',2:'OFFER',3:'REQUEST',4:'DECLINE',
                               5:'ACK',6:'NAK',7:'RELEASE',8:'INFORM'}
                    info['msg_type'] = _types.get(val[0], str(val[0]))
                elif opt == 50 and length == 4:  # Requested IP
                    info['options']['requested_ip'] = socket.inet_ntoa(val)
                elif opt == 51 and length == 4:  # Lease time
                    info['options']['lease_time'] = struct.unpack('>I', val)[0]
                elif opt == 54 and length == 4:  # Server identifier
                    info['options']['server_id'] = socket.inet_ntoa(val)
                elif opt == 12:                  # Hostname
                    info['options']['hostname'] = FastDissector._safe_str(val, 64)
                elif opt == 60:                  # Vendor class
                    info['options']['vendor'] = FastDissector._safe_str(val, 64)
            return info
        except Exception:
            return None
            
    # --- SNMP decoder (v1/v2c community string leak detector) ---
    @staticmethod
    def _decode_snmp_community(data: bytes) -> Optional[str]:
        """Extract SNMP community string from v1/v2c PDU for credential scanning."""
        try:
            if data[0] != 0x30:   # SEQUENCE
                return None
            # Skip outer SEQUENCE length
            idx = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7f)
            # Version INTEGER
            if data[idx] != 0x02:
                return None
            vlen = data[idx + 1]
            idx += 2 + vlen
            # Community STRING
            if data[idx] != 0x04:
                return None
            clen = data[idx + 1]
            community = data[idx + 2: idx + 2 + clen].decode('latin-1', errors='replace')
            return community
        except Exception:
            return None

    # --- mDNS / DNS-SD question/answer name extractor ---
    @staticmethod
    def _decode_mdns_names(data: bytes) -> List[str]:
        """Return list of service names from mDNS packet (best-effort)."""
        names: List[str] = []
        try:
            import dpkt.dns as dns_mod
            pkt = dns_mod.DNS(data)
            for q in pkt.qd:
                names.append(q.name)
            for a in pkt.an:
                names.append(a.name)
        except Exception:
            pass
        return names

    # --- QUIC version sniffer (Initial packet detection) ---
    @staticmethod
    def _detect_quic(data: bytes) -> Optional[str]:
        """Return QUIC version string if first byte looks like a QUIC long header."""
        if len(data) < 5:
            return None
        first = data[0]
        # Long header: bit 7 set, bit 6 set (fixed bit)
        if (first & 0xC0) == 0xC0:
            version = struct.unpack_from('>I', data, 1)[0]
            known = {
                0x00000001: 'QUICv1 (RFC 9000)',
                0xff00001d: 'QUIC draft-29',
                0xff00001e: 'QUIC draft-30',
                0xff00001f: 'QUIC draft-31',
                0xff000020: 'QUIC draft-32',
                0x6b3343cf: 'QUIC v2 (RFC 9369)',
            }
            return known.get(version, f'QUIC 0x{version:08x}')
        return None

    # --- SSH banner extractor ---
    @staticmethod
    def _extract_ssh_banner(payload: bytes) -> Optional[str]:
        """Return SSH version banner if payload starts with SSH-."""
        try:
            if payload[:4] == b'SSH-':
                end = payload.find(b'\r\n')
                if end == -1:
                    end = payload.find(b'\n')
                banner = payload[:end if end > 0 else 128].decode('ascii', errors='replace')
                return banner.strip()
        except Exception:
            pass
        return None

    # --- FTP command/response parser ---
    @staticmethod
    def _parse_ftp(payload: bytes) -> Optional[Dict[str, str]]:
        try:
            line = payload[:256].decode('ascii', errors='replace').strip()
            # Response: 3-digit code
            if line[:3].isdigit() and len(line) > 3 and line[3] in (' ', '-'):
                return {'type': 'response', 'code': line[:3], 'msg': line[4:]}
            # Command
            parts = line.split(None, 1)
            if parts:
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ''
                # Mask password
                if cmd == 'PASS':
                    arg = '***REDACTED***'
                return {'type': 'command', 'cmd': cmd, 'arg': arg}
        except Exception:
            pass
        return None

    # --- SMTP command sniffer ---
    @staticmethod
    def _parse_smtp(payload: bytes) -> Optional[Dict[str, str]]:
        try:
            line = payload[:512].decode('ascii', errors='replace').strip()
            if line[:3].isdigit():
                return {'type': 'response', 'code': line[:3], 'msg': line[4:]}
            parts = line.split(None, 1)
            if parts:
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ''
                # AUTH LOGIN / PLAIN — base64 credentials
                if cmd == 'AUTH':
                    return {'type': 'command', 'cmd': cmd, 'arg': arg}
                if cmd in ('EHLO', 'HELO', 'MAIL', 'RCPT', 'DATA',
                            'QUIT', 'STARTTLS', 'RSET'):
                    return {'type': 'command', 'cmd': cmd, 'arg': arg}
        except Exception:
            pass
        return None

    # --- Telnet IAC option scanner ---
    @staticmethod
    def _detect_telnet(payload: bytes) -> bool:
        """True if payload looks like Telnet (contains IAC byte 0xff)."""
        return b'\xff' in payload[:64]

    # --- NTLM challenge detector ---
    @staticmethod
    def _detect_ntlm(payload: bytes) -> Optional[str]:
        """Detect NTLM auth blobs and return type string."""
        try:
            if b'NTLMSSP\x00' in payload:
                idx = payload.index(b'NTLMSSP\x00')
                msg_type = struct.unpack_from('<I', payload, idx + 8)[0]
                return {1: 'NTLM Negotiate', 2: 'NTLM Challenge',
                        3: 'NTLM Authenticate'}.get(msg_type, 'NTLM Unknown')
        except Exception:
            pass
        return None

    @staticmethod
    def _tcp_flag_string(flags: int) -> str:
        flag_map = (
            (dpkt.tcp.TH_FIN, 'F'), (dpkt.tcp.TH_SYN, 'S'), (dpkt.tcp.TH_RST, 'R'),
            (dpkt.tcp.TH_PUSH, 'P'), (dpkt.tcp.TH_ACK, 'A'), (dpkt.tcp.TH_URG, 'U'),
            (dpkt.tcp.TH_ECE, 'E'), (dpkt.tcp.TH_CWR, 'C'),
        )
        return ''.join(c for bit, c in flag_map if flags & bit)

    @staticmethod
    def _safe_str(val: Any, max_len: int = 120) -> str:
        """Convert any field value to a clean, readable string."""
        if val is None:
            return "None"
        if hasattr(val, '__class__') and val.__class__.__module__.startswith('dpkt') \
                and not isinstance(val, (bytes, bytearray)):
            return f"<{val.__class__.__name__} object>"

        if isinstance(val, (bytes, bytearray)):
            if len(val) == 6:   # MAC
                return mac_to_str(val)
            if len(val) == 4:   # IPv4
                try:
                    return socket.inet_ntop(socket.AF_INET, val)
                except Exception:
                    pass
            if len(val) == 16:  # IPv6
                try:
                    return socket.inet_ntop(socket.AF_INET6, val)
                except Exception:
                    pass

            # Try UTF-8 for text payloads
            if 0 < len(val) <= 512:
                try:
                    decoded = val.decode('utf-8', errors="replace")
                    if all(32 <= ord(c) <= 126 or c in '\n\r\t\x0b\x0c' for c in decoded):
                        res = decoded.strip()
                        return res[:max_len] + "..." if len(res) > max_len else res
                except Exception:
                    pass

            if len(val) > 48:
                return val[:48].hex() + f" ... ({len(val)} bytes)"
            return val.hex() if val else "(empty)"

        if isinstance(val, int):
            return str(val)
        if isinstance(val, list):
            if not val:
                return "[]"
            items = [FastDissector._safe_str(item, 60) for item in val[:6]]
            extra = f" ... ({len(val)} total)" if len(val) > 6 else ""
            return "[" + ", ".join(items) + extra + "]"
        if isinstance(val, dict):
            if not val:
                return "{}"
            preview = [f"{k}:{FastDissector._safe_str(v, 40)}" for k, v in list(val.items())[:4]]
            extra = " ..." if len(val) > 4 else ""
            return "{" + ", ".join(preview) + extra + "}"

        try:
            sval = str(val)
            return sval[:max_len] + "..." if len(sval) > max_len else sval
        except Exception:
            return f"<unprintable {type(val).__name__}>"

    # -----------------------------------------------------------------
    # TLS Extensions & Parsing

    @staticmethod
    def _parse_extension_data(ext_type: int, data: bytes, ja3_info: Dict[str, Any]) -> None:
        """Mutates ja3_info with details extracted from a single TLS extension."""
        try:
            if ext_type == _EXT_SERVER_NAME:  # SNI
                # struct: 2-byte list len, then [1-byte type, 2-byte len, name...]
                if len(data) < 2:
                    return
                pos = 2
                while pos + 3 <= len(data):
                    name_type = data[pos]
                    name_len = struct.unpack('!H', data[pos + 1:pos + 3])[0]
                    name_val = data[pos + 3:pos + 3 + name_len]
                    if name_type == 0:  # host_name
                        ja3_info["sni"] = name_val.decode('utf-8', errors='replace')
                    pos += 3 + name_len

            elif ext_type == _EXT_SUPPORTED_GROUPS:  # elliptic curves
                if len(data) >= 2:
                    list_len = struct.unpack('!H', data[:2])[0]
                    for i in range(2, min(2 + list_len, len(data)) - 1, 2):
                        val = struct.unpack('!H', data[i:i + 2])[0]
                        if val not in _GREASE_VALUES:
                            ja3_info["curves"].append(val)

            elif ext_type == _EXT_EC_POINT_FORMATS:
                if len(data) >= 1:
                    list_len = data[0]
                    for i in range(1, min(1 + list_len, len(data))):
                        ja3_info["points"].append(data[i])

            elif ext_type == _EXT_ALPN:
                # struct: 2-byte list len, then [1-byte len, proto...]
                if len(data) >= 2:
                    list_len = struct.unpack('!H', data[:2])[0]
                    pos = 2
                    protos = []
                    end = min(2 + list_len, len(data))
                    while pos < end:
                        plen = data[pos]
                        proto = data[pos + 1:pos + 1 + plen]
                        protos.append(proto.decode('utf-8', errors='replace'))
                        pos += 1 + plen
                    ja3_info["alpn"] = protos

            elif ext_type == _EXT_SUPPORTED_VERSIONS:
                if len(data) >= 1:
                    list_len = data[0]
                    versions = []
                    for i in range(1, min(1 + list_len, len(data)) - 1, 2):
                        v = struct.unpack('!H', data[i:i + 2])[0]
                        if v not in _GREASE_VALUES:
                            versions.append(v)
                    if versions:
                        ja3_info["supported_versions"] = versions
                        # Highest offered version is the best signal for TLS1.3
                        if max(versions) == 0x0304:
                            ja3_info["client_tls13"] = True

        except Exception as e:
            logger.debug("extension parse error (type=%s): %s", ext_type, e)

    # -----------------------------------------------------------------
    # JA3 / JA3S Fingerprinting

    @staticmethod
    def _parse_ja3_client_hello(handshake) -> Dict[str, Any]:
        """Extract data and compute the JA3 fingerprint from a ClientHello."""
        ja3_info: Dict[str, Any] = {
            "ja3": "N/A", "ciphers": [], "extensions": [], "curves": [],
            "points": [], "sni": None, "alpn": [], "supported_versions": [],
            "client_tls13": False,
        }

        try:
            ciphers = getattr(handshake, 'ciphersuites', getattr(handshake, 'cipher_suites', []))
            ja3_info["ciphers"] = [
                c for c in (getattr(item, 'code', item) for item in ciphers)
                if c not in _GREASE_VALUES
            ]

            for ext in getattr(handshake, 'extensions', []):
                ext_type = getattr(ext, 'type', None)
                if ext_type is None or ext_type in _GREASE_VALUES:
                    continue
                ja3_info["extensions"].append(ext_type)
                FastDissector._parse_extension_data(ext_type, getattr(ext, 'data', b''), ja3_info)

            ja3_str = (
                f"{handshake.version},"
                f"{'-'.join(map(str, ja3_info['ciphers']))},"
                f"{'-'.join(map(str, ja3_info['extensions']))},"
                f"{'-'.join(map(str, ja3_info['curves']))},"
                f"{'-'.join(map(str, ja3_info['points']))}"
            )
            ja3_info["ja3"] = hashlib.md5(ja3_str.encode('utf-8')).hexdigest()
            ja3_info["ja3_str"] = ja3_str

        except Exception as e:
            logger.debug("JA3 parsing error: %s", e)

        return ja3_info

    @staticmethod
    def _parse_ja3s_server_hello(handshake) -> Dict[str, Any]:
        """Extract data and compute the JA3S fingerprint from a ServerHello.

        JA3S format: SSLVersion,Cipher,SSLExtension
        (server responses don't echo curves/point formats).
        """
        ja3s_info: Dict[str, Any] = {"ja3s": "N/A", "extensions": [], "cipher": None}

        try:
            cipher_obj = getattr(handshake, 'ciphersuite', getattr(handshake, 'cipher_suite', None))
            cipher_code = getattr(cipher_obj, 'code', cipher_obj)
            ja3s_info["cipher"] = cipher_code

            for ext in getattr(handshake, 'extensions', []):
                ext_type = getattr(ext, 'type', None)
                if ext_type is None or ext_type in _GREASE_VALUES:
                    continue
                ja3s_info["extensions"].append(ext_type)

            ja3s_str = (
                f"{handshake.version},"
                f"{cipher_code if cipher_code is not None else ''},"
                f"{'-'.join(map(str, ja3s_info['extensions']))}"
            )
            ja3s_info["ja3s"] = hashlib.md5(ja3s_str.encode('utf-8')).hexdigest()
            ja3s_info["ja3s_str"] = ja3s_str

        except Exception as e:
            logger.debug("JA3S parsing error: %s", e)

        return ja3s_info

    # -----------------------------------------------------------------
    # Certificate Parsing

    @staticmethod
    def _parse_tls_cert(cert_der: bytes) -> Dict[str, Any]:
        """Enhanced X.509 certificate parsing using `cryptography` if available,
        falling back to a SHA256 fingerprint-only summary otherwise."""
        info: Dict[str, Any] = {
            "subject": "Unknown", "issuer": "Unknown",
            "not_before": None, "not_after": None,
            "serial": None,
            "fingerprint_sha256": None,
            "fingerprint_sha1": None,
            "san": [],
            "crl_distribution_points": [],
            "ocsp_responders": [],
            "pubkey_algorithm": None,
            "signature_algorithm": None,
            "is_expired": False,
            "is_not_yet_valid": False,
            "is_self_signed": False,
            "days_remaining": None,
        }

        if not cert_der:
            return info

        try:
            if CRYPTOGRAPHY_AVAILABLE:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                info["subject"] = cert.subject.rfc4514_string()
                info["issuer"] = cert.issuer.rfc4514_string()
                info["serial"] = hex(cert.serial_number)

                # Validity period – try the modern UTC-aware accessors first,
                # falling back to the naive datetime properties on older releases.
                try:
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                except AttributeError:
                    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

                info["not_before"] = not_before.isoformat()
                info["not_after"] = not_after.isoformat()

                info["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
                info["fingerprint_sha1"] = cert.fingerprint(hashes.SHA1()).hex()

                try:
                    info["signature_algorithm"] = cert.signature_hash_algorithm.name
                except Exception:
                    pass

                # Subject Alternative Names
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    info["san"] = [str(name.value) for name in san_ext.value]
                except x509.ExtensionNotFound:
                    pass
                except Exception as e:
                    logger.debug("SAN parse error: %s", e)

                # Public key algorithm + size
                try:
                    pub = cert.public_key()
                    pk_name = pub.__class__.__name__
                    key_size = getattr(pub, 'key_size', None)
                    info["pubkey_algorithm"] = f"{pk_name} ({key_size} bit)" if key_size else pk_name
                except Exception:
                    pass

                # CRL distribution points + OCSP responders
                for ext in cert.extensions:
                    try:
                        if isinstance(ext.value, x509.CRLDistributionPoints):
                            for dp in ext.value:
                                if dp.full_name:
                                    for point in dp.full_name:
                                        if isinstance(point, x509.UniformResourceIdentifier):
                                            info["crl_distribution_points"].append(point.value)
                        if isinstance(ext.value, x509.AuthorityInformationAccess):
                            for ad in ext.value:
                                if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                                    if isinstance(ad.access_location, x509.UniformResourceIdentifier):
                                        info["ocsp_responders"].append(ad.access_location.value)
                    except Exception as e:
                        logger.debug("extension scan error: %s", e)

                # Validity / trust checks
                now = datetime.now(timezone.utc)
                info["is_expired"] = not_after < now
                info["is_not_yet_valid"] = not_before > now
                info["is_self_signed"] = cert.subject == cert.issuer
                info["days_remaining"] = int((not_after - now).total_seconds() // 86400)

            else:
                # Fallback – just hash the raw DER
                info["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest()
                info["fingerprint_sha1"] = hashlib.sha1(cert_der).hexdigest()
                info["subject"] = "Install 'cryptography' for full parsing"

        except Exception as e:
            logger.debug("Cert parse error: %s", e)
            if not info["fingerprint_sha256"]:
                info["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest()

        return info

    # -----------------------------------------------------------------
    # TLS Handshake Parsing

    @staticmethod
    def _parse_tls_handshake(tcp_payload: bytes) -> Dict[str, Any]:
        """Robust TLS record/handshake parser with JA3/JA3S support.

        Handles multi‑record reads, multiple handshake messages per record,
        and degrades gracefully on TLS 1.3 (where Certificate is encrypted
        and thus invisible post‑handshake) and on fragmented streams (where
        a single TCP segment may contain a partial handshake message).
        """
        result: Dict[str, Any] = {
            "certs": [],
            "sni": None,
            "alpn": [],
            "version": None,
            "version_name": None,
            "cipher": None,
            "cipher_name": None,
            "ja3": None,
            "ja3_info": {},
            "ja3s": None,
            "ja3s_info": {},
            "ocsp_stapled": False,
            "handshake_type": "Unknown",
            "tls13": False,
            "alert": None,
        }

        if not tcp_payload or len(tcp_payload) < 5:
            return result

        try:
            # Initial sanity check: TLS record content types are 20‑23
            if tcp_payload[0] not in (20, 21, 22, 23):
                return result

            tls = dpkt.ssl.TLS(tcp_payload)

            # Baseline version from the record header to avoid 'None'
            if hasattr(tls, 'version'):
                result["version"] = tls.version
                result["version_name"] = _TLS_VERSION_NAMES.get(tls.version, f"0x{tls.version:04x}")

            if hasattr(tls, 'type'):
                if tls.type == 20:
                    result["handshake_type"] = "ChangeCipherSpec"
                elif tls.type == 21:
                    result["handshake_type"] = "Alert"
                elif tls.type == 23:
                    result["handshake_type"] = "AppData"

            records = getattr(tls, 'records', None) or [tls]

            for record in records:
                rtype = getattr(record, 'type', None)

                if rtype == 21:  # Alert
                    try:
                        adata = record.data
                        if len(adata) >= 2:
                            level, desc = adata[0], adata[1]
                            result["alert"] = f"level={level} desc={desc}"
                    except Exception:
                        pass
                    continue

                if rtype != 22:  # Not a Handshake record
                    continue

                # A record can contain multiple handshake messages
                # (e.g. ServerHello + Certificate + ServerHelloDone)
                h_data = record.data
                while len(h_data) >= 4:
                    try:
                        handshake = dpkt.ssl.TLSHandshake(h_data)
                    except (dpkt.NeedData, dpkt.UnpackError):
                        # Fragmented handshake message split across TCP segments.
                        break

                    hs_type = getattr(handshake, 'type', None)
                    h_len = getattr(handshake, 'length', 0)

                    if len(h_data) < 4 + h_len:
                        # Truncated – message continues in a later segment.
                        if hs_type == 1:
                            result["handshake_type"] = "ClientHello (fragmented)"
                        elif hs_type == 2:
                            result["handshake_type"] = "ServerHello (fragmented)"
                        elif hs_type == 11:
                            result["handshake_type"] = "Certificate (fragmented)"
                        break

                    if hs_type == 1:  # ClientHello
                        result["handshake_type"] = "ClientHello"
                        inner = handshake.data
                        result["version"] = inner.version
                        result["version_name"] = _TLS_VERSION_NAMES.get(inner.version, f"0x{inner.version:04x}")
                        ja3_data = FastDissector._parse_ja3_client_hello(inner)
                        result["ja3"] = ja3_data["ja3"]
                        result["ja3_info"] = ja3_data
                        result["sni"] = ja3_data["sni"]
                        result["alpn"] = ja3_data["alpn"]
                        if ja3_data.get("client_tls13"):
                            result["tls13"] = True

                    elif hs_type == 2:  # ServerHello
                        result["handshake_type"] = "ServerHello"
                        inner = handshake.data
                        if hasattr(inner, 'version'):
                            result["version"] = inner.version
                            result["version_name"] = _TLS_VERSION_NAMES.get(inner.version, f"0x{inner.version:04x}")
                            if inner.version == 0x0304:
                                result["tls13"] = True
                        ja3s_data = FastDissector._parse_ja3s_server_hello(inner)
                        result["ja3s"] = ja3s_data["ja3s"]
                        result["ja3s_info"] = ja3s_data
                        cipher = ja3s_data.get("cipher")
                        if cipher is not None:
                            result["cipher"] = cipher
                            result["cipher_name"] = f"0x{cipher:04x}"

                    elif hs_type == 11:  # Certificate
                        result["handshake_type"] = "Certificate"
                        inner = handshake.data
                        for cert_der in getattr(inner, 'certificates', []):
                            if isinstance(cert_der, (bytes, bytearray)) and len(cert_der) > 0:
                                parsed = FastDissector._parse_tls_cert(cert_der)
                                result["certs"].append(parsed)

                    elif hs_type == 22:  # CertificateStatus (OCSP Stapling)
                        result["ocsp_stapled"] = True
                        result["handshake_type"] = "CertificateStatus (OCSP)"

                    elif hs_type == 14:  # ServerHelloDone
                        if result["handshake_type"] == "Unknown":
                            result["handshake_type"] = "ServerHelloDone"

                    elif result["handshake_type"] in ("Unknown", "Handshake"):
                        result["handshake_type"] = f"Handshake(type={hs_type})"

                    h_data = h_data[4 + h_len:]

        except (dpkt.NeedData, dpkt.UnpackError) as e:
            logger.debug("TLS NeedData/UnpackError (likely fragmented): %s", e)
        except Exception as e:
            logger.debug("TLS handshake parse error: %s", e)

        return result

    # -----------------------------------------------------------------
    # Layer Walking

    @staticmethod
    def _dissect_layer(layer: Any, depth: int = 0) -> List[Tuple[str, Dict[str, Any]]]:
        """Recursively dissect nested protocol layers for the detail view."""
        layers: List[Tuple[str, Dict[str, Any]]] = []
        if layer is None or isinstance(layer, (bytes, bytearray)) or depth > 12:
            return layers

        try:
            raw_name = layer.__class__.__name__
            layer_name = "IPv4" if raw_name == "IP" else ("IPv6" if raw_name == "IP6" else raw_name)
            fields: Dict[str, Any] = {}

            if hasattr(layer, '__hdr__'):
                for hdr_item in getattr(layer, '__hdr__', []):
                    name = hdr_item[0]
                    fields[name] = getattr(layer, name)
            else:
                for attr in dir(layer):
                    if attr.startswith('_') or attr in ('data', 'unpack', 'pack', 'off', 'sum'):
                        continue
                    val = getattr(layer, attr, None)
                    if not callable(val):
                        fields[attr] = val

            layers.append((layer_name, fields))

            payload = getattr(layer, 'data', None)
            if payload is not None and hasattr(payload, '__class__') \
                    and payload.__class__.__module__.startswith('dpkt'):
                layers.extend(FastDissector._dissect_layer(payload, depth + 1))

        except Exception as e:
            logger.debug("layer dissection error: %s", e)

        return layers

    @staticmethod
    def dissect(raw_pkt: bytes) -> Dict[str, Any]:
        """Main dissection entry point. Returns a flat summary dict consumed
        by the UI for row rendering, filtering, and the detail pane."""
        res: Dict[str, Any] = {
            "proto": "OTHER", "src": "N/A", "dst": "N/A", "summary": "Unknown Frame",
            "len": len(raw_pkt), "layers": [], "creds": [], "ports": [], "tls_info": {},
        }

        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
            payload = eth.data

            if isinstance(payload, dpkt.arp.ARP):
                arp = payload
                res["proto"] = "ARP"
                res["src"] = ip_to_str(arp.spa)
                res["dst"] = ip_to_str(arp.tpa)
                op = "Request" if arp.op == dpkt.arp.ARP_OP_REQUEST else "Reply"
                res["summary"] = f"ARP {op} {res['src']} -> {res['dst']}"

            elif isinstance(payload, (dpkt.ip.IP, dpkt.ip6.IP6)):
                ip_pkt = payload
                is_v6 = isinstance(ip_pkt, dpkt.ip6.IP6)

                res["src"] = (ip6_to_str if is_v6 else ip_to_str)(ip_pkt.src)
                res["dst"] = (ip6_to_str if is_v6 else ip_to_str)(ip_pkt.dst)
                res["proto"] = "IPv6" if is_v6 else "IPv4"

                if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                    tcp = ip_pkt.data
                    res["proto"] = "TCP"
                    res["src"] += f":{tcp.sport}"
                    res["dst"] += f":{tcp.dport}"
                    res["ports"] = [tcp.sport, tcp.dport]
                    flagstr = FastDissector._tcp_flag_string(tcp.flags)
                    res["summary"] = (
                        f"TCP {tcp.sport}->{tcp.dport} [{flagstr}] "
                        f"Seq={tcp.seq} Ack={tcp.ack} Len={len(tcp.data or b'')}"
                    )

                    if tcp.data:
                        res["creds"] = FastDissector._scan_credentials(tcp.data)

                    # HTTP
                    if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
                        try:
                            data = tcp.data
                            http_cls = dpkt.http.Response if data.startswith(b'HTTP/') else dpkt.http.Request
                            http = http_cls(data)
                            res["proto"] = "HTTP"
                            method_or_ver = getattr(http, 'method', http.version)
                            uri_or_status = getattr(http, 'uri', getattr(http, 'status', ''))
                            res["summary"] = f"HTTP {method_or_ver} {uri_or_status}"
                            tcp.data = http
                        except Exception:
                            pass

                    # TLS (port‑agnostic)
                    if tcp.data and tcp.data[:1] and tcp.data[0] in (20, 21, 22, 23):
                        res["proto"] = "TLS"
                        tls_info = FastDissector._parse_tls_handshake(tcp.data or b'')
                        res["tls_info"] = tls_info

                        h_type = tls_info.get('handshake_type', 'Data')
                        ver = tls_info.get('version_name') or '?'

                        extra_bits = []
                        if tls_info.get('sni'):
                            extra_bits.append(f"SNI:{tls_info['sni']}")
                        if tls_info.get('ja3') and tls_info['ja3'] != "N/A":
                            extra_bits.append(f"JA3:{tls_info['ja3'][:12]}")
                        if tls_info.get('ja3s') and tls_info['ja3s'] != "N/A":
                            extra_bits.append(f"JA3S:{tls_info['ja3s'][:12]}")
                        if tls_info.get('certs'):
                            extra_bits.append(f"Certs:{len(tls_info['certs'])}")
                        if tls_info.get('alert'):
                            extra_bits.append(f"ALERT({tls_info['alert']})")

                        extra = (" " + " ".join(extra_bits)) if extra_bits else ""
                        res["summary"] = f"TLS {h_type} {tcp.sport}->{tcp.dport} v{ver}{extra}"

                elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                    udp = ip_pkt.data
                    res["proto"] = "UDP"
                    res["src"] += f":{udp.sport}"
                    res["dst"] += f":{udp.dport}"
                    res["ports"] = [udp.sport, udp.dport]
                    res["summary"] = f"UDP {udp.sport}->{udp.dport} Len={udp.ulen}"

                    if udp.dport == 53 or udp.sport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            res["proto"] = "DNS"
                            qr = 'Query' if dns.qr == 0 else 'Response'
                            qname = dns.qd[0].name.decode('utf-8', errors='replace') if dns.qd else ""
                            res["summary"] = f"DNS {qr} {qname}"
                        except Exception:
                            pass
                    elif udp.dport == 123 or udp.sport == 123:
                        try:
                            ntp = dpkt.ntp.NTP(udp.data)
                            res["proto"] = "NTP"
                            res["summary"] = f"NTP v{ntp.v} Mode {ntp.mode} Stratum {ntp.stratum}"
                        except Exception:
                            pass

                elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                    icmp = ip_pkt.data
                    res["proto"] = "ICMP"
                    res["summary"] = f"ICMP Type={icmp.type} Code={icmp.code}"

                elif hasattr(dpkt, 'icmp6') and isinstance(ip_pkt.data, dpkt.icmp6.ICMP6):
                    icmp6 = ip_pkt.data
                    res["proto"] = "ICMPv6"
                    res["summary"] = f"ICMPv6 Type={icmp6.type} Code={icmp6.code}"

            elif eth.type == 0x8100:
                res["proto"] = "VLAN"
                res["summary"] = "802.1Q VLAN Frame"

            # Build the layer tree once, after any in‑place protocol enrichment
            res["layers"] = FastDissector._dissect_layer(eth)

        except Exception as e:
            logger.debug("dissect error: %s", e)

        return res

    @staticmethod
    def get_hexdump(data: bytes, max_bytes: int = 1024) -> str:
        """Generate a classic offset/hex/ASCII hexdump."""
        truncated = len(data) > max_bytes
        view = data[:max_bytes]
        lines = []
        for i in range(0, len(view), 16):
            chunk = view[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
        if truncated:
            lines.append(f"... truncated ({len(data)} bytes total) ...")
        return "\n".join(lines)


# -----------------------------------------------------------------
# IP Reassembler

class IPReassembler:
    """Stateful IPv4 fragmentation reassembler with expiry of stale buffers."""

    def __init__(self, max_age: float = 30.0):
        self.fragments: Dict[Tuple, Dict[int, bytes]] = {}
        self.finished: Dict[Tuple, int] = {}
        self.timestamps: Dict[Tuple, float] = {}
        self.max_age = max_age

    def process(self, ip: "dpkt.ip.IP") -> Optional[bytes]:
        now = time.time()
        # Clean up expired buffers
        expired = [k for k, ts in self.timestamps.items() if now - ts > self.max_age]
        for k in expired:
            self._clear(k)

        mf = getattr(ip, 'mf', False) or bool(getattr(ip, 'off', 0) & dpkt.ip.IP_MF)
        offset = getattr(ip, 'offset', 0) * 8

        key = (ip.src, ip.dst, ip.p, ip.id)
        self.timestamps[key] = now

        if key not in self.fragments:
            self.fragments[key] = {}

        self.fragments[key][offset] = ip.data
        if not mf:
            self.finished[key] = offset + len(ip.data)

        if key in self.finished:
            total, curr, parts = self.finished[key], 0, []
            while curr < total:
                if curr in self.fragments[key]:
                    chunk = self.fragments[key][curr]
                    parts.append(chunk)
                    curr += len(chunk)
                else:
                    return None  # Still missing pieces
            self._clear(key)
            return b"".join(parts)
        return None

    def _clear(self, key) -> None:
        self.fragments.pop(key, None)
        self.finished.pop(key, None)
        self.timestamps.pop(key, None)


# -----------------------------------------------------------------
# Flow Tracker

class FlowTracker:
    """Lightweight bidirectional flow table. Tracks per‑flow packet/byte
    counters and last‑seen timestamps so the UI can surface "top talkers"
    and basic conversation hints without a full state machine."""

    def __init__(self, max_flows: int = 2000):
        self.flows: Dict[FrozenSet, Dict[str, Any]] = {}
        self.max_flows = max_flows

    def update(self, summary: Dict[str, Any], ts: float) -> Optional[Dict[str, Any]]:
        src, dst, proto = summary.get('src'), summary.get('dst'), summary.get('proto')
        if not src or not dst or proto in ('ARP', 'OTHER'):
            return None

        key = frozenset((src, dst))
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                # Evict the oldest flow to bound memory use
                oldest_key = min(self.flows, key=lambda k: self.flows[k]['last_seen'])
                self.flows.pop(oldest_key, None)
            flow = {
                "endpoints": (src, dst), "proto": proto,
                "packets": 0, "bytes": 0,
                "first_seen": ts, "last_seen": ts,
            }
            self.flows[key] = flow

        flow["packets"] += 1
        flow["bytes"] += summary.get('len', 0)
        flow["last_seen"] = ts
        return flow

    def top_flows(self, n: int = 10) -> List[Dict[str, Any]]:
        return sorted(self.flows.values(), key=lambda f: f['bytes'], reverse=True)[:n]
        
    def update_tcp_metrics(self, summary: Dict[str, Any], ts: float) -> None:
        """Track TCP retransmits and window sizes per flow."""
        if summary.get('proto') not in ('TCP', 'TLS', 'HTTP'):
            return

        src = summary.get('src', '')
        dst = summary.get('dst', '')
        if not src or not dst:
            return

        endpoints = frozenset([src, dst])
        proto     = summary.get('proto', 'TCP')
        fkey      = (endpoints, proto)

        if not hasattr(self, '_tcp_metrics'):
            self._tcp_metrics: Dict[Any, Dict] = {}

        with self._lock:
            m = self._tcp_metrics.setdefault(fkey, {
                'retransmits': 0,
                'window_sizes': [],
                'seq_seen':     set(),
                'rtt_samples':  [],
            })

            for layer in summary.get('layers', []):
                if layer.get('name') != 'TCP':
                    continue
                seq  = layer.get('seq', 0)
                ack  = layer.get('ack', 0)
                win  = layer.get('window', 0)
                flags = layer.get('flags_str', '')

                if win:
                    m['window_sizes'].append(win)
                    if len(m['window_sizes']) > 100:
                        del m['window_sizes'][:50]

                if seq and seq in m['seq_seen']:
                    m['retransmits'] += 1
                elif seq:
                    m['seq_seen'].add(seq)
                    if len(m['seq_seen']) > 500:
                        # Keep only recent 250
                        m['seq_seen'] = set(list(m['seq_seen'])[-250:])
                        
    def tcp_flow_metrics(self, src: str, dst: str,
                         proto: str = 'TCP') -> Dict[str, Any]:
        """Return TCP metrics for a given flow."""
        if not hasattr(self, '_tcp_metrics'):
            return {}
        endpoints = frozenset([src, dst])
        fkey = (endpoints, proto)
        with self._lock:
            m = self._tcp_metrics.get(fkey, {})
            if not m:
                return {}
            wins = m.get('window_sizes', [])
            return {
                'retransmits':  m.get('retransmits', 0),
                'avg_win':      sum(wins) / len(wins) if wins else 0,
                'min_win':      min(wins) if wins else 0,
                'max_win':      max(wins) if wins else 0,
                'unique_seqs':  len(m.get('seq_seen', set())),
            }

    def flows_with_retransmits(self, min_retransmits: int = 3) -> List[Dict]:
        """Return flows that have seen at least min_retransmits retransmits."""
        if not hasattr(self, '_tcp_metrics'):
            return []
        with self._lock:
            results = []
            for (endpoints, proto), m in self._tcp_metrics.items():
                rt = m.get('retransmits', 0)
                if rt >= min_retransmits:
                    eps = list(endpoints)
                    results.append({
                        'endpoints':    eps,
                        'proto':        proto,
                        'retransmits':  rt,
                    })
            return sorted(results, key=lambda x: x['retransmits'], reverse=True)

    def clear(self) -> None:
        self.flows.clear()


# -----------------------------------------------------------------
# Filter Expressions

_COND_RE = re.compile(r'^\s*([\w.]+)\s*(==|!=)\s*(\S+)\s*$')


def _get_field(summary: Dict[str, Any], field: str) -> Any:
    """Enhanced field accessor supporting Wireshark-like hierarchical paths:
    ip.src, ip.dst, tcp.srcport, tcp.dstport, udp.srcport, tls.sni, 
    ip.src.banner, ip.dst.banner, http.request.method, etc.
    """
    field = field.lower().strip()
    parts = field.split('.')

    # Legacy + IP address support
    if field in ('src', 'srcip', 'ip.src'):
        src_full = summary.get('src', '')
        return src_full.rsplit(':', 1)[0] if ':' in src_full else src_full
    if field in ('dst', 'dstip', 'ip.dst'):
        dst_full = summary.get('dst', '')
        return dst_full.rsplit(':', 1)[0] if ':' in dst_full else dst_full

    # Ports
    if field in ('sport', 'tcp.srcport', 'udp.srcport'):
        src_full = summary.get('src', '')
        return src_full.rsplit(':', 1)[1] if ':' in src_full else None
    if field in ('dport', 'tcp.dstport', 'udp.dstport'):
        dst_full = summary.get('dst', '')
        return dst_full.rsplit(':', 1)[1] if ':' in dst_full else None
    if field == 'port':
        ports = []
        for key in ('src', 'dst'):
            parts_key = summary.get(key, '').rsplit(':', 1)
            if len(parts_key) > 1:
                ports.append(parts_key[1])
        return ports

    if field == 'proto' or field == 'ip.proto':
        return summary.get('proto', '')

    # Length
    if field in ('len', 'frame.len'):
        return str(summary.get('len', ''))

    # TLS / security
    tls_info = summary.get('tls_info') or {}
    if field in ('tls.sni', 'sni'):
        return tls_info.get('sni')
    if field in ('tls.ja3', 'ja3'):
        return tls_info.get('ja3')
    if field in ('tls.ja3s', 'ja3s'):
        return tls_info.get('ja3s')
    if field in ('cred', 'http.auth'):
        return 'yes' if summary.get('creds') else 'no'
    if field in ('ip.src.banner', 'src.banner'):
        payload = _extract_payload_for_banner(summary, is_src=True)
        if payload:
            banner = "".join(chr(b) if 32 <= b <= 126 or b in (10, 13) else "." for b in payload[:256])
            return banner.strip()[:120]
        return None

    if field in ('ip.dst.banner', 'dst.banner'):
        payload = _extract_payload_for_banner(summary, is_src=False)
        if payload:
            banner = "".join(chr(b) if 32 <= b <= 126 or b in (10, 13) else "." for b in payload[:256])
            return banner.strip()[:120]
        return None

    for layer_name, fields in summary.get('layers', []):
        lname = layer_name.lower()
        if parts[0] == lname or (parts[0] == 'ip' and lname in ('ipv4', 'ipv6')):
            if len(parts) == 1:
                return fields
            key = parts[1]
            if key in fields:
                val = fields[key]
                if key in ('src', 'dst') and isinstance(val, (bytes, bytearray)):
                    try:
                        if len(val) == 4:
                            return socket.inet_ntop(socket.AF_INET, val)
                        elif len(val) == 16:
                            return socket.inet_ntop(socket.AF_INET6, val)
                    except Exception:
                        pass
                return val

    return summary.get(field, None)


def _compile_expr_filter(expr: str) -> Callable[[Dict[str, Any]], bool]:
    """Support for more Wireshark-style expressions:
    ip.src == 192.168.1.1 && tcp.dstport == 443
    tls.sni == example.com || http.request.method == GET
    """
    or_groups = [g.strip() for g in expr.split('||')]
    compiled_or: List[List[Tuple[Optional[str], Optional[str], str]]] = []
    for group in or_groups:
        and_parts = [p.strip() for p in group.split('&&') if p.strip()]
        conds: List[Tuple[Optional[str], Optional[str], str]] = []
        for part in and_parts:
            m = _COND_RE.match(part)
            if m:
                field, op, val = m.groups()
                conds.append((field, op, val))
            else:
                # free text search
                conds.append((None, None, part.lower()))
        compiled_or.append(conds)

    def matcher(summary: Dict[str, Any]) -> bool:
        for conds in compiled_or:
            ok = True
            for field, op, val in conds:
                if field is None:
                    # free text fallback
                    text = (
                        f"{summary.get('summary', '')} {summary.get('proto', '')} "
                        f"{summary.get('src', '')} {summary.get('dst', '')}"
                    ).lower()
                    cond = val in text
                else:
                    actual = _get_field(summary, field)
                    if actual is None:
                        cond = False
                    elif isinstance(actual, (list, tuple)):
                        cond = any(str(a).lower() == val.lower() for a in actual)
                    else:
                        cond = val.lower() in str(actual).lower()
                    if op == '!=':
                        cond = not cond
                if not cond:
                    ok = False
                    break
            if ok:
                return True
        return False

    return matcher


def compile_filter(expr: str) -> Callable[[Dict[str, Any]], bool]:
    """Compile a filter string. Falls back to plain substring search on any parse issue."""
    expr = (expr or "").strip()
    if not expr:
        return lambda summary: True
    try:
        return _compile_expr_filter(expr)
    except Exception as e:
        logger.debug("filter compile fallback: %s", e)
        val = expr.lower()
        def fallback(summary: Dict[str, Any]) -> bool:
            text = f"{summary.get('summary', '')} {summary.get('proto', '')} {summary.get('src', '')} {summary.get('dst', '')}".lower()
            return val in text
        return fallback


def _extract_payload_for_banner(summary: Dict[str, Any], is_src: bool) -> Optional[bytes]:
    """Helper to pull raw payload for banner extraction."""
    layers = summary.get('layers', [])
    for name, fields in layers:
        if name.upper() in ('TCP', 'UDP'):
            data = fields.get('data')
            if isinstance(data, (bytes, bytearray)):
                return data
    return None

# -----------------------------------------------------------------
# Threat Auditor

class ThreatAuditor:
    """Lightweight passive + active security checks with improved port scan detection."""

    def __init__(self, alert_cb: Callable[[str], None]):
        self.alert_cb = alert_cb
        self.arp_table: Dict[str, str] = load_arp_cache()
        self.history: Set[str] = set()
        self.expired_cert_history: Set[str] = set()
        self.selfsigned_cert_history: Set[str] = set()

        # Tracking structures
        self.icmp_tracking: Dict[str, deque] = {}
        self.syn_tracking: Dict[str, deque] = {}
        self.scan_tracking: Dict[str, deque] = {} # src -> deque of (timestamp, dport)
        self.incremental_tracking: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # Host Scanning
        self.host_scan_tracking:Dict[str,deque]={}
        self.arp_scan_tracking:Dict[str,deque]={}

        # Configuration
        self.arp_auditor_enabled = True
        self.port_scan_enabled: bool = True
        self.syn_auditor_enabled = True
        self.icmp_auditor_enabled = True
        self.host_scan_enabled = True

        # Port‑scan tuning – the defaults are now low enough to catch a normal
        # nmap “‑T4” sweep out‑of‑the‑box.  Users can still override them via the
        # CLI flag ``--scan-threshold`` which maps to ``port_scan_unique_threshold``.
        self.port_scan_unique_threshold: int = 12      # unique ports in window → “excessive”
        self.port_scan_sequential_threshold: int = 8   # consecutive ports → “sequential”
        self.port_scan_window: float = 10.0            # seconds

        self.host_scan_threshold: int = 15          # unique hosts pinged in window
        self.host_scan_window: float = 8.0          # seconds

    def audit_packet(self, raw_pkt: bytes) -> None:
        """Main entry point for packet auditing."""
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)

            # ARP Handling: Spoof Detection + Host Scan Detection
            if isinstance(eth.data, dpkt.arp.ARP):
                if not self.arp_auditor_enabled:
                    return
                arp = eth.data

                # ARP Reply → Spoofing detection
                if arp.op == dpkt.arp.ARP_OP_REPLY:
                    ip_addr = ip_to_str(arp.spa)
                    mac = mac_to_str(arp.sha)
                    known = self.arp_table.get(ip_addr)
                    if known and known != mac:
                        msg = f"ARP SPOOF: {ip_addr} moved {known} -> {mac}"
                        if msg not in self.history:
                            self.history.add(msg)
                            self.alert_cb(msg)
                    self.arp_table[ip_addr] = mac

                # ARP Request → Host Scan Detection (NEW)
                elif arp.op == dpkt.arp.ARP_OP_REQUEST and self.host_scan_enabled:
                    src_mac = mac_to_str(arp.sha)
                    target_ip = ip_to_str(arp.tpa)
                    # Ignore obvious broadcast / invalid targets
                    if target_ip not in ("0.0.0.0", "255.255.255.255"):
                        self._audit_host_scan(src_mac, target_ip, scan_type="ARP")

            # IP‑based traffic (ICMP, TCP, UDP, etc.)
            elif isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                ip = eth.data
                src_ip = ip6_to_str(ip.src) if isinstance(ip, dpkt.ip6.IP6) else ip_to_str(ip.src)

                # === ICMP Host Scan Detection ===
                if self.host_scan_enabled and isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data
                    if icmp.type == 8:  # Echo Request (Ping)
                        dst_ip = ip6_to_str(ip.dst) if isinstance(ip, dpkt.ip6.IP6) else ip_to_str(ip.dst)
                        self._audit_host_scan(src_ip, dst_ip, scan_type="ICMP")

                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    transport = ip.data
                    proto = "TCP" if isinstance(transport, dpkt.tcp.TCP) else "UDP"

                    if self.port_scan_enabled:
                        self._audit_port_scan(src_ip, transport.dport, proto)

                    if isinstance(transport, dpkt.tcp.TCP) and self.syn_auditor_enabled:
                        if (transport.flags & dpkt.tcp.TH_SYN) and not (transport.flags & dpkt.tcp.TH_ACK):
                            self._audit_flood(src_ip, self.syn_tracking, "TCP SYN FLOOD", 50)

                # ICMP Flood
                elif (isinstance(ip.data, dpkt.icmp.ICMP) or
                      (hasattr(dpkt, 'icmp6') and isinstance(ip.data, dpkt.icmp6.ICMP6))):
                    if self.icmp_auditor_enabled:
                        self._audit_flood(src_ip, self.icmp_tracking, "ICMP FLOOD", 40)

        except Exception as e:
            logger.debug("audit_packet error: %s", e)

    def _audit_port_scan(self, src: str, dport: int, proto: str) -> None:
        """Improved detection for both random/excessive and sequential port scanning."""
        if not self.port_scan_enabled:
            return

        now = time.time()

        # === 1. Unique Ports (Best for "excessive" / random scans like Nmap -T4) ===
        if src not in self.scan_tracking:
            self.scan_tracking[src] = deque(maxlen=64)  # bound memory

        track = self.scan_tracking[src]
        track.append((now, dport))

        # Prune old entries
        while track and now - track[0][0] > self.port_scan_window:
            track.popleft()

        unique_ports = {p[1] for p in track}
        if len(unique_ports) >= self.port_scan_unique_threshold:
            msg = (f"PORT SCAN: {src} touched {len(unique_ports)} unique {proto} ports "
                   f"in last {self.port_scan_window}s")
            if msg not in self.history:
                self.history.add(msg)
                self.alert_cb(msg)

        # === 2. Sequential / Incremental Scan Detection ===
        key = (src, proto)
        if key not in self.incremental_tracking:
            self.incremental_tracking[key] = {'last': dport, 'streak': 1, 'time': now}
        else:
            state = self.incremental_tracking[key]
            time_gap = now - state['time']
            port_gap = abs(dport - state['last'])

            if time_gap > 8.0 or port_gap > 5:  # Reset on large gaps
                if state['streak'] >= self.port_scan_sequential_threshold:
                    msg = f"SEQ SCAN: {src} finished {proto} sequence of {state['streak']} ports"
                    if msg not in self.history:
                        self.history.add(msg)
                        self.alert_cb(msg)
                state['streak'] = 1
            elif port_gap >= 1:
                state['streak'] += 1

                if state['streak'] >= self.port_scan_sequential_threshold:
                    msg = f"SEQ SCAN DETECTED: {src} scanning {state['streak']} consecutive {proto} ports"
                    if msg not in self.history:
                        self.history.add(msg)
                        self.alert_cb(msg)

            state['last'] = dport
            state['time'] = now

    def _audit_host_scan(self, src: str, dst: str, scan_type: str = "ICMP") -> None:
        """Detect host scanning via ICMP or ARP (nmap -sn, fing, wifimon, etc.)."""
        if not self.host_scan_enabled:
            return

        now = time.time()

        # Select appropriate tracking structure and window
        if scan_type == "ARP":
            tracking = self.arp_scan_tracking
            window = self.host_scan_window * 1.25  # ARP scans tend to be burstier
        else:
            tracking = self.host_scan_tracking
            window = self.host_scan_window

        if src not in tracking:
            tracking[src] = deque(maxlen=120)

        track = tracking[src]
        track.append((now, dst))

        # Prune old entries
        while track and now - track[0][0] > window:
            track.popleft()

        unique_hosts = {p[1] for p in track}
        if len(unique_hosts) >= self.host_scan_threshold:
            msg = (f"HOST SCAN: {src} probed {len(unique_hosts)} unique hosts "
                   f"in last {window:.1f}s ({scan_type} Discovery)")
            if msg not in self.history:
                self.history.add(msg)
                self.alert_cb(msg)

    def _audit_flood(self, src: str, tracking_dict: Dict[str, deque], label: str, threshold: int) -> None:
        """Generic flood detection using sliding window."""
        now = time.time()
        if src not in tracking_dict:
            tracking_dict[src] = deque()

        track = tracking_dict[src]
        track.append(now)

        # Prune old entries
        while track and now - track[0] > 5.0:
            track.popleft()

        if len(track) > threshold:
            msg = f"{label}: Potential attack from {src} ({len(track)} events in 5s)"
            if msg not in self.history:
                self.history.add(msg)
                self.alert_cb(msg)

    def audit_tls(self, summary: Dict[str, Any]) -> None:
        """Surface alerts for expired / self‑signed certs (unchanged)."""
        tls_info = summary.get('tls_info') or {}
        sni = tls_info.get('sni') or summary.get('dst', '')
        for cert in tls_info.get('certs', []):
            subj = cert.get('subject', 'Unknown')
            key = f"{sni}|{subj}"
            if cert.get('is_expired') and key not in self.expired_cert_history:
                self.expired_cert_history.add(key)
                self.alert_cb(f"CERT EXPIRED: {sni} ({subj})")
            if cert.get('is_self_signed') and key not in self.selfsigned_cert_history:
                self.selfsigned_cert_history.add(key)
                self.alert_cb(f"SELF‑SIGNED CERT: {sni} ({subj})")
                
    def audit_dns_tunneling(self, summary: Dict[str, Any]) -> None:
        """Heuristic DNS tunneling detector:
        flags long subdomain labels and high-entropy names."""
        if summary.get('proto') not in ('DNS',):
            return
        for layer in summary.get('layers', []):
            if layer.get('name') != 'DNS':
                continue
            queries = layer.get('queries', [])
            for q in queries:
                name = q.get('name', '')
                if not name:
                    continue
            labels = name.split('.')
            # Flag 1: any single label > 50 chars
            if long_labels:
                self.alert_cb(
                        f"[DNS-TUNNEL] Long label in query '{name[:80]}' "
                        f"from {summary.get('src', '?')} "
                        f"({len(long_labels)} oversized label(s))"
                    )
                    return
                # Flag 2: total FQDN > 100 chars with ≥ 4 labels
                if len(name) > 100 and len(labels) >= 4:
                    # Entropy check on first label
                    first = labels[0]
                    if len(first) > 20:
                        entropy = self._shannon_entropy(first)
                        if entropy > 3.8:
                            self.alert_cb(
                                f"[DNS-TUNNEL] High-entropy DNS label "
                                f"'{first[:40]}' (H={entropy:.2f}) "
                                f"from {summary.get('src', '?')}"
                            )
                            return
                            
    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        from math import log2
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((c / n) * log2(c / n) for c in freq.values())
        
    def audit_cleartext_credentials(self, summary: Dict[str, Any]) -> None:
        """Alert on credential leaks detected by FastDissector."""
        creds = summary.get('creds', [])
        for cred in creds:
            src = summary.get('src', '?')
            dst = summary.get('dst', '?')
            self.alert_cb(
                f"[CRED-LEAK] {cred.get('type', 'cred')} detected "
                f"{src} → {dst} | value preview: "
                f"{str(cred.get('value', ''))[:40]}"
            )
            
    def audit_llmnr_nbns(self, summary: Dict[str, Any]) -> None:
        """Detect LLMNR (5355/UDP) and NetBIOS-NS (137/UDP) traffic.
        These protocols are abused for poisoning (Responder)."""
        layers = summary.get('layers', [])
        for layer in layers:
            if layer.get('name') != 'UDP':
                continue
            dport = layer.get('dport', 0) or layer.get('dst_port', 0)
            if dport == 5355:
                self.alert_cb(
                    f"[LLMNR] LLMNR query from {summary.get('src', '?')} — "
                    f"susceptible to poisoning (Responder/Inveigh)"
                )
            elif dport == 137:
                self.alert_cb(
                    f"[NBNS] NetBIOS Name Service from {summary.get('src', '?')} — "
                    f"susceptible to NBNS spoofing"
                )

    def audit_brute_force(self, summary: Dict[str, Any],
                          ts: float) -> None:
        """Track authentication failure patterns on common service ports.
        Ports: SSH(22), FTP(21), RDP(3389), SMB(445), Telnet(23), IMAP(143),
               POP3(110), SMTP(25/587), HTTP-Auth(80/443/8080/8443)."""
        _AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 587, 3389,
                       80, 443, 8080, 8443}
        _THRESHOLD  = 10   # failed attempts per window
        _WINDOW     = 30.0  # seconds

        layers = summary.get('layers', [])
        for layer in layers:
            if layer.get('name') not in ('TCP', 'UDP'):
                continue
            dport = layer.get('dport', 0) or layer.get('dst_port', 0)
            if dport not in _AUTH_PORTS:
                continue
            src = summary.get('src', '?').split(':')[0]
            key = (src, dport)

            if not hasattr(self, '_brute_tracking'):
                self._brute_tracking: Dict[Any, deque] = {}
            if not hasattr(self, '_brute_alerted'):
                self._brute_alerted: Set[Any] = set()

            window = self._brute_tracking.setdefault(key, deque())
            window.append(ts)
            # Prune outside window
            while window and ts - window[0] > _WINDOW:
                window.popleft()

            if len(window) >= _THRESHOLD and key not in self._brute_alerted:
                self._brute_alerted.add(key)
                self.alert_cb(
                    f"[BRUTE-FORCE] {src} → port {dport}: "
                    f"{len(window)} packets in {_WINDOW:.0f}s window"
                )
                # Reset after alerting so it can re-trigger
                window.clear()
                self._brute_alerted.discard(key)
                
    def audit_bandwidth_threshold(self, bps: float,
                                  threshold_mbps: float = 100.0) -> None:
        """Alert if bandwidth exceeds a configured threshold (default 100 Mbps)."""
        threshold_bps = threshold_mbps * 1_000_000 / 8
        if bps > threshold_bps:
            self._bw_last_alert = 0.0
        now = time.monotonic()
        if now - self._bw_last_alert > 10.0:
            self._bw_last_alert = now
                mbps_actual = bps * 8 / 1_000_000
                self.alert_cb(
                    f"[BW-THRESH] Bandwidth {mbps_actual:.1f} Mbps "
                    f"exceeds threshold {threshold_mbps:.0f} Mbps"
                )

    def active_probe(self, target_ip: str, interface: str) -> None:
        """Send ARP probe (unchanged)."""
        try:
            sha = get_iface_mac(interface)
            spa = get_iface_ip(interface)
            tpa = socket.inet_aton(target_ip)

            arp = dpkt.arp.ARP(op=dpkt.arp.ARP_OP_REQUEST, sha=sha, spa=spa,
                                tha=b'\x00' * 6, tpa=tpa)
            eth = dpkt.ethernet.Ethernet(dst=b'\xff' * 6, src=sha,
                                          type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)

            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            try:
                s.bind((interface, 0))
                s.send(bytes(eth))
            finally:
                s.close()
            self.alert_cb(f"[*] ARP probe sent to {target_ip}")
        except PermissionError:
            self.alert_cb("[!] Probe failed: requires root privileges")
        except Exception as e:
            logger.warning("raw probe failed: %s", e)
            if SCAPY_AVAILABLE:
                try:
                    pkt = ScapyEther(dst="ff:ff:ff:ff:ff:ff") / ScapyARP(pdst=target_ip)
                    scapy_srp(pkt, timeout=1, iface=interface, verbose=False)
                    self.alert_cb(f"[*] ARP probe (scapy fallback) sent to {target_ip}")
                except Exception as e2:
                    self.alert_cb(f"[!] Probe failed: {e2}")
            else:
                self.alert_cb(f"[!] Probe failed: {e} (install scapy for fallback)")


# -----------------------------------------------------------------
# Core

class VimSharkApp:
    """Top‑level TUI application: owns the capture thread, packet store,
    urwid widget tree, and input dispatch."""

    def __init__(self, interface: str = "eth0", read_pcap: Optional[str] = None,
                 write_pcap: Optional[str] = None, max_packets: int = 5000,
                 batch_size: int = 100, max_rate: float = 0.0,
                 max_display: int = 500, theme: str = "btop_classic", scan_threshold: int = 12):
        self.interface = interface
        self.read_pcap = read_pcap
        self.write_pcap = write_pcap
        self.max_packets = max_packets
        self.batch_size = batch_size
        self.max_rate = max_rate
        self.max_display = max_display

        self.telemetry = TrafficTelemetry()
        self.dissector = FastDissector()
        self.pkt_queue: "queue.Queue[int]" = queue.Queue()
        self.alert_queue: "queue.Queue[str]" = queue.Queue()
        self.auditor = ThreatAuditor(self.queue_alert)
        self.auditor.port_scan_unique_threshold = scan_threshold
        self.auditor.host_scan_enabled = True
        self.reassembler = IPReassembler()
        self.flow_tracker = FlowTracker()
        self.store = PacketStore(max_packets=max_packets)

        self.is_running = True
        self.paused = False
        self.current_theme = theme if theme in THEMES else "btop_classic"
        self.current_pkt_idx: Optional[int] = None
        self.hex_search_query = ""
        self.display_filter = ""
        self.filter_fn: Callable[[Dict[str, Any]], bool] = compile_filter("")
        self._capture_thread: Optional[threading.Thread] = None
        self.loop: Optional[urwid.MainLoop] = None

        self.setup_ui()

    # ------------------------------------------------------------------ 
    # UI
    def setup_ui(self) -> None:
        self._theme_attrs = {entry[0] for entry in THEMES[self.current_theme]}

        src = self.read_pcap or self.interface
        self.header = urwid.Text(
            f" \U0001F988 vimShark v{__version__} | {src} | Theme: {self.current_theme} | "
            f"Buffer: 0/{self.max_packets}"
        )
        self.header_attr = urwid.AttrMap(self.header, 'header')

        self.filter_edit = urwid.Edit(" Filter: ")
        urwid.connect_signal(self.filter_edit, 'change', self.on_filter_change)
        self.filter_attr = urwid.AttrMap(self.filter_edit, 'bg', 'text_focus')

        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)
        self.left_top = urwid.LineBox(urwid.Pile([
            ('pack', self.filter_attr),
            ('weight', 1, self.listbox),
        ]), title="Traffic Stream")

        self.tel_pkt = urwid.Text("Throughput: 0 p/s")
        self.tel_byte = urwid.Text("Bandwidth:  0 B/s")
        self.tel_total = urwid.Text("Total: 0 pkts / 0B")
        self.left_bottom = urwid.LineBox(
            urwid.Filler(urwid.Pile([self.tel_pkt, self.tel_byte, self.tel_total])),
            title="Telemetry"
        )
        self.left_pane = urwid.Pile([('weight', 4, self.left_top), ('weight', 1, self.left_bottom)])

        self.det_walker = urwid.SimpleFocusListWalker([urwid.Text("Select a packet...")])
        self.hex_walker = urwid.SimpleFocusListWalker([urwid.Text("")])
        self.alrt_walker = urwid.SimpleFocusListWalker([])

        self.right_pane = urwid.Pile([
            ('weight', 3, urwid.LineBox(urwid.ListBox(self.det_walker), title="Dissection")),
            ('weight', 2, urwid.LineBox(urwid.ListBox(self.hex_walker), title="Hex Dump")),
            ('weight', 1, urwid.LineBox(urwid.ListBox(self.alrt_walker), title="Security")),
        ])

        self.body = urwid.Columns([('weight', 3, self.left_pane), ('weight', 2, self.right_pane)], dividechars=1)
        self.footer = urwid.Text(
            " [Q]uit [T]heme [P]ause [F]ollow [S]earch Hex [E]xport [V]alidate "
            " [C]lear [L]Flows [A]uditor [/]Filter"
        )
        self.root = urwid.Frame(
            urwid.AttrMap(self.body, 'bg'),
            header=self.header_attr,
            footer=urwid.AttrMap(self.footer, 'footer'),
        )

    # --------------------------------------------------------------- 
    # alerts
    def queue_alert(self, msg: str) -> None:
        self.alert_queue.put(msg)

    # --------------------------------------------------------------- 
    # filter
    def on_filter_change(self, widget: urwid.Edit, text: str) -> None:
        self.display_filter = text
        self.filter_fn = compile_filter(text)
        self.refresh_display()

    def refresh_display(self) -> None:
        """Rebuild the visible row list from the PacketStore using the current filter."""
        new_rows = []
        for idx in self.store.all_indices():
            item = self.store.get(idx)
            if item is None:
                continue
            _, summary, _ = item
            if self.filter_fn(summary):
                new_rows.append(self.build_row(idx, summary))

        # Limit visible rows
        if len(new_rows) > self.max_display:
            new_rows = new_rows[-self.max_display:]

        self.walker[:] = new_rows
        # Ensure focus is valid
        if self.walker and self.listbox.focus_position >= len(self.walker):
            self.listbox.set_focus(len(self.walker) - 1)

    # ----------------------------------------------------------- 
    # row build
    def build_row(self, idx: int, summary: Dict[str, Any]) -> urwid.AttrMap:
        proto = summary['proto'].lower()
        attr = f"pkt_{proto}" if f"pkt_{proto}" in self._theme_attrs else "pkt_other"

        summ_text = summary['summary']
        if len(summ_text) > 60:
            summ_text = summ_text[:57] + "..."

        # Marker column: combine credential + TLS/JA3 indicators
        markers = []
        if summary.get('creds'):
            markers.append('!')
        tls_info = summary.get('tls_info') or {}
        if tls_info.get('alert'):
            markers.append('⚠')
        if tls_info.get('ja3') and tls_info['ja3'] != "N/A":
            markers.append('J')
        if tls_info.get('certs'):
            if any(c.get('is_expired') or c.get('is_self_signed') for c in tls_info['certs']):
                markers.append('X')
            else:
                markers.append('C')
        marker = "".join(markers).ljust(2)[:2] if markers else "  "

        line = (
            f"#{idx:<5}{marker}| {summary['src']:<22} -> {summary['dst']:<22} | "
            f"{summary['proto']:<7} | {summ_text}"
        )
        btn = urwid.Button(line)
        btn._pkt_idx = idx  # lightweight int reference only
        urwid.connect_signal(btn, 'click', self.on_packet_click)
        return urwid.AttrMap(btn, attr, 'text_focus')

    # ------------------------------------------------------------- 
    # details
    def on_packet_click(self, btn: urwid.Button) -> None:
        idx = getattr(btn, '_pkt_idx', None)
        if idx is None:
            return
        self.current_pkt_idx = idx
        item = self.store.get(idx)
        if item is None:
            return
        raw, info, _ = item

        details: List[urwid.Widget] = [
            urwid.AttrMap(urwid.Text(f"### Packet #{idx} Dissection ###"), 'header'),
            urwid.Text(f"Length: {info.get('len', len(raw))} bytes"),
            urwid.Text(""),
        ]

        # Core protocol layers
        for layer_name, fields in info.get('layers', []):
            details.append(urwid.AttrMap(urwid.Text(f"-- {layer_name} --"), 'border'))
            for k, v in fields.items():
                if k == 'data' or k.startswith('_') or callable(v):
                    continue
                sval = FastDissector._safe_str(v, 90)
                details.append(urwid.Text(f"  {k:<18}: {sval}"))

        # TLS / SSL section
        tls_info = info.get('tls_info', {})
        if tls_info and tls_info.get('handshake_type') != "Unknown":
            details.append(urwid.Text(""))
            details.append(urwid.AttrMap(urwid.Text("=== TLS / SSL ==="), 'pkt_tls'))
            details.append(urwid.Text(f"  Message Type : {tls_info.get('handshake_type')}"))

            if tls_info.get('version_name'):
                ver_text = tls_info['version_name']
                if tls_info.get('tls13') and "1.3" not in ver_text:
                    ver_text += " (negotiating TLS 1.3)"
                details.append(urwid.Text(f"  Version      : {ver_text}"))

            if tls_info.get('cipher'):
                cipher_id = tls_info['cipher']
                name = FastDissector._CIPHER_SUITES.get(cipher_id, "UNKNOWN")
                details.append(urwid.Text(f"  Cipher Suite : 0x{cipher_id:04x} ({name})"))

            if tls_info.get('sni'):
                details.append(urwid.Text(f"  SNI          : {tls_info['sni']}"))

            if tls_info.get('alpn'):
                details.append(urwid.Text(f"  ALPN         : {', '.join(tls_info['alpn'])}"))

            if tls_info.get('alert'):
                details.append(urwid.AttrMap(
                    urwid.Text(f"  TLS Alert    : {tls_info['alert']}"), 'warn'))

            # JA3 (client fingerprint)
            ja3 = tls_info.get('ja3')
            if ja3 and ja3 != "N/A":
                details.append(urwid.AttrMap(urwid.Text(f"  JA3          : {ja3}"), 'ja3'))
                ja3i = tls_info.get('ja3_info', {})
                if ja3i.get('ciphers'):
                    details.append(urwid.Text(f"    Ciphers    : {len(ja3i['ciphers'])} offered"))
                if ja3i.get('curves'):
                    details.append(urwid.Text(f"    Curves     : {'-'.join(map(str, ja3i['curves']))}"))
                if ja3i.get('supported_versions'):
                    vnames = [_TLS_VERSION_NAMES.get(v, f"0x{v:04x}") for v in ja3i['supported_versions']]
                    details.append(urwid.Text(f"    Offers     : {', '.join(vnames)}"))

            # JA3S (server fingerprint)
            ja3s = tls_info.get('ja3s')
            if ja3s and ja3s != "N/A":
                details.append(urwid.AttrMap(urwid.Text(f"  JA3S         : {ja3s}"), 'ja3'))

            if tls_info.get('ocsp_stapled'):
                details.append(urwid.AttrMap(urwid.Text("  OCSP Stapling: Present"), 'good'))

            # Certificates
            certs = tls_info.get('certs', [])
            if certs:
                details.append(urwid.Text(""))
                details.append(urwid.AttrMap(
                    urwid.Text(f"=== Certificates ({len(certs)}) ==="), 'pkt_tls'))

                for i, cert in enumerate(certs):
                    bad = cert.get('is_expired') or cert.get('is_self_signed') or cert.get('is_not_yet_valid')
                    header_color = 'warn' if bad else 'pkt_tls'
                    details.append(urwid.AttrMap(urwid.Text(f"  Cert #{i + 1}:"), header_color))

                    details.append(urwid.Text(f"    Subject   : {cert.get('subject', 'Unknown')}"))
                    details.append(urwid.Text(f"    Issuer    : {cert.get('issuer', 'Unknown')}"))
                    details.append(urwid.Text(
                        f"    Valid     : {fmt_ts(cert.get('not_before'))} -> {fmt_ts(cert.get('not_after'))}"
                    ))

                    days = cert.get('days_remaining')
                    if days is not None and not cert.get('is_expired'):
                        warn_soon = days <= 14
                        details.append(urwid.AttrMap(
                            urwid.Text(f"    Expires in: {days} day(s)"),
                            'warn' if warn_soon else 'dim'
                        ))

                    if cert.get('is_expired'):
                        details.append(urwid.AttrMap(urwid.Text("    [!] CERTIFICATE EXPIRED"), 'warn'))
                    if cert.get('is_not_yet_valid'):
                        details.append(urwid.AttrMap(urwid.Text("    [!] CERTIFICATE NOT YET VALID"), 'warn'))
                    if cert.get('is_self_signed'):
                        details.append(urwid.AttrMap(urwid.Text("    [!] Self‑Signed Certificate"), 'warn'))

                    if cert.get('pubkey_algorithm'):
                        details.append(urwid.Text(f"    Public Key: {cert['pubkey_algorithm']}"))
                    if cert.get('signature_algorithm'):
                        details.append(urwid.Text(f"    Signature : {cert['signature_algorithm']}"))
                    if cert.get('serial'):
                        details.append(urwid.Text(f"    Serial    : {cert['serial']}"))

                    if cert.get('san'):
                        san_preview = ', '.join(cert['san'][:5])
                        if len(cert['san']) > 5:
                            san_preview += " ..."
                        details.append(urwid.Text(f"    SAN       : {san_preview}"))

                    fp256 = cert.get('fingerprint_sha256')
                    if fp256:
                        details.append(urwid.Text(f"    SHA256    : {fp256}"))
                    fp1 = cert.get('fingerprint_sha1')
                    if fp1:
                        details.append(urwid.Text(f"    SHA1      : {fp1}"))

                    if cert.get('ocsp_responders'):
                        details.append(urwid.Text(f"    OCSP      : {cert['ocsp_responders'][0]}"))
                    if cert.get('crl_distribution_points'):
                        details.append(urwid.Text(f"    CRL       : {cert['crl_distribution_points'][0]}"))

        # Credential warnings
        if info.get('creds'):
            details.append(urwid.Text(""))
            details.append(urwid.AttrMap(urwid.Text("!! POTENTIAL CREDENTIAL EXPOSURE !!"), 'warn'))
            for c in info['creds']:
                details.append(urwid.Text(f"   - {c}"))

        self.det_walker[:] = details
        self.update_hex_view()

    def update_hex_view(self) -> None:
        if self.current_pkt_idx is None:
            self.hex_walker[:] = [urwid.Text("")]
            return
        item = self.store.get(self.current_pkt_idx)
        if not item:
            return
        raw, _, _ = item

        hd = self.dissector.get_hexdump(raw)
        lines = hd.splitlines()
        if not self.hex_search_query:
            self.hex_walker[:] = [urwid.Text(l) for l in lines]
            return

        query = self.hex_search_query.lower()
        new_hex_rows = []
        for line in lines:
            if query in line.lower():
                parts, last_end = [], 0
                lower_line = line.lower()
                start = lower_line.find(query)
                while start != -1:
                    parts.extend([line[last_end:start], ('selected', line[start:start + len(query)])])
                    last_end = start + len(query)
                    start = lower_line.find(query, last_end)
                parts.append(line[last_end:])
                new_hex_rows.append(urwid.Text(parts))
            else:
                new_hex_rows.append(urwid.Text(line))
        self.hex_walker[:] = new_hex_rows

    # --------------------------------------------------------------- 
    # capture
    def capture_loop(self) -> None:
        """Background thread: capture, dissect, store, enqueue index only.
        Never touches urwid widgets directly."""
        try:
            if self.read_pcap:
                cap = pcapy.open_offline(self.read_pcap)
            else:
                cap = pcapy.open_live(self.interface, 65535, 1, 100)
        except Exception as e:
            logger.exception("capture init failed")
            self.queue_alert(f"Capture init error: {e}")
            return

        writer = None
        if self.write_pcap:
            try:
                writer = cap.dump_open(self.write_pcap)
            except Exception as e:
                logger.warning("pcap writer init failed: %s", e)
                self.queue_alert(f"PCAP write init failed: {e}")

        last_packet_time = 0.0
        min_interval = (1.0 / self.max_rate) if self.max_rate > 0 else 0.0

        while self.is_running:
            try:
                header, data = cap.next()
                if not data:
                    if self.read_pcap:
                        break
                    continue

                if writer is not None:
                    try:
                        writer.dump(header, data)
                    except Exception as e:
                        logger.warning("pcap write error, disabling writer: %s", e)
                        self.queue_alert(f"PCAP write error (disabled): {e}")
                        writer = None

                if self.paused:
                    continue

                if min_interval:
                    now = time.monotonic()
                    if now - last_packet_time < min_interval:
                        continue
                    last_packet_time = now

                self._process_packet(data, header)

            except pcapy.PcapError:
                continue
            except Exception as e:
                logger.exception("capture loop error")
                self.queue_alert(f"Capture error: {e}")
                time.sleep(0.1)

    def _process_packet(self, data: bytes, header: Any) -> None:
        """Dissect a single raw frame, store it, and queue follow‑up work
        (telemetry, flow tracking, security audits, fragment reassembly)."""
        summary = self.dissector.dissect(data)
        ts_sec, ts_usec = header.getts()
        ts = ts_sec + ts_usec / 1_000_000.0

        idx = self.store.add(data, summary, ts)
        self.pkt_queue.put(idx)

        self.telemetry.accumulate(len(data))
        self.flow_tracker.update(summary, ts)
        self.auditor.audit_packet(data)
        if summary.get('proto') == 'TLS':
            self.auditor.audit_tls(summary)

        # IPv4 fragmentation reassembly
        try:
            eth = dpkt.ethernet.Ethernet(data)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                
                # Modern dpkt fragment detection (avoids deprecated ip.off completely)
                is_fragmented = False
                
                # Preferred modern attributes
                if hasattr(ip, 'mf') and getattr(ip, 'mf', 0) != 0:
                    is_fragmented = True
                elif hasattr(ip, 'offset') and getattr(ip, 'offset', 0) > 0:
                    is_fragmented = True
                
                if is_fragmented:
                    full_payload = self.reassembler.process(ip)
                    if full_payload:
                        # Reassemble
                        ip.data = full_payload
                        
                        # Clear fragment fields safely
                        if hasattr(ip, 'mf'):
                            ip.mf = 0
                        if hasattr(ip, 'offset'):
                            ip.offset = 0
                        # Do NOT touch ip.off at all
                        
                        # Update length
                        ip.len = len(ip) if hasattr(ip, 'len') else len(bytes(ip))
                        
                        eth.data = ip
                        res_raw = bytes(eth)
                        
                        res_summary = self.dissector.dissect(res_raw)
                        res_summary['summary'] = "[REASSEMBLED] " + res_summary['summary']
                        
                        res_idx = self.store.add(res_raw, res_summary, ts)
                        self.pkt_queue.put(res_idx)
                        
                        if res_summary.get('proto') == 'TLS':
                            self.auditor.audit_tls(res_summary)
        except Exception as e:
            logger.debug("reassembly handling error: %s", e)

    # ----------------------------------------------------------------- 
    # tick
    def ui_update_tick(self, loop: urwid.MainLoop, _user_data: Any) -> None:
        """Main‑thread heartbeat: drains queues in batches, updates telemetry."""
        new_rows = []
        processed = 0
        while processed < self.batch_size:
            try:
                idx = self.pkt_queue.get_nowait()
            except queue.Empty:
                break
            item = self.store.get(idx)
            if item is not None:
                _, summary, _ = item
                if self.filter_fn(summary):
                    new_rows.append(self.build_row(idx, summary))
            processed += 1

        if new_rows:
            self.walker.extend(new_rows)
            overflow = len(self.walker) - self.max_display
            if overflow > 0:
                del self.walker[:overflow]

        while True:
            try:
                msg = self.alert_queue.get_nowait()
            except queue.Empty:
                break
            self.alrt_walker.append(urwid.Text(f" {msg}"))
            if len(self.alrt_walker) > 50:
                del self.alrt_walker[0]
        if self.alrt_walker:
            self.alrt_walker.set_focus(len(self.alrt_walker) - 1)

        pr, br = self.telemetry.tick()
        self.tel_pkt.set_text(f"Throughput: {self.telemetry.format_unit(pr)} p/s  {self.telemetry.get_sparkline('p')}")
        self.tel_byte.set_text(f"Bandwidth:  {self.telemetry.format_unit(br, True)}/s  {self.telemetry.get_sparkline('b')}")
        self.tel_total.set_text(
            f"Total: {self.telemetry.format_unit(self.telemetry.total_packets)} pkts / "
            f"{self.telemetry.format_unit(self.telemetry.total_bytes, True)}"
        )

        status = "PAUSED" if self.paused else "LIVE"
        mode = "READ" if self.read_pcap else "CAPTURE"
        src = self.read_pcap or self.interface
        self.header.set_text(
            f" \U0001F988 vimShark v{__version__} | {src} | {mode} [{status}] | "
            f"Theme: {self.current_theme} | "
            f"Buffer: {len(self.store)}/{self.max_packets}"
        )

        loop.set_alarm_in(0.05, self.ui_update_tick)

    # --------------------------------------------------------------- 
    # input
    def handle_input(self, key: str) -> None:
        """Handle global key bindings. Navigation keys now safely delegate to ListBox."""
        if key in ('q', 'Q', 'esc'):
            if isinstance(self.root.body, urwid.Overlay):
                self._close_overlay()
                return
            # Normal quit only if no modal is open
            self.is_running = False
            raise urwid.ExitMainLoop()

        # === Navigation ===
        if key in ('k', 'K', 'up'):
            self._safe_listbox_keypress('up')
        elif key in ('j', 'J', 'down'):
            self._safe_listbox_keypress('down')
        elif key == '[':   # Previous packet
            try:
                if self.listbox.focus_position > 0:
                    self.listbox.set_focus(self.listbox.focus_position - 1)
            except (IndexError, AttributeError, TypeError):
                pass
        elif key == ']':   # Next packet
            try:
                self.listbox.set_focus(self.listbox.focus_position + 1)
            except (IndexError, AttributeError, TypeError):
                pass
        elif key in ('enter', ' '):
            focus = self.listbox.focus
            if focus and hasattr(focus.base_widget, '_pkt_idx'):
                self.on_packet_click(focus.base_widget)

        # === Other commands ===
        elif key in ('t', 'T'):
            self.cycle_theme()
        elif key in ('p', 'P'):
            self.paused = not self.paused
        elif key in ('c', 'C'):
            self.current_pkt_idx = None
            self.store.clear()
            self.flow_tracker.clear()
            self.walker[:] = []
            self.update_hex_view()
            self.auditor.history.clear()
            self.auditor.expired_cert_history.clear()
            self.auditor.selfsigned_cert_history.clear()
            self.auditor.icmp_tracking.clear()
            self.auditor.syn_tracking.clear()
            self.auditor.scan_tracking.clear()
            self.auditor.incremental_tracking.clear()
            self.auditor.host_scan_tracking.clear()
            self.auditor.arp_scan_tracking.clear()
        elif key == '/':
            # Focus filter
            self.root.focus_position = 'body'
            self.body.focus_position = 0
            self.left_pane.focus_position = 0
            self.left_top.original_widget.focus_position = 0
        elif key in ('e', 'E'):
            self.show_export_modal()
        elif key in ('s', 'S'):
            self.show_hex_search_modal()
        elif key in ('v', 'V'):
            self.show_validation_modal()
        elif key in ('f', 'F'):
            self.follow_stream()
        elif key in ('l', 'L'):
            self.show_flows_modal()
        elif key in ('a', 'A'):
            self.show_auditor_modal()

    def _safe_listbox_keypress(self, direction: str) -> None:
        """Safely send up/down keys to the ListBox even if size() is unavailable."""
        try:
            # Preferred: use the current screen size from the main loop
            if self.loop and hasattr(self.loop.screen, 'get_cols_rows'):
                size = self.loop.screen.get_cols_rows()
            else:
                # Fallback size (most terminals)
                size = (80, 25)
            self.listbox.keypress(size, direction)
        except Exception as e:  # Broad catch to prevent crashes on edge cases
            logger.debug("ListBox keypress failed (%s): %s", direction, e)
            # Fallback: try direct focus movement
            try:
                if direction == 'up' and self.listbox.focus_position > 0:
                    self.listbox.set_focus(self.listbox.focus_position - 1)
                elif direction == 'down':
                    self.listbox.set_focus(self.listbox.focus_position + 1)
            except Exception:
                pass

    def cycle_theme(self) -> None:
        names = list(THEMES.keys())
        cur = names.index(self.current_theme)
        self.current_theme = names[(cur + 1) % len(names)]
        self._theme_attrs = {entry[0] for entry in THEMES[self.current_theme]}
        if self.loop is not None:
            self.loop.screen.register_palette(THEMES[self.current_theme])
            self.loop.screen.clear()
        self.refresh_display()

    # --------------------------------------------------------------------- 
    # AUDITOR UI
    def _auditor_status(self) -> str:
        """Return a short status string used in the footer."""
        parts = []
        if self.auditor.arp_auditor_enabled:
            parts.append('ARP')
        if self.auditor.port_scan_enabled:
            parts.append('PORT‑SCAN')
        if getattr(self.auditor, 'host_scan_enabled', True):
            parts.append('HOST‑SCAN')
        if self.auditor.syn_auditor_enabled:
            parts.append('SYN')
        if self.auditor.icmp_auditor_enabled:
            parts.append('ICMP')
        return ', '.join(parts) or 'none'

    def _update_footer(self) -> None:
        """Re‑build the footer text so the toggle status is always visible."""
        base = " [Q]uit [T]heme [P]ause [F]ollow [S]earch Hex [E]xport [V]alidate " \
               "[C]lear [L]Flows [A]uditor [/]Filter"
        status = f"  Auditors: {self._auditor_status()}"
        self.footer.set_text(base + status)

    def show_auditor_modal(self) -> None:
        """Overlay with check‑boxes for each audit component (including new Host Scan)."""
        cb_arp   = urwid.CheckBox('ARP Spoof Detector', state=self.auditor.arp_auditor_enabled)
        cb_port  = urwid.CheckBox('Port‑Scan Detector', state=self.auditor.port_scan_enabled)
        cb_host  = urwid.CheckBox('Host Scan Detector (ICMP + ARP)', 
                                 state=getattr(self.auditor, 'host_scan_enabled', True))
        cb_syn   = urwid.CheckBox('TCP SYN‑Flood Detector', state=self.auditor.syn_auditor_enabled)
        cb_icmp  = urwid.CheckBox('ICMP Flood Detector', state=self.auditor.icmp_auditor_enabled)
        
        ok_btn   = urwid.Button('OK')
        cancel   = urwid.Button('Cancel')

        def apply(_b):
            self.auditor.arp_auditor_enabled   = cb_arp.get_state()
            self.auditor.port_scan_enabled     = cb_port.get_state()
            self.auditor.host_scan_enabled     = cb_host.get_state()
            self.auditor.syn_auditor_enabled   = cb_syn.get_state()
            self.auditor.icmp_auditor_enabled  = cb_icmp.get_state()
            self._update_footer()
            self._close_overlay()

        urwid.connect_signal(ok_btn,    'click', apply)
        urwid.connect_signal(cancel,    'click', self._close_overlay)

        pile = urwid.Pile([
            urwid.Text('--- Security Auditor Settings ---', align='center'),
            urwid.Divider(),
            cb_arp,
            cb_port,
            cb_host,
            cb_syn,
            cb_icmp,
            urwid.Divider(),
            urwid.Columns([ok_btn, cancel])
        ])
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(pile), title='Auditor Settings'),
            self.root.body, 'center', 58, 'middle', 18
        )
        self.root.body = overlay

    def _close_overlay(self, *_args) -> None:
        self.root.body = urwid.AttrMap(self.body, 'bg')

    # ------------------------------------------------------------- 
    # modals (export / hex / validation / flows)
    def show_validation_modal(self) -> None:
        edit = urwid.Edit("Target IP: ", "192.168.1.1")
        cb_arp = urwid.CheckBox("Passive ARP Validator", state=self.auditor.arp_auditor_enabled)
        cb_scan = urwid.CheckBox("Port Scan Detection", state=self.auditor.port_scan_enabled)
        btn = urwid.Button("Dispatch Probe")
        cancel = urwid.Button("Cancel")

        def go(_b):
            self.auditor.arp_auditor_enabled = cb_arp.get_state()
            self.auditor.port_scan_enabled = cb_scan.get_state()
            self.auditor.active_probe(edit.get_edit_text(), self.interface)
            self._close_overlay()

        urwid.connect_signal(btn, 'click', go)
        urwid.connect_signal(cancel, 'click', self._close_overlay)

        pile = urwid.Pile([
            urwid.Text("--- Security Configuration ---"),
            urwid.Divider(),
            cb_arp,
            cb_scan,
            urwid.Divider(),
            urwid.Text("--- Active ARP Probe ---"),
            edit,
            urwid.Columns([btn, cancel])
        ])

        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(pile), title="Security Validator"),
            self.root.body, 'center', 48, 'middle', 13
        )
        self.root.body = overlay

    def show_hex_search_modal(self) -> None:
        edit = urwid.Edit("Search Hex/ASCII: ", self.hex_search_query)
        btn, clear, cancel = urwid.Button("Search"), urwid.Button("Clear"), urwid.Button("Cancel")

        def do_search(_b):
            self.hex_search_query = edit.get_edit_text()
            self.update_hex_view()
            self._close_overlay()

        def do_clear(_b):
            self.hex_search_query = ""
            self.update_hex_view()
            self._close_overlay()

        urwid.connect_signal(btn, 'click', do_search)
        urwid.connect_signal(clear, 'click', do_clear)
        urwid.connect_signal(cancel, 'click', self._close_overlay)

        overlay = urwid.Overlay(
            urwid.LineBox(
                urwid.Filler(urwid.Pile([edit, urwid.Divider(), urwid.Columns([btn, clear, cancel])])),
                title="Hex Dump Search"
            ),
            self.root.body, 'center', 50, 'middle', 9
        )
        self.root.body = overlay

    def show_export_modal(self) -> None:
        edit     = urwid.Edit("Filename: ", "capture")
        fmt_pcap = urwid.RadioButton([], "PCAP")
        fmt_json = urwid.RadioButton(fmt_pcap.group, "JSON")
        fmt_csv  = urwid.RadioButton(fmt_pcap.group, "CSV")
        fmt_txt  = urwid.RadioButton(fmt_pcap.group, "Summary TXT")
        btn      = urwid.Button("Export")
        cancel   = urwid.Button("Cancel")

        def do_export(_b):
            base = edit.get_edit_text().strip() or "capture"
            if fmt_pcap.get_state():
                fn = base if base.endswith('.pcap') else base + '.pcap'
                self.export_filtered_packets(fn)
            elif fmt_json.get_state():
                fn = base if base.endswith('.json') else base + '.json'
                self.export_json(fn)
            elif fmt_csv.get_state():
                fn = base if base.endswith('.csv') else base + '.csv'
                self.export_csv(fn)
            else:
                fn = base if base.endswith('.txt') else base + '.txt'
                self.export_summary_txt(fn)
            self._close_overlay()

        urwid.connect_signal(btn, 'click', do_export)
        urwid.connect_signal(cancel, 'click', self._close_overlay)

        pile = urwid.Pile([
            urwid.Text("--- Export Filtered Traffic ---"),
            urwid.Divider(),
            edit,
            urwid.Divider(),
            urwid.Text("Format:"),
            fmt_pcap, fmt_json, fmt_csv, fmt_txt,
            urwid.Divider(),
            urwid.Columns([btn, cancel]),
        ])
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Filler(pile, valign='top'), title="Export"),
            self.root.body, 'center', 50, 'middle', 18
        )
        self.root.body = overlay

    def show_flows_modal(self) -> None:
        """Display the top flows by byte count, with JA3 hints where available."""
        rows: List[urwid.Widget] = [
            urwid.AttrMap(urwid.Text("--- Top Flows (by bytes, press q to close) ---"), 'header'),
            urwid.Text(""),
        ]
        for flow in self.flow_tracker.top_flows(20):
            a, b = flow['endpoints']
            size = TrafficTelemetry.format_unit(flow['bytes'], True)
            rows.append(urwid.Text(
                f"{a:<24} <-> {b:<24} | {flow['proto']:<5} | "
                f"{flow['packets']:>6} pkts | {size:>8}"
            ))
        if len(rows) == 2:
            rows.append(urwid.Text("(no flows recorded yet)"))

        close_btn = urwid.Button("Close")
        parent = self.root.body
        urwid.connect_signal(close_btn, 'click', lambda _b: setattr(self.root, 'body', parent))
        rows.append(urwid.Text(""))
        rows.append(close_btn)

        self.root.body = urwid.Overlay(
            urwid.LineBox(urwid.ListBox(urwid.SimpleListWalker(rows)), title="Flow Table"),
            parent, 'center', ('relative', 80), 'middle', ('relative', 80)
        )
        
    def show

    def export_filtered_packets(self, filename: str) -> None:
        try:
            count = 0
            with open(filename, 'wb') as f:
                writer = dpkt.pcap.Writer(f)
                for idx in self.store.all_indices():
                    item = self.store.get(idx)
                    if item:
                        raw, summary, ts = item
                        if self.filter_fn(summary):
                            writer.write_pkt(raw, ts)
                            count += 1
            self.queue_alert(f"Successfully exported {count} packets to {filename}")
        except Exception as e:
            self.queue_alert(f"Export failed: {e}")
            
    def export_json(self, filename: str) -> None:
        """Export all visible (filtered) packets as a JSON array."""
        try:
            records = []
            for idx in self.store.all_indices():
                item = self.store.get(idx)
                if not item:
                    continue
                raw, summary, ts = item
                if not self.filter_fn(summary):
                    continue
                # Build a JSON-safe record
                record: Dict[str, Any] = {
                    'index':     idx,
                    'timestamp': ts,
                    'ts_iso':    datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                    'proto':     summary.get('proto', ''),
                    'src':       summary.get('src', ''),
                    'dst':       summary.get('dst', ''),
                    'length':    summary.get('len', 0),
                    'summary':   summary.get('summary', ''),
                    'creds':     summary.get('creds', []),
                }
                tls = summary.get('tls_info')
                if tls:
                    record['tls'] = {
                        'sni':  tls.get('sni', ''),
                        'ja3':  tls.get('ja3_md5', ''),
                        'ja3s': tls.get('ja3s_md5', ''),
                        'version': tls.get('version', ''),
                    }
                records.append(record)

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(records, f, indent=2, default=str)
            self.queue_alert(f"JSON export: {len(records)} packets → {filename}")
        except Exception as e:
            self.queue_alert(f"JSON export failed: {e}")

    def export_csv(self, filename: str) -> None:
        """Export filtered packets as CSV (timestamp, proto, src, dst, len, summary)."""
        try:
            count = 0
            fieldnames = ['index', 'timestamp', 'ts_iso', 'proto',
                          'src', 'dst', 'length', 'summary',
                          'tls_sni', 'ja3', 'has_creds']
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames,
                                        extrasaction='ignore')
                writer.writeheader()
                for idx in self.store.all_indices():
                    item = self.store.get(idx)
                    if not item:
                        continue
                    raw, summary, ts = item
                    if not self.filter_fn(summary):
                        continue
                    tls = summary.get('tls_info') or {}
                    row = {
                        'index':     idx,
                        'timestamp': f'{ts:.6f}',
                        'ts_iso':    datetime.fromtimestamp(
                                         ts, tz=timezone.utc).isoformat(),
                        'proto':     summary.get('proto', ''),
                        'src':       summary.get('src', ''),
                        'dst':       summary.get('dst', ''),
                        'length':    summary.get('len', 0),
                        'summary':   summary.get('summary', ''),
                        'tls_sni':   tls.get('sni', ''),
                        'ja3':       tls.get('ja3_md5', ''),
                        'has_creds': '1' if summary.get('creds') else '0',
                    }
                    writer.writerow(row)
                    count += 1
            self.queue_alert(f"CSV export: {count} packets → {filename}")
        except Exception as e:
            self.queue_alert(f"CSV export failed: {e}")

    def export_summary_txt(self, filename: str) -> None:
        """Human-readable session summary: protocol stats, top talkers, alerts."""
        try:
            lines = [
                f"vimShark Session Summary — {datetime.now().isoformat()}",
                f"Interface/Source: {self.read_pcap or self.interface}",
                f"Total packets in store: {len(self.store)}",
                "",
                "=== Protocol Distribution ===",
            ]
            dist = self.proto_stats.proto_distribution()
            for proto, pkts, byt, pct in dist[:20]:
                lines.append(
                    f"  {proto:<10} {pkts:>8} pkts  "
                    f"{TrafficTelemetry.format_unit(byt, True):>10}  "
                    f"{pct:5.1f}%"
                )
            lines += ["", "=== Top Talkers (by bytes sent) ==="]
            for ip, byt in self.proto_stats.top_talkers_src(10):
                lines.append(
                    f"  {ip:<20} {TrafficTelemetry.format_unit(byt, True):>10}"
                )
            lines += ["", "=== Top Destination Ports ==="]
            for port, cnt in self.proto_stats.top_ports(15):
                lines.append(f"  :{port:<6}  {cnt:>8} packets")
            lines += ["", "=== Recent Alerts ==="]
            for widget in self.alrt_walker:
                txt = getattr(widget, 'text', None)
                if txt:
                    if isinstance(txt, list):
                        txt = ''.join(
                            t if isinstance(t, str) else t[-1]
                            for t in txt
                        )
                    lines.append(f"  {txt}")

            baseline = self.baseline_detector.baseline_summary()
            lines += [
                "",
                "=== Traffic Baseline ===",
                f"  EMA pps: {baseline['ema_pps']:.1f}",
                f"  EMA bps: {TrafficTelemetry.format_unit(baseline['ema_bps'], True)}/s",
                f"  Learning: {baseline['learning']}",
                f"  Uptime:   {baseline['uptime']:.0f}s",
            ]

            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            self.queue_alert(f"Summary exported → {filename}")
        except Exception as e:
            self.queue_alert(f"Summary export failed: {e}")

    def _get_highlighted_markup(self, text: str, query: str) -> Any:
        """Helper to highlight search matches. Returns plain text or list markup."""
        if not query or not text or query.lower() not in text.lower():
            return text

        parts: List[Any] = []
        last_end = 0
        l_text = text.lower()
        l_query = query.lower()
        q_len = len(query)

        idx = l_text.find(l_query)
        while idx != -1:
            # Add normal text before match
            if idx > last_end:
                parts.append(text[last_end:idx])

            # Add highlighted segment
            highlight_text = text[idx:idx + q_len]
            parts.append(('selected', highlight_text))

            last_end = idx + q_len
            idx = l_text.find(l_query, last_end)

        # Add remaining text
        if last_end < len(text):
            parts.append(text[last_end:])

        # Filter out any empty strings
        cleaned = [p for p in parts if p != "" and (not isinstance(p, str) or p)]
        return cleaned if cleaned else text

    def follow_stream(self) -> None:
        focus = self.listbox.focus
        if not focus:
            self.queue_alert("No packet selected")
            return

        btn = focus.base_widget
        idx = getattr(btn, '_pkt_idx', None)
        if idx is None:
            self.queue_alert("Invalid packet selection")
            return

        item = self.store.get(idx)
        if item is None:
            return

        raw, _summary, _ = item

        try:
            eth = dpkt.ethernet.Ethernet(raw)
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                self.queue_alert("Not an IP packet")
                return

            ip_pkt = eth.data

            if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                proto_class = dpkt.tcp.TCP
                proto_label = "TCP"
            elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                proto_class = dpkt.udp.UDP
                proto_label = "UDP"
            else:
                self.queue_alert("Not a TCP/UDP packet")
                return

            transport = ip_pkt.data
            addr_set = {(ip_pkt.src, transport.sport), (ip_pkt.dst, transport.dport)}
            orig_src = (ip_pkt.src, transport.sport)
            is_v6 = isinstance(ip_pkt, dpkt.ip6.IP6)
            addr_to_str = ip6_to_str if is_v6 else ip_to_str

            src_str = addr_to_str(ip_pkt.src)
            dst_str = addr_to_str(ip_pkt.dst)

            if not hasattr(self, '_stream_dir_filter'):
                self._stream_dir_filter = "both"

            stream_rows: List[urwid.Widget] = [
                urwid.AttrMap(urwid.Text(
                    f"--- {proto_label} Stream {src_str}:{transport.sport} <-> "
                    f"{dst_str}:{transport.dport} | Filter: {self._stream_dir_filter.upper()} (D = cycle) ---",
                    wrap='any'
                ), 'header'),
                urwid.Text(""),
            ]

            for i in self.store.all_indices():
                rec = self.store.get(i)
                if rec is None:
                    continue
                r, _, _ = rec
                try:
                    e = dpkt.ethernet.Ethernet(r)
                except Exception:
                    continue
                if not isinstance(e.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                p_ip = e.data
                p_data = getattr(p_ip, 'data', None)
                if not isinstance(p_data, proto_class):
                    continue

                pair = {(p_ip.src, getattr(p_data, 'sport', None)), 
                        (p_ip.dst, getattr(p_data, 'dport', None))}
                if pair != addr_set:
                    continue

                is_outgoing = (p_ip.src, getattr(p_data, 'sport', None)) == orig_src
                if self._stream_dir_filter == "outgoing" and not is_outgoing:
                    continue
                if self._stream_dir_filter == "incoming" and is_outgoing:
                    continue

                payload = getattr(p_data, 'data', None)
                if not payload:
                    continue
                if not isinstance(payload, bytes):
                    try:
                        payload = bytes(payload)
                    except Exception:
                        continue

                txt = "".join(
                    chr(b) if 32 <= b <= 126 or b in (10, 13) else "." 
                    for b in payload[:2048]
                )
                direction = '->' if is_outgoing else '<-'
                color = 'pkt_tcp' if direction == '->' else 'pkt_udp'

                prefix = f"[{direction}] "
                if self.hex_search_query and isinstance(self.hex_search_query, str):
                    highlighted = self._get_highlighted_markup(txt, self.hex_search_query)
                    if isinstance(highlighted, list):
                        markup = [('default', prefix)] + highlighted
                    else:
                        markup = prefix + txt
                else:
                    markup = prefix + txt

                text_widget = urwid.Text(markup, wrap='clip', align='left')
                columns = urwid.Columns([
                    ('fixed', 3, urwid.Text('')),
                    
                    ('weight', 1, text_widget),
                    ('fixed', 3, urwid.Text('')),        
                ], dividechars=0)

                stream_rows.append(urwid.AttrMap(columns, color))

            close_btn = urwid.Button("Close")
            urwid.connect_signal(close_btn, 'click', self._close_overlay)

            stream_rows.append(urwid.Text(""))
            stream_rows.append(close_btn)

            parent = self.root.body
            listbox = urwid.ListBox(urwid.SimpleListWalker(stream_rows))
            inner = urwid.Padding(listbox, left=2, right=2)
            lined = urwid.LineBox(inner, title=f"{proto_label} Stream Follow")

            overlay = urwid.Overlay(
                lined,
                parent, 
                'center', ('relative', 90), 
                'middle', ('relative', 85)
            )
            self.root.body = overlay

        except Exception as e:
            logger.debug("follow_stream error: %s", e)
            self.queue_alert(f"Stream follow error: {e}")

    # -----------------------------------------------------------------
    # Init
    def run(self) -> None:
        if not self.read_pcap and os.getuid() != 0:
            print("[!] Live capture requires sudo/root.")
            sys.exit(1)

        self.loop = urwid.MainLoop(self.root, THEMES[self.current_theme], unhandled_input=self.handle_input)
        self.loop.screen.set_terminal_properties(colors=256)

        self._capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
        self._capture_thread.start()

        self.loop.set_alarm_in(0.1, self.ui_update_tick)

        try:
            self.loop.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.is_running = False
            if self._capture_thread is not None:
                self._capture_thread.join(timeout=1.0)
            logger.info("vimShark shut down cleanly")



# -----------------------------------------------------------------
# Entry

def main() -> None:
    parser = argparse.ArgumentParser(description=f"vimShark v{__version__}")
    parser.add_argument("-i", "--interface", default="eth0", help="Capture interface")
    parser.add_argument("-r", "--read", help="Read from a PCAP file instead of live capture")
    parser.add_argument("-o", "--output", help="Write captured packets to a PCAP file")
    parser.add_argument("-b", "--buffer", type=int, default=5000,
                        help="Packet store capacity (ring buffer size)")
    parser.add_argument("--scan-threshold", type=int, default=12,
                        help="Threshold for scan detection.")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Max packets drained from queue per UI tick")
    parser.add_argument("--max-rate", type=float, default=0.0,
                        help="Throttle: max packets/sec to process (0 = unlimited)")
    parser.add_argument("--max-display", type=int, default=500,
                        help="Max rows kept in the visible traffic list")
    parser.add_argument("--theme", default="btop_classic",
                        choices=list(THEMES.keys()), help="Initial color theme")
    parser.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Log verbosity (written to vimshark.log)")
    parser.add_argument("--credits",action="store_true",help="Shows credits & exits.")
    args = parser.parse_args()

    logger.setLevel(getattr(logging, args.log_level))
    
    if args.credits:
        banner = [

        ]
        lines = [
            "Developed"
        ]
        print("\n".join(lines))
        sys.exit(0)

    if not CRYPTOGRAPHY_AVAILABLE:
        logger.warning("'cryptography' not installed - certificate parsing will be limited to SHA fingerprints")

    app = VimSharkApp(
        interface=args.interface,
        read_pcap=args.read,
        write_pcap=args.output,
        max_packets=args.buffer,
        batch_size=args.batch_size,
        max_rate=args.max_rate,
        max_display=args.max_display,
        theme=args.theme,
        scan_threshold=args.scan_threshold,
    )
    app.run()


if __name__ == "__main__":
    main()