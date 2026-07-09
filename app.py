# ///////////////////////////////////////////
# /////////    Main Dev Only  ///////////////
# ///////////////////////////////////////////


from datetime import datetime
import numpy as np
import plost
import requests
import streamlit as st
import os
import random
from streamlit_folium import folium_static
from folium.plugins import MarkerCluster
import folium
from scapy.all import rdpcap, conf as scapy_conf
from scapy.layers.http import HTTPResponse, HTTPRequest
from scapy.layers.snmp import SNMP
from scapy.contrib.enipTCP import ENIPTCP, ENIPListIdentity
from scapy.contrib.modbus import (
    ModbusPDU2B0EReadDeviceIdentificationResponse, ModbusObjectId,
    ModbusADURequest, ModbusADUResponse,
)
import base64
import collections
import ipaddress
import pathlib
import pickle
import re
import struct
import tempfile
import sys
from streamlit_agraph import agraph, Node, Edge, Config
import pandas as pd
from scapy.utils import corrupt_bytes
from streamlit_echarts import st_echarts
import geoip2.database
import folium
from streamlit_option_menu import option_menu
from utils.pcap_decode import PcapDecode
import time
import plotly.express as px
from fpdf import FPDF
from fpdf.fonts import FontFace

PD = PcapDecode()  # Parser
PCAPS = None  # Packets

# ── Session persistence ───────────────────────────────────────────────────────
# Parsed packet data (scapy Packet objects) is pickled to disk so it survives
# a browser page-refresh without requiring the user to re-upload their files.
# The original UploadedFile objects cannot be persisted (they're tied to the
# active upload session), but the parsed pcap_data_by_file dict can.

_CACHE_DIR = pathlib.Path.home() / ".cache" / "ot-pcap-analyzer"
_CACHE_FILE = _CACHE_DIR / "session.pkl"


def _save_session_cache():
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            'pcap_data': st.session_state.pcap_data,
            'pcap_data_by_file': st.session_state.pcap_data_by_file,
            'parsed_file_signature': st.session_state.parsed_file_signature,
            'file_metadata': st.session_state.get('file_metadata', {}),
        }
        with open(_CACHE_FILE, 'wb') as f:
            pickle.dump(payload, f)
    except Exception:
        pass


def _load_session_cache():
    try:
        if not _CACHE_FILE.exists():
            return False
        with open(_CACHE_FILE, 'rb') as f:
            payload = pickle.load(f)
        st.session_state.pcap_data = payload.get('pcap_data')
        st.session_state.pcap_data_by_file = payload.get('pcap_data_by_file', {})
        st.session_state.parsed_file_signature = payload.get('parsed_file_signature')
        st.session_state.file_metadata = payload.get('file_metadata', {})
        return bool(st.session_state.pcap_data_by_file)
    except Exception:
        return False


def _clear_session_cache():
    try:
        if _CACHE_FILE.exists():
            _CACHE_FILE.unlink()
    except Exception:
        pass
# ─────────────────────────────────────────────────────────────────────────────


if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = None

if 'pcap_data' not in st.session_state:
    st.session_state.pcap_data = None

if 'pcap_data_by_file' not in st.session_state:
    st.session_state.pcap_data_by_file = {}

if 'parsed_file_signature' not in st.session_state:
    st.session_state.parsed_file_signature = None

if 'file_metadata' not in st.session_state:
    st.session_state.file_metadata = {}

if 'uploader_key_version' not in st.session_state:
    # Bumped whenever files are cleared/removed so the file_uploader widget
    # below is recreated with a fresh key - otherwise Streamlit keeps the
    # browser-side widget's previous selection and silently re-adds files
    # we just removed on the next rerun.
    st.session_state.uploader_key_version = 0

# Restore parsed data from disk on a fresh session (e.g. after page refresh).
if st.session_state.pcap_data is None and not st.session_state.pcap_data_by_file:
    _load_session_cache()

def get_all_pcap(PCAPS, PD):
    pcaps = collections.OrderedDict()
    for count, i in enumerate(PCAPS, 1):
        pcaps[count] = PD.ether_decode(i)
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    pcaps = collections.OrderedDict()
    count = 1
    for p in PCAPS:
        pcap = PD.ether_decode(p)
        if key == 'Procotol':
            if value == pcap.get('Procotol').upper():
                pcaps[count] = pcap
                count += 1
            else:
                pass
        elif key == 'Source':
            if value == pcap.get('Source').upper():
                pcaps[count] = pcap
                count += 1
        elif key == 'Destination':
            if value == pcap.get('Destination').upper():
                pcaps[count] = pcap
                count += 1
        else:
            pass
    return pcaps


def process_json_data(json_data):
    # Convert JSON data to a pandas DataFrame
    df = pd.DataFrame.from_dict(json_data, orient='index')
    return df


# To Calculate Live Time
def calculate_live_time(pcap_data):
    timestamps = [float(packet.time) for packet in pcap_data]  # Convert to float
    start_time = min(timestamps)
    end_time = max(timestamps)
    live_time_duration = end_time - start_time
    live_time_duration_str = str(pd.Timedelta(seconds=live_time_duration))
    return start_time, end_time, live_time_duration, live_time_duration_str


# protocol length statistics
def pcap_len_statistic(PCAPS):
    pcap_len_dict = {'0-300': 0, '301-600': 0, '601-900': 0, '901-1200': 0, '1201-1500': 0, '1500-more': 0}
    if PCAPS is None:
        return pcap_len_dict
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if 0 < pcap_len < 300:
            pcap_len_dict['0-300'] += 1
        elif 301 <= pcap_len < 600:
            pcap_len_dict['301-600'] += 1
        elif 601 <= pcap_len < 900:
            pcap_len_dict['601-900'] += 1
        elif 901 <= pcap_len < 1200:
            pcap_len_dict['901-1200'] += 1
        elif 1201 <= pcap_len <= 1500:
            pcap_len_dict['1201-1500'] += 1
        elif pcap_len > 1500:
            pcap_len_dict['1500-more'] += 1
        else:
            pass
    return pcap_len_dict


# protocol freq statistics
def common_proto_statistic(PCAPS, PD):
    common_proto_dict = collections.OrderedDict()
    common_proto_dict['IP'] = 0
    common_proto_dict['IPv6'] = 0
    common_proto_dict['ARP'] = 0
    common_proto_dict['ICMP'] = 0
    common_proto_dict['DNS'] = 0
    common_proto_dict['TCP'] = 0
    common_proto_dict['UDP'] = 0
    common_proto_dict['Others'] = 0

    if PCAPS is None:
        return common_proto_dict
    for pcap in PCAPS:
        if pcap.haslayer("ARP"):
            common_proto_dict['ARP'] += 1
        elif pcap.haslayer("ICMP") or pcap.haslayer("ICMPv6ND_NS"):
            common_proto_dict['ICMP'] += 1
        elif pcap.haslayer("DNS"):
            common_proto_dict['DNS'] += 1
        elif pcap.haslayer("TCP"):
            # Resolve the named protocol (Modbus, DNP3, S7comm, HTTP, ...) from
            # utils/protocol/PORT and utils/protocol/TCP instead of lumping
            # every TCP packet into a generic "TCP" bucket.
            tcp = pcap.getlayer("TCP")
            proto = PD.PORT_DICT.get(tcp.dport) or PD.PORT_DICT.get(tcp.sport) \
                or PD.TCP_DICT.get(tcp.dport) or PD.TCP_DICT.get(tcp.sport)
            if proto:
                common_proto_dict[proto] = common_proto_dict.get(proto, 0) + 1
            else:
                common_proto_dict['TCP'] += 1
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            proto = PD.PORT_DICT.get(udp.dport) or PD.PORT_DICT.get(udp.sport) \
                or PD.UDP_DICT.get(udp.dport) or PD.UDP_DICT.get(udp.sport)
            if proto:
                common_proto_dict[proto] = common_proto_dict.get(proto, 0) + 1
            else:
                common_proto_dict['UDP'] += 1
        elif pcap.haslayer("IP"):
            # IP packets carrying neither TCP nor UDP (e.g. ESP, GRE, OSPF, ...)
            common_proto_dict['IP'] += 1
        elif pcap.haslayer("IPv6"):
            common_proto_dict['IPv6'] += 1
        elif pcap.haslayer("Ether"):
            # Non-IP Ethernet frames (e.g. Profinet RT/DCP run directly on
            # Ethernet) - resolve by EtherType via utils/protocol/ETHER.
            proto = PD.ETHER_DICT.get(pcap.getlayer("Ether").type)
            if proto:
                common_proto_dict[proto] = common_proto_dict.get(proto, 0) + 1
            else:
                common_proto_dict['Others'] += 1
        else:
            common_proto_dict['Others'] += 1
    return common_proto_dict


# maximum protocol statistics
def most_proto_statistic(PCAPS, PD):
    protos_list = list()
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        protos_list.append(data['Procotol'])
    most_count_dict = collections.OrderedDict(collections.Counter(protos_list).most_common(10))
    return most_count_dict


# http/https Protocol Statistics
def http_statistic(PCAPS):
    http_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            ip = None
            if dport == 80 or dport == 443:
                ip = pcap.getlayer("IP").dst
            elif sport == 80 or sport == 443:
                ip = pcap.getlayer("IP").src
            if ip:
                if ip in http_dict:
                    http_dict[ip] += 1
                else:
                    http_dict[ip] = 1
    return http_dict


def https_stats_main(PCAPS):
    http_dict = http_statistic(PCAPS)
    http_dict = sorted(http_dict.items(),
                       key=lambda d: d[1], reverse=False)
    http_key_list = list()
    http_value_list = list()
    for key, value in http_dict:
        http_key_list.append(key)
        http_value_list.append(value)
    return http_key_list, http_value_list


# DNS Protocol Statistics
def dns_statistic(PCAPS):
    dns_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("DNSQR"):
            qname = pcap.getlayer("DNSQR").qname
            if qname in dns_dict:
                dns_dict[qname] += 1
            else:
                dns_dict[qname] = 1
    return dns_dict


def dns_stats_main(PCAPS):
    dns_dict = dns_statistic(PCAPS)
    dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
    dns_key_list = list()
    dns_value_list = list()
    for key, value in dns_dict:
        dns_key_list.append(key.decode('utf-8'))
        dns_value_list.append(value)
    return dns_key_list, dns_value_list


def get_host_ip(PCAPS):
    ip_list = list()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            ip_list.append(pcap.getlayer("IP").src)
            ip_list.append(pcap.getlayer("IP").dst)
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip


def _classify_ttl(ttl):
    # Passive OS guess from the initial TTL a host tends to use. Ranges are
    # generous to tolerate a few hops of decrement between source and capture point.
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux / macOS / Unix-like (TTL~64)"
    elif ttl <= 128:
        return "Windows (TTL~128)"
    else:
        return "Network device / Solaris (TTL~255)"


def _classify_dhcp_vendor(vendor_class):
    # DHCP option 60 (vendor class id) is more specific than TTL when present.
    if not vendor_class:
        return None
    vc = vendor_class.lower()
    if "msft" in vc or "microsoft" in vc:
        return "Windows (DHCP vendor class)"
    if "android" in vc:
        return "Android (DHCP vendor class)"
    if "apple" in vc or "iphone" in vc or "ipad" in vc or "mac" in vc:
        return "Apple / iOS / macOS (DHCP vendor class)"
    if "udhcp" in vc or "dhcpcd" in vc or "busybox" in vc:
        return "Embedded Linux (DHCP vendor class)"
    return "Other (%s)" % vendor_class


def guess_device_os(PCAPS):
    # Best-effort OS guess per MAC address, combining a TTL heuristic with
    # DHCP vendor class hints (DHCP wins when present, since it's more specific).
    ttl_counter = collections.defaultdict(collections.Counter)
    dhcp_hint = {}

    for pcap in PCAPS:
        if not pcap.haslayer("Ether"):
            continue
        ether = pcap.getlayer("Ether")

        if pcap.haslayer("IP"):
            ttl_counter[ether.src][pcap.getlayer("IP").ttl] += 1

        if pcap.haslayer("DHCP") and pcap.haslayer("BOOTP"):
            chaddr = pcap.getlayer("BOOTP").chaddr[:6]
            mac = ':'.join('%02x' % b for b in chaddr)
            for opt in pcap.getlayer("DHCP").options:
                if isinstance(opt, tuple) and opt[0] == 'vendor_class_id':
                    vendor_class = opt[1]
                    if isinstance(vendor_class, bytes):
                        vendor_class = vendor_class.decode('utf-8', errors='ignore')
                    dhcp_hint[mac] = vendor_class
                    break

    os_guess = {}
    for mac, ttls in ttl_counter.items():
        most_common_ttl = ttls.most_common(1)[0][0]
        os_guess[mac] = _classify_ttl(most_common_ttl) or "Unknown"

    for mac, vendor_class in dhcp_hint.items():
        classified = _classify_dhcp_vendor(vendor_class)
        if classified:
            os_guess[mac] = classified

    return os_guess


def _to_text(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='ignore').strip()
    return str(value).strip()


def _parse_tls_sni(payload):
    # Manually walks a TLS ClientHello (record type 0x16) to find the SNI
    # extension. No decryption involved - this is sent in plaintext by the client.
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        pos = 5
        if payload[pos] != 0x01:  # ClientHello
            return None
        pos += 4  # handshake type(1) + length(3)
        pos += 2 + 32  # client_version(2) + random(32)
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_suites_len = struct.unpack('>H', payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len
        compression_len = payload[pos]
        pos += 1 + compression_len
        if pos + 2 > len(payload):
            return None
        ext_total_len = struct.unpack('>H', payload[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total_len
        while pos + 4 <= end:
            ext_type = struct.unpack('>H', payload[pos:pos + 2])[0]
            ext_len = struct.unpack('>H', payload[pos + 2:pos + 4])[0]
            pos += 4
            if ext_type == 0x0000:  # server_name
                sp = pos + 2  # skip server_name_list length
                if sp + 3 > len(payload):
                    return None
                name_type = payload[sp]
                name_len = struct.unpack('>H', payload[sp + 1:sp + 3])[0]
                sp += 3
                if name_type == 0:
                    return payload[sp:sp + name_len].decode('utf-8', errors='ignore')
                return None
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None


def _parse_bacnet_firmware(payload):
    # Heuristic scan for a BACnet ReadProperty-Ack carrying the firmwareRevision
    # property (context tag 1, value 44) followed by a character-string value.
    marker = b'\x19\x2c'
    idx = payload.find(marker)
    if idx == -1:
        return None
    pos = idx + len(marker)
    if pos < len(payload) and payload[pos] == 0x3e:  # opening tag for property value
        pos += 1
    if pos >= len(payload):
        return None
    tag_byte = payload[pos]
    if (tag_byte >> 4) != 7:  # application tag 7 = Character String
        return None
    lvt = tag_byte & 0x0F
    pos += 1
    if lvt == 5:  # extended length: actual length is in the next byte
        if pos >= len(payload):
            return None
        length = payload[pos]
        pos += 1
    else:
        length = lvt
    if length == 0:
        return None
    pos += 1  # skip the 1-byte string encoding marker
    text = payload[pos:pos + length - 1].decode('utf-8', errors='ignore').strip()
    return text or None


def _extract_s7comm_info(payload):
    # No scapy S7comm layer exists, so scrape printable Siemens order-code /
    # version strings that Read-SZL module-identification responses embed as ASCII.
    text = payload.decode('latin-1', errors='ignore')
    order_codes = re.findall(r'6[A-Z]{2}\d[\w\-. ]{4,18}', text)
    versions = re.findall(r'[Vv]\d{1,2}\.\d{1,2}(?:\.\d{1,2})?', text)
    parts = list(dict.fromkeys(order_codes + versions))
    return ', '.join(p.strip() for p in parts[:3]) if parts else None


def _add_enip_hints(layer, add, ip):
    if not layer.haslayer(ENIPListIdentity):
        return
    for item in layer.getlayer(ENIPListIdentity).items:
        name = _to_text(item.productName)
        rev = "%d.%d" % (item.revisionMajor, item.revisionMinor)
        add(ip, "EtherNet/IP", "%s rev %s (vendor %d)" % (name or "device", rev, item.vendorId))


def get_firmware_hints(PCAPS):
    # Best-effort firmware/version fingerprints per IP, gathered from whichever
    # application-layer protocols happen to expose that information on the wire.
    # Each hint is kept as a (protocol, text) pair so callers can show them in
    # separate columns instead of one combined string.
    hints = collections.defaultdict(set)

    def add(ip, protocol, text):
        if ip and text:
            if len(text) > 150:
                text = text[:150] + '...'
            hints[ip].add((protocol, text))

    for pcap in PCAPS:
        if not pcap.haslayer("IP"):
            continue
        ip_layer = pcap.getlayer("IP")
        src, dst = ip_layer.src, ip_layer.dst

        if pcap.haslayer(HTTPResponse):
            server = pcap.getlayer(HTTPResponse).Server
            if server:
                add(src, "HTTP", "Server: %s" % _to_text(server))
        if pcap.haslayer(HTTPRequest):
            ua = pcap.getlayer(HTTPRequest).User_Agent
            if ua:
                add(src, "HTTP", "User-Agent: %s" % _to_text(ua))

        if pcap.haslayer(SNMP):
            pdu = pcap.getlayer(SNMP).PDU
            for vb in getattr(pdu, "varbindlist", None) or []:
                oid = getattr(vb.oid, "val", None)
                if oid == "1.3.6.1.2.1.1.1.0":  # sysDescr
                    value = _to_text(getattr(vb.value, "val", vb.value))
                    add(src, "SNMP", "sysDescr: %s" % value)

        _add_enip_hints(pcap, add, src)

        if pcap.haslayer(ModbusPDU2B0EReadDeviceIdentificationResponse):
            obj = pcap.getlayer(ModbusPDU2B0EReadDeviceIdentificationResponse).payload
            fields = {}
            while isinstance(obj, ModbusObjectId):
                fields[obj.id] = _to_text(obj.value)
                obj = obj.payload
            parts = []
            if fields.get(4):  # ProductName
                parts.append(fields[4])
            if fields.get(2):  # MajorMinorRevision
                parts.append("rev %s" % fields[2])
            if not parts and fields.get(0):  # VendorName
                parts.append(fields[0])
            if parts:
                add(src, "Modbus", "Device ID: %s" % ' '.join(parts))

        if pcap.haslayer("TCP") and pcap.haslayer("Raw"):
            payload = bytes(pcap.getlayer("Raw").load)
            tcp = pcap.getlayer("TCP")

            if tcp.sport == 21:
                m = re.match(rb'220[- ](.+)', payload.strip())
                if m:
                    add(src, "FTP", "Banner: %s" % _to_text(m.group(0)))

            if tcp.sport == 23 or tcp.dport == 23:
                text = _to_text(payload)
                if text and len(text) < 200 and re.search(r'(version|firmware|v\d+\.\d+)', text, re.IGNORECASE):
                    add(src if tcp.sport == 23 else dst, "Telnet", "Banner: %s" % text)

            if 5900 <= tcp.sport <= 5905 and payload.startswith(b'RFB '):
                add(src, "VNC", "Protocol: %s" % _to_text(payload[:12]))

            if tcp.sport == 102 or tcp.dport == 102:
                info = _extract_s7comm_info(payload)
                if info:
                    add(src if tcp.sport == 102 else dst, "S7comm", "Info: %s" % info)

            if tcp.dport == 443 or tcp.sport == 443:
                sni = _parse_tls_sni(payload)
                if sni:
                    add(src, "HTTPS", "TLS SNI: %s" % sni)

        if pcap.haslayer("UDP") and pcap.haslayer("Raw"):
            payload = bytes(pcap.getlayer("Raw").load)
            udp = pcap.getlayer("UDP")

            if udp.sport == 44818 or udp.dport == 44818:
                try:
                    _add_enip_hints(ENIPTCP(payload), add, src)
                except Exception:
                    pass

            if udp.sport == 47808 or udp.dport == 47808:
                fw = _parse_bacnet_firmware(payload)
                if fw:
                    add(src, "BACnet", "Firmware: %s" % fw)

            if udp.sport == 1900 or udp.dport == 1900:
                text = _to_text(payload) or ''
                m = re.search(r'SERVER:\s*(.+)', text, re.IGNORECASE)
                if m:
                    add(src, "SSDP", "Server: %s" % m.group(1).strip())

    return hints


# Maps a (protocol, regex) pair to an endoflife.date product slug. Limited to
# generic open-source components with public lifecycle data - proprietary OT/ICS
# firmware (Modbus, EtherNet/IP, S7comm, BACnet) has no such public database, so
# those are deliberately left out rather than guessed at.
KNOWN_SOFTWARE_PATTERNS = [
    ("HTTP", re.compile(r'Apache/(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), "apache-http-server"),
    ("HTTP", re.compile(r'nginx/(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), "nginx"),
    ("FTP", re.compile(r'ProFTPD (\d+\.\d+(?:\.\d+)?)', re.IGNORECASE), "proftpd"),
]


def _match_known_software(protocol, hint_text):
    for proto, pattern, slug in KNOWN_SOFTWARE_PATTERNS:
        if proto != protocol:
            continue
        m = pattern.search(hint_text)
        if m:
            return slug, m.group(1)
    return None


@st.cache_data(ttl=86400, show_spinner=False)
def _fetch_eol_cycles(slug):
    try:
        resp = requests.get("https://endoflife.date/api/%s.json" % slug, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def _version_tuple(version_str):
    return tuple(int(p) for p in re.findall(r'\d+', version_str))


def check_eol_status(slug, version):
    cycles = _fetch_eol_cycles(slug)
    if cycles is None:
        return "Unknown (lookup unavailable)"

    version_t = _version_tuple(version)
    best_match, best_len = None, 0
    for entry in cycles:
        cycle_t = _version_tuple(str(entry.get("cycle", "")))
        shortest = min(len(version_t), len(cycle_t))
        if shortest == 0:
            continue
        match_len = 0
        for a, b in zip(version_t, cycle_t):
            if a != b:
                break
            match_len += 1
        if match_len == shortest and match_len > best_len:
            best_match, best_len = entry, match_len

    if not best_match:
        return "Unknown version (not in lifecycle data)"

    eol = best_match.get("eol")
    if eol is False:
        return "Supported"
    if isinstance(eol, str):
        today_str = datetime.now().strftime("%Y-%m-%d")
        return ("EOL since %s" % eol) if eol <= today_str else ("Supported (EOL on %s)" % eol)
    return "Supported" if eol is True else "Unknown"


def _build_device_ip_map(PCAPS):
    # Identify devices by MAC address, pairing each MAC with the IP address(es)
    # it was seen using.
    device_ips = collections.OrderedDict()
    for pcap in PCAPS:
        if not pcap.haslayer("Ether"):
            continue
        ether = pcap.getlayer("Ether")
        for mac in (ether.src, ether.dst):
            device_ips.setdefault(mac, set())
        if pcap.haslayer("IP"):
            ip = pcap.getlayer("IP")
            device_ips[ether.src].add(ip.src)
            device_ips[ether.dst].add(ip.dst)
        elif pcap.haslayer("IPv6"):
            ipv6 = pcap.getlayer("IPv6")
            device_ips[ether.src].add(ipv6.src)
            device_ips[ether.dst].add(ipv6.dst)
    return device_ips


def _get_vendor(mac):
    vendor = scapy_conf.manufdb._get_manuf(mac)
    return "Unknown" if vendor.upper() == mac.upper() else vendor


def get_device_inventory(PCAPS):
    # Resolve the manufacturer via the IEEE OUI database (scapy's conf.manufdb).
    device_ips = _build_device_ip_map(PCAPS)
    os_guess = guess_device_os(PCAPS)

    max_ips_shown = 15
    rows = []
    for mac, ips in device_ips.items():
        ips_sorted = sorted(ips)
        if len(ips_sorted) > max_ips_shown:
            ip_display = '%s, +%d more' % (', '.join(ips_sorted[:max_ips_shown]), len(ips_sorted) - max_ips_shown)
        else:
            ip_display = ', '.join(ips_sorted)

        rows.append({
            'MAC Address': mac,
            'Vendor': _get_vendor(mac),
            'IP Address(es)': ip_display,
            'OS Guess': os_guess.get(mac, "Unknown"),
        })
    return pd.DataFrame(rows)


def get_firmware_inventory(PCAPS):
    # One row per detected firmware/version hint, kept in its own table since
    # devices can carry many hints and cramming them into one cell either
    # truncates them or risks overflowing a PDF table row.
    device_ips = _build_device_ip_map(PCAPS)
    ip_to_mac = _build_ip_to_mac_map(device_ips)
    firmware_hints = get_firmware_hints(PCAPS)

    rows = []
    for ip, hints in firmware_hints.items():
        mac = ip_to_mac.get(ip, "Unknown")
        for protocol, hint in hints:
            match = _match_known_software(protocol, hint)
            if match:
                slug, version = match
                eol_status = check_eol_status(slug, version)
            else:
                eol_status = "N/A - vendor-specific, verify with vendor lifecycle page"
            rows.append({
                'MAC Address': mac,
                'IP Address': ip,
                'Protocol': protocol,
                'Hint': hint,
                'EOL Status': eol_status,
            })
    rows.sort(key=lambda r: (r['MAC Address'], r['IP Address'], r['Protocol'], r['Hint']))
    return pd.DataFrame(rows)


def _build_ip_to_mac_map(device_ips):
    ip_to_mac = {}
    for mac, ips in device_ips.items():
        for ip in ips:
            ip_to_mac.setdefault(ip, mac)
    return ip_to_mac


# Known AV/EDR vendor domains - matched (suffix) against DNS queries, TLS SNI,
# and HTTP Host headers. Presence only proves the host talked to that vendor's
# infrastructure, not that the product is actively installed/running.
AV_EDR_VENDOR_DOMAINS = {
    "wd.microsoft.com": "Microsoft Defender",
    "wdcp.microsoft.com": "Microsoft Defender",
    "smartscreen.microsoft.com": "Microsoft Defender SmartScreen",
    "settings-win.data.microsoft.com": "Microsoft Defender/Telemetry",
    "symantec.com": "Symantec/Broadcom Endpoint Protection",
    "norton.com": "Norton (Gen Digital)",
    "broadcom.com": "Symantec/Broadcom Endpoint Protection",
    "mcafee.com": "McAfee",
    "mcafeeasap.com": "McAfee",
    "kaspersky.com": "Kaspersky",
    "kaspersky-labs.com": "Kaspersky",
    "trendmicro.com": "Trend Micro",
    "eset.com": "ESET",
    "sophos.com": "Sophos",
    "sophosxl.net": "Sophos",
    "sophosupd.com": "Sophos",
    "crowdstrike.com": "CrowdStrike Falcon",
    "cloudsink.net": "CrowdStrike Falcon",
    "sentinelone.net": "SentinelOne",
    "sentinelone.com": "SentinelOne",
    "carbonblack.io": "VMware Carbon Black",
    "cbdefense.com": "VMware Carbon Black",
    "cylance.com": "BlackBerry Cylance",
    "bitdefender.com": "Bitdefender",
    "bitdefender.net": "Bitdefender",
    "avast.com": "Avast",
    "avg.com": "AVG",
    "f-secure.com": "F-Secure/WithSecure",
    "withsecure.com": "WithSecure",
    "paloaltonetworks.com": "Palo Alto Cortex XDR",
    "malwarebytes.com": "Malwarebytes",
    "webroot.com": "Webroot",
    "tanium.com": "Tanium (EDR/mgmt agent)",
    "qualys.com": "Qualys (vuln/EDR agent)",
}

# Secondary signal: substrings to match against an HTTP User-Agent when the
# domain itself didn't match (some agents call out through generic CDNs).
AV_EDR_USER_AGENTS = [
    ("symantec", "Symantec/Broadcom Endpoint Protection"),
    ("mcafee", "McAfee"),
    ("crowdstrike", "CrowdStrike Falcon"),
    ("sentinelone", "SentinelOne"),
    ("kaspersky", "Kaspersky"),
    ("eset", "ESET"),
    ("sophos", "Sophos"),
    ("bitdefender", "Bitdefender"),
    ("windowsdefender", "Microsoft Defender"),
]


def _match_vendor_domain(hostname, vendor_domains):
    if not hostname:
        return None
    h = hostname.lower().rstrip('.')
    for domain, vendor in vendor_domains.items():
        if h == domain or h.endswith('.' + domain):
            return vendor
    return None


def get_av_edr_hints(PCAPS):
    # Best-effort detection of AV/EDR vendor traffic per IP, gathered from DNS
    # queries, TLS SNI hostnames, and HTTP Host/User-Agent headers.
    hits = collections.defaultdict(set)

    def add(ip, vendor, evidence):
        if ip and vendor and evidence:
            if len(evidence) > 150:
                evidence = evidence[:150] + '...'
            hits[ip].add((vendor, evidence))

    for pcap in PCAPS:
        if not pcap.haslayer("IP"):
            continue
        src = pcap.getlayer("IP").src

        if pcap.haslayer("DNSQR"):
            qname = _to_text(pcap.getlayer("DNSQR").qname)
            vendor = _match_vendor_domain(qname, AV_EDR_VENDOR_DOMAINS)
            if vendor:
                add(src, vendor, "DNS query: %s" % (qname.rstrip('.') if qname else qname))

        if pcap.haslayer(HTTPRequest):
            http_req = pcap.getlayer(HTTPRequest)
            host = _to_text(http_req.Host)
            vendor = _match_vendor_domain(host, AV_EDR_VENDOR_DOMAINS)
            if vendor:
                add(src, vendor, "HTTP Host: %s" % host)

            ua = _to_text(http_req.User_Agent)
            if ua:
                ua_lower = ua.lower()
                for substr, ua_vendor in AV_EDR_USER_AGENTS:
                    if substr in ua_lower:
                        add(src, ua_vendor, "HTTP User-Agent: %s" % ua)
                        break

        if pcap.haslayer("TCP") and pcap.haslayer("Raw") and pcap.getlayer("TCP").dport == 443:
            sni = _parse_tls_sni(bytes(pcap.getlayer("Raw").load))
            vendor = _match_vendor_domain(sni, AV_EDR_VENDOR_DOMAINS)
            if vendor:
                add(src, vendor, "TLS SNI: %s" % sni)

    return hits


def get_av_edr_inventory(PCAPS):
    # One row per (host, vendor, evidence) AV/EDR traffic match.
    device_ips = _build_device_ip_map(PCAPS)
    ip_to_mac = _build_ip_to_mac_map(device_ips)
    av_hits = get_av_edr_hints(PCAPS)

    rows = []
    for ip, hits in av_hits.items():
        mac = ip_to_mac.get(ip, "Unknown")
        for vendor, evidence in hits:
            rows.append({
                'MAC Address': mac,
                'IP Address': ip,
                'AV/EDR Vendor': vendor,
                'Evidence': evidence,
            })
    rows.sort(key=lambda r: (r['MAC Address'], r['IP Address'], r['AV/EDR Vendor'], r['Evidence']))
    return pd.DataFrame(rows)


# ── Analysis result cache ─────────────────────────────────────────────────────
# Parameters prefixed with _ are excluded from st.cache_data's hash, so the
# (unhashable) packet list is passed through without being hashed. The `sig`
# tuple (file name + size pairs) acts as the unique cache key instead.

@st.cache_data(show_spinner=False)
def _cached_device_inventory(sig, _pcap):
    return get_device_inventory(_pcap)

@st.cache_data(show_spinner=False)
def _cached_firmware_inventory(sig, _pcap):
    return get_firmware_inventory(_pcap)

@st.cache_data(show_spinner=False)
def _cached_av_edr_inventory(sig, _pcap):
    return get_av_edr_inventory(_pcap)

@st.cache_data(show_spinner=False)
def _cached_security_alerts(sig, _pcap):
    return get_security_alerts(_pcap)

@st.cache_data(show_spinner=False)
def _cached_credential_exposure(sig, _pcap):
    return get_credential_exposure(_pcap)

@st.cache_data(show_spinner=False)
def _cached_modbus_breakdown(sig, _pcap):
    return get_modbus_breakdown(_pcap)

@st.cache_data(show_spinner=False)
def _cached_topology(sig, _pcap):
    return build_topology(_pcap)

@st.cache_data(show_spinner=False)
def _cached_all_pcap(sig, _pcap, _pd):
    return get_all_pcap(_pcap, _pd)

# ─────────────────────────────────────────────────────────────────────────────


def parse_ip_filter(ip_or_network):
    # Accepts a single IP ("192.168.1.10") or a CIDR network ("192.168.1.0/24").
    # Returns an ipaddress network object, or None if the input is blank/invalid.
    text = (ip_or_network or "").strip()
    if not text:
        return None
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        return ipaddress.ip_network(ipaddress.ip_address(text))
    except ValueError:
        return None


def _ip_in_network(ip_str, network):
    try:
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


def classify_int_ext(ip_str):
    try:
        return "Internal" if ipaddress.ip_address(ip_str).is_private else "External"
    except ValueError:
        return "Unknown"


def internal_external_io_stats(PCAPS, network):
    # For traffic where exactly one side matches the selected IP/network, classify
    # the remote (other) side as Internal (RFC1918/private) or External (public).
    stats = collections.defaultdict(lambda: {'packets': 0, 'bytes': 0})
    for pcap in PCAPS:
        if not pcap.haslayer("IP"):
            continue
        ip_layer = pcap.getlayer("IP")
        src, dst = ip_layer.src, ip_layer.dst
        try:
            src_in = ipaddress.ip_address(src) in network
            dst_in = ipaddress.ip_address(dst) in network
        except ValueError:
            continue

        if dst_in and not src_in:
            direction, remote = "Inbound", src
        elif src_in and not dst_in:
            direction, remote = "Outbound", dst
        else:
            continue

        key = (direction, classify_int_ext(remote))
        entry = stats[key]
        entry['packets'] += 1
        entry['bytes'] += len(corrupt_bytes(pcap))

    rows = []
    for direction in ("Inbound", "Outbound"):
        for remote_type in ("Internal", "External"):
            entry = stats.get((direction, remote_type), {'packets': 0, 'bytes': 0})
            rows.append({
                'Direction': direction,
                'Remote Type': remote_type,
                'Packets': entry['packets'],
                'Bytes': entry['bytes'],
            })
    return pd.DataFrame(rows)


def outside_filter_ip_table(PCAPS, network):
    # Lists each remote IP that falls outside the selected filter (i.e. the
    # "other side" of inbound/outbound traffic), tagged Internal/External.
    stats = collections.defaultdict(lambda: {'packets': 0, 'bytes': 0})
    for pcap in PCAPS:
        if not pcap.haslayer("IP"):
            continue
        ip_layer = pcap.getlayer("IP")
        src, dst = ip_layer.src, ip_layer.dst
        try:
            src_in = ipaddress.ip_address(src) in network
            dst_in = ipaddress.ip_address(dst) in network
        except ValueError:
            continue

        if dst_in and not src_in:
            direction, remote = "Inbound", src
        elif src_in and not dst_in:
            direction, remote = "Outbound", dst
        else:
            continue

        entry = stats[(remote, direction)]
        entry['packets'] += 1
        entry['bytes'] += len(corrupt_bytes(pcap))

    columns = ['IP Address', 'Type', 'Direction', 'Packets', 'Bytes']
    rows = []
    for (remote, direction), entry in stats.items():
        rows.append({
            'IP Address': remote,
            'Type': classify_int_ext(remote),
            'Direction': direction,
            'Packets': entry['packets'],
            'Bytes': entry['bytes'],
        })
    df = pd.DataFrame(rows, columns=columns)
    if not df.empty:
        df = df.sort_values(['Type', 'Direction', 'Packets'], ascending=[True, True, False]).reset_index(drop=True)
    return df



def most_flow_statistic(PCAPS, PD):
    most_flow_dict = collections.defaultdict(int)
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        most_flow_dict[data['Procotol']] += len(corrupt_bytes(pcap))
    return most_flow_dict


def getmyip():
    try:
        headers = {'User-Agent': 'Baiduspider+(+http://www.baidu.com/search/spider.htm'}
        ip = requests.get('http://icanhazip.com', headers=headers).text
        return ip.strip()
    except:
        return None


GEOIP_DB_PATH = 'utils/GeoIP/GeoLite2-City.mmdb'


def get_geo(ip):
    if not os.path.exists(GEOIP_DB_PATH):
        return None
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
        response = reader.city(ip)
        city_name = response.country.names['en'] + response.city.names['en']
        longitude = response.location.longitude
        latitude = response.location.latitude
        return [city_name, longitude, latitude]
    except:
        return None


def get_ipmap(PCAPS, host_ip):
    geo_dict = dict()
    ip_value_dict = dict()
    ip_value_list = list()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            src = pcap.getlayer("IP").src
            dst = pcap.getlayer("IP").dst
            pcap_len = len(corrupt_bytes(pcap))
            if src == host_ip:
                oip = dst
            else:
                oip = src
            if oip in ip_value_dict:
                ip_value_dict[oip] += pcap_len
            else:
                ip_value_dict[oip] = pcap_len
    for ip, value in ip_value_dict.items():
        geo_list = get_geo(ip)
        if geo_list:
            geo_dict[geo_list[0]] = [geo_list[1], geo_list[2]]
            Mvalue = str(float('%.2f' % (value / 1024.0))) + ':' + ip
            ip_value_list.append({geo_list[0]: Mvalue})
        else:
            pass
    return [geo_dict, ip_value_list]


# def ipmap(PCAPS):
#     myip = getmyip()
#     host_ip = get_host_ip(PCAPS)
#     ipdata = get_ipmap(PCAPS, host_ip)
#     geo_dict = ipdata[0]
#     ip_value_list = ipdata[1]
#     myip_geo = get_geo(myip)
#     ip_value_list = [(list(d.keys())[0], list(d.values())[0])
#                      for d in ip_value_list]
#     # print('ip_value_list', ip_value_list)
#     # print('geo_dict', geo_dict)
#     # return render_template('./dataanalyzer/ipmap.html', geo_data=geo_dict, ip_value=ip_value_list, mygeo=myip_geo)
#     return geo_dict, ip_value_list, myip_geo


def ipmap(PCAPS):
    # Assuming these functions are defined elsewhere in your code
    myip = getmyip()
    host_ip = get_host_ip(PCAPS)
    ipdata = get_ipmap(PCAPS, host_ip)
    geo_dict = ipdata[0]
    ip_value_list = ipdata[1]
    myip_geo = get_geo(myip)
    ip_value_list = [(list(d.keys())[0], list(d.values())[0]) for d in ip_value_list]

    # Create DataFrames from the dictionaries and lists
    geo_df = pd.DataFrame(list(geo_dict.items()), columns=['Location', 'Coordinates'])
    ip_df = pd.DataFrame(ip_value_list, columns=['Location', 'IP'])

    # Check if myip_geo is not None before creating the DataFrame
    # if myip_geo is not None:
    #     myip_geo_df = pd.DataFrame(myip_geo, columns=['MyLocation', 'MyCoordinates'])
    #
    #     # Merge the DataFrames based on the 'Location' column
    #     merged_df = geo_df.merge(ip_df, on='Location', how='left').merge(myip_geo_df, left_on='Location',
    #                                                                      right_on='MyLocation', how='left')
    # else:
    #     # If myip_geo is None, merge only geo_df and ip_df
    merged_df = geo_df.merge(ip_df, on='Location', how='left')

    if merged_df.empty:
        # No geolocatable peers (e.g. capture only contains private/internal IPs)
        return merged_df

    # Split the 'IP' column into 'Numeric_Value' and 'IP_Address'
    merged_df[['Data_Traffic', 'IP_Address']] = merged_df['IP'].str.split(':', expand=True)

    # Drop the original 'IP' column
    merged_df = merged_df.drop('IP', axis=1)
    # print("merged_df>>", merged_df)

    # Display the merged DataFrame
    with st.expander("Geo Data Associated with PCAPs "):
        st.write(merged_df)

    return merged_df


def parse_uploaded_files(uploaded_files):
    # Parse each valid uploaded file separately (so each can be viewed on its
    # own) and also build one time-sorted capture merging all of them.
    pcap_by_file = collections.OrderedDict()
    for uploaded_file in uploaded_files:
        if not uploaded_file.name.endswith((".pcap", ".cap", "csv")):
            continue
        suffix = os.path.splitext(uploaded_file.name)[1]
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            tmp_path = tmp_file.name
        try:
            pcap_by_file[uploaded_file.name] = list(rdpcap(tmp_path))
        finally:
            os.remove(tmp_path)

    combined = [packet for packets in pcap_by_file.values() for packet in packets]
    combined.sort(key=lambda p: p.time)
    return combined, pcap_by_file


def _reset_data_view_selector_if_stale():
    # st.selectbox raises if the value stored at its key is no longer in its
    # options list, which happens if the currently-viewed file just got removed.
    valid_choices = {"All Files Combined"} | set(st.session_state.pcap_data_by_file.keys())
    if st.session_state.get("data_view_selector") not in valid_choices:
        st.session_state.data_view_selector = "All Files Combined"


def remove_uploaded_file(name, size):
    st.session_state.uploaded_files = [
        f for f in (st.session_state.uploaded_files or []) if (f.name, f.size) != (name, size)
    ]
    st.session_state.pcap_data_by_file.pop(name, None)
    st.session_state.file_metadata.pop(name, None)
    combined = [packet for packets in st.session_state.pcap_data_by_file.values() for packet in packets]
    combined.sort(key=lambda p: p.time)
    st.session_state.pcap_data = combined or None
    remaining = st.session_state.uploaded_files or []
    st.session_state.parsed_file_signature = tuple(sorted((f.name, f.size) for f in remaining))
    st.session_state.uploader_key_version += 1
    _reset_data_view_selector_if_stale()
    _save_session_cache()


def page_file_upload():
    # File upload - stays visible so files can be added one at a time across multiple browses
    new_files = st.file_uploader(
        "Choose CSV/PCAP files", type=["csv", "pcap", "cap"], accept_multiple_files=True,
        key="pcap_uploader_%d" % st.session_state.uploader_key_version,
    )

    # Merge newly selected files into the persistent set instead of replacing
    # it, so a file already uploaded doesn't disappear when another is added
    # in a separate browse (the widget itself only returns its current
    # selection, not everything picked across multiple browses).
    accumulated = {(f.name, f.size): f for f in (st.session_state.uploaded_files or [])}
    for f in (new_files or []):
        accumulated[(f.name, f.size)] = f
    uploaded_files = list(accumulated.values())
    st.session_state.uploaded_files = uploaded_files

    if uploaded_files:
        # Only re-parse when the set of uploaded files actually changed
        file_signature = tuple(sorted(accumulated.keys()))
        if st.session_state.parsed_file_signature != file_signature:
            with st.spinner("Parsing uploaded file(s)..."):
                _, pcap_by_file = parse_uploaded_files(uploaded_files)
                # Merge new files into the existing dict so cached files from a
                # previous session aren't wiped when the user adds a new pcap.
                st.session_state.pcap_data_by_file.update(pcap_by_file)
                combined = [p for packets in st.session_state.pcap_data_by_file.values() for p in packets]
                combined.sort(key=lambda p: p.time)
                st.session_state.pcap_data = combined
            st.session_state.parsed_file_signature = file_signature
            for f in uploaded_files:
                st.session_state.file_metadata[f.name] = {
                    'name': f.name, 'size': f.size, 'type': getattr(f, 'type', ''),
                }
            _save_session_cache()

        st.success(f"{len(uploaded_files)} file(s) loaded.")
        if st.button("Clear All Uploaded Files"):
            st.session_state.uploaded_files = None
            st.session_state.pcap_data = None
            st.session_state.pcap_data_by_file = {}
            st.session_state.parsed_file_signature = None
            st.session_state.file_metadata = {}
            st.session_state.uploader_key_version += 1
            _reset_data_view_selector_if_stale()
            _clear_session_cache()
            st.rerun()
    elif st.session_state.pcap_data_by_file:
        # Data was restored from cache (no active upload). Show a banner so
        # the user knows why analysis is available without any upload widget.
        st.info(
            "Showing data from a previous session. "
            "Upload new files above to replace, or use **Clear All** to start fresh."
        )
        if st.button("Clear All Uploaded Files"):
            st.session_state.uploaded_files = None
            st.session_state.pcap_data = None
            st.session_state.pcap_data_by_file = {}
            st.session_state.parsed_file_signature = None
            st.session_state.file_metadata = {}
            st.session_state.uploader_key_version += 1
            _reset_data_view_selector_if_stale()
            _clear_session_cache()
            st.rerun()


def select_active_pcap_data():
    # Lets the user view a single uploaded file on its own instead of always
    # seeing every file merged together. Shared widget key so the choice
    # stays consistent across tabs (Raw Data & Filtering / Analysis / Geoplots).
    pcap_by_file = st.session_state.pcap_data_by_file
    options = ["All Files Combined"] + list(pcap_by_file.keys())
    choice = st.selectbox("View data from:", options, key="data_view_selector")
    if choice == "All Files Combined":
        return st.session_state.pcap_data
    return pcap_by_file.get(choice, [])


def page_display_info():
    # Display per-file info and a Remove button for each loaded file.
    # After a page refresh, uploaded_files is gone (UploadedFile objects don't
    # survive a session reset), but file_metadata persisted to disk so we can
    # still show the file list and allow individual removal.
    uploaded = st.session_state.get("uploaded_files") or []
    restored_meta = st.session_state.get("file_metadata", {})

    if uploaded:
        # Normal path: active upload session — UploadedFile objects available.
        for uploaded_file in uploaded:
            col1, col2 = st.columns([5, 1])
            with col1:
                st.write({"File Name": uploaded_file.name,
                          "File Type": uploaded_file.type,
                          "File Size": uploaded_file.size})
            with col2:
                if st.button("Remove", key="remove_file_%s_%d" % (uploaded_file.name, uploaded_file.size)):
                    remove_uploaded_file(uploaded_file.name, uploaded_file.size)
                    st.rerun()
    elif restored_meta:
        # Refresh-restore path: no UploadedFile objects, but metadata survived.
        for name, meta in restored_meta.items():
            col1, col2 = st.columns([5, 1])
            with col1:
                st.write({"File Name": meta.get("name", name),
                          "File Type": meta.get("type", ""),
                          "File Size": meta.get("size", "")})
            with col2:
                if st.button("Remove", key="remove_cached_%s" % name):
                    remove_uploaded_file(name, meta.get("size", 0))
                    st.rerun()


def Intro():
    # Introduction
    st.markdown(
        """
        Packet Capture (PCAP) files are a common way to store network traffic data. They contain information about
        the packets exchanged between devices on a network. This data is crucial for network analysis and cybersecurity.
   
 
        ## What is a PCAP file?

        A PCAP file (Packet Capture) is a binary file that stores network traffic data. It records the details of
        each packet, such as source and destination addresses, protocol, and payload. PCAP files are widely used by
        network administrators, security professionals, and researchers to analyze network behavior.

        ## Importance in Cybersecurity

        PCAP files play a vital role in cybersecurity for several reasons:

        - **Network Traffic Analysis:** Analyzing PCAP files helps detect anomalies, identify patterns, and
          understand network behavior.

        - **Incident Response:** In the event of a security incident, PCAP files can be instrumental in
          reconstructing the sequence of events and identifying the root cause.

        - **Forensic Investigations:** PCAP files provide a detailed record of network activity, aiding in
          forensic investigations to determine the source and impact of security incidents.

        """
    )


_MAC_PATTERN = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
_TRAILING_PORT_PATTERN = re.compile(r':\d{1,5}$')


def _strip_port(value):
    # The Source/Destination columns hold "ip:port" for TCP/UDP rows but a
    # bare MAC address for other traffic - only strip a real port suffix.
    if not isinstance(value, str) or _MAC_PATTERN.match(value):
        return value
    return _TRAILING_PORT_PATTERN.sub('', value)


def _split_ip_port(value):
    ip = _strip_port(value)
    if ip == value:
        return ip, None
    return ip, value[len(ip) + 1:]


def _render_ip_counts(label, series, widget_key):
    # Aggregates "ip:port" rows by bare IP so the same IP isn't split across
    # multiple count rows just because it used different ports. Click a row
    # for an IP that used more than one port to see the per-port breakdown
    # right underneath; single-port (or non-IP) rows just show their count.
    ip_totals = collections.Counter()
    ip_ports = collections.defaultdict(collections.Counter)
    for value in series.dropna():
        ip, port = _split_ip_port(value)
        ip_totals[ip] += 1
        if port is not None:
            ip_ports[ip][port] += 1

    st.subheader(label)
    ips = [ip for ip, _ in ip_totals.most_common()]
    port_display = []
    for ip in ips:
        ports = ip_ports.get(ip, {})
        if len(ports) > 1:
            port_display.append("Multiple (%d)" % len(ports))
        elif len(ports) == 1:
            port_display.append(next(iter(ports)))
        else:
            port_display.append("-")

    counts_df = pd.DataFrame({
        'IP': ips,
        'Port': port_display,
        'Count': [ip_totals[ip] for ip in ips],
    })

    # Streamlit's dataframe selection has no per-row disable, so the row
    # checkbox stays clickable for every row - but for single-port IPs the
    # port is already shown inline above, so selecting one is a harmless no-op.
    event = st.dataframe(
        counts_df,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key=widget_key,
    )

    selected_rows = event["selection"]["rows"]
    if selected_rows:
        selected_ip = ips[selected_rows[0]]
        ports = ip_ports.get(selected_ip)
        if ports and len(ports) > 1:
            ports_df = pd.DataFrame({
                'Port': list(ports.keys()),
                'Packets': list(ports.values()),
            }).sort_values('Packets', ascending=False)
            st.caption("Ports used by %s:" % selected_ip)
            st.dataframe(ports_df, hide_index=True, use_container_width=True)


_MODBUS_FC_INFO = {
    1:  ('Read Coils',                      'Read'),
    2:  ('Read Discrete Inputs',            'Read'),
    3:  ('Read Holding Registers',          'Read'),
    4:  ('Read Input Registers',            'Read'),
    5:  ('Write Single Coil',               'Write'),
    6:  ('Write Single Register',           'Write'),
    7:  ('Read Exception Status',           'Diagnostic'),
    8:  ('Diagnostics',                     'Diagnostic'),
    11: ('Get Comm Event Counter',          'Diagnostic'),
    12: ('Get Comm Event Log',              'Diagnostic'),
    15: ('Write Multiple Coils',            'Write'),
    16: ('Write Multiple Registers',        'Write'),
    17: ('Report Server ID',                'Diagnostic'),
    20: ('Read File Record',                'Read'),
    21: ('Write File Record',               'Write'),
    22: ('Mask Write Register',             'Write'),
    23: ('Read/Write Multiple Registers',   'Read+Write'),
    24: ('Read FIFO Queue',                 'Read'),
    43: ('Encapsulated Interface Transport','Diagnostic'),
}
_MODBUS_USER_DEFINED = set(range(65, 73)) | set(range(100, 111))

_MODBUS_EXCEPTION_CODES = {
    1:  'Illegal Function Code',
    2:  'Illegal Data Address',
    3:  'Illegal Data Value',
    4:  'Server Device Failure',
    5:  'Acknowledge',
    6:  'Server Device Busy',
    7:  'Negative Acknowledge',
    8:  'Memory Parity Error',
    10: 'Gateway Path Unavailable',
    11: 'Gateway Target Device Failed to Respond',
}


def _modbus_fc_flag(fc):
    if fc in _MODBUS_FC_INFO:
        return ''
    if fc >= 128:
        return '⚠ Error code as request'
    if fc in _MODBUS_USER_DEFINED:
        return 'User-defined'
    return '⚠ Reserved'


def _modbus_addr_qty(pdu, fc):
    g = lambda f: getattr(pdu, f, None)
    if fc in (1, 2, 3, 4):
        return g('startAddr'), g('quantity')
    if fc == 5:
        return g('outputAddr'), g('outputValue')
    if fc == 6:
        return g('registerAddr'), g('registerValue')
    if fc in (15, 16):
        return g('startAddr'), g('quantityOutput') or g('quantityRegisters')
    if fc == 22:
        return g('refAddr'), None
    if fc == 23:
        return g('writeStartingAddr'), g('writeQuantityRegisters')
    return None, None


def get_modbus_breakdown(PCAPS):
    fc_counts      = collections.Counter()
    unit_id_counts = collections.Counter()
    request_rows   = []
    exception_rows = []

    for pcap in PCAPS:
        if not pcap.haslayer("IP"):
            continue
        src = pcap.getlayer("IP").src
        dst = pcap.getlayer("IP").dst

        # ── Requests (from engineering station / HMI to PLC) ──────────────
        if pcap.haslayer(ModbusADURequest):
            adu = pcap.getlayer(ModbusADURequest)
            unit_id = adu.unitId
            unit_id_counts[unit_id] += 1
            pdu = adu.payload
            fc = getattr(pdu, 'funcCode', None)
            if fc is None:
                continue
            fc_counts[fc] += 1
            addr, qty = _modbus_addr_qty(pdu, fc)
            fc_name, _ = _MODBUS_FC_INFO.get(fc, ('Unknown (FC %d)' % fc, 'Unknown'))
            request_rows.append({
                'Source IP':   src,
                'Dest IP':     dst,
                'Unit ID':     unit_id,
                'FC':          fc,
                'Function':    fc_name,
                'Start Addr':  addr if addr is not None else '-',
                'Qty / Value': qty  if qty  is not None else '-',
            })

        # ── Exception responses (PLC rejecting a command) ──────────────────
        if pcap.haslayer(ModbusADUResponse):
            adu = pcap.getlayer(ModbusADUResponse)
            pdu = adu.payload
            fc = getattr(pdu, 'funcCode', None)
            if fc is None or fc < 0x80:
                continue  # not an error response
            orig_fc = fc & 0x7F
            except_code = getattr(pdu, 'exceptCode', None)
            orig_name, _ = _MODBUS_FC_INFO.get(orig_fc, ('Unknown (FC %d)' % orig_fc, 'Unknown'))
            except_meaning = _MODBUS_EXCEPTION_CODES.get(except_code, 'Unknown (code %s)' % except_code)
            security_note = ''
            if except_code == 1:
                security_note = 'Device does not support this function — possible probe'
            elif except_code in (2, 3):
                security_note = 'Invalid address/value — possible reconnaissance or misconfigured write'
            elif except_code == 4:
                security_note = 'Device failure — check device health'
            exception_rows.append({
                'PLC IP':          src,
                'Requester IP':    dst,
                'Unit ID':         adu.unitId,
                'Rejected FC':     orig_fc,
                'Rejected Function': orig_name,
                'Exception Code':  except_code,
                'Meaning':         except_meaning,
                'Security Note':   security_note,
            })

    # Function code summary
    fc_rows = []
    for fc, count in sorted(fc_counts.items()):
        name, category = _MODBUS_FC_INFO.get(fc, ('Unknown (FC %d)' % fc, 'Unknown'))
        fc_rows.append({
            'FC': fc, 'Name': name, 'Category': category,
            'Count': count, 'Flag': _modbus_fc_flag(fc),
        })

    fc_df        = pd.DataFrame(fc_rows) if fc_rows else pd.DataFrame(columns=['FC','Name','Category','Count','Flag'])
    detail_df    = pd.DataFrame(request_rows) if request_rows else pd.DataFrame(columns=['Source IP','Dest IP','Unit ID','FC','Function','Start Addr','Qty / Value'])
    unit_df      = pd.DataFrame({'Unit ID': list(unit_id_counts.keys()),
                                 'Requests': list(unit_id_counts.values())}).sort_values('Requests', ascending=False) \
                   if unit_id_counts else pd.DataFrame(columns=['Unit ID','Requests'])
    exception_df = pd.DataFrame(exception_rows) if exception_rows else pd.DataFrame(columns=['PLC IP','Requester IP','Unit ID','Rejected FC','Rejected Function','Exception Code','Meaning','Security Note'])
    return fc_df, detail_df, unit_df, exception_df


def show_modbus_breakdown(PCAPS):
    _sig = st.session_state.parsed_file_signature
    fc_df, detail_df, unit_df, exception_df = _cached_modbus_breakdown(_sig, PCAPS)

    if fc_df.empty and exception_df.empty:
        return  # No Modbus traffic — section stays hidden

    st.divider()
    st.subheader("Modbus Traffic Breakdown")

    total      = int(fc_df['Count'].sum()) if not fc_df.empty else 0
    reads      = int(fc_df[fc_df['Category'] == 'Read']['Count'].sum()) if not fc_df.empty else 0
    writes     = int(fc_df[fc_df['Category'].isin(['Write','Read+Write'])]['Count'].sum()) if not fc_df.empty else 0
    diag       = int(fc_df[fc_df['Category'] == 'Diagnostic']['Count'].sum()) if not fc_df.empty else 0
    unusual    = int((fc_df['Flag'] != '').sum()) if not fc_df.empty else 0
    exceptions = len(exception_df)

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Requests", total)
    c2.metric("Read", reads)
    c3.metric("Write", writes)
    c4.metric("Diagnostic", diag)
    c5.metric("Unusual FCs", unusual,  delta=unusual    if unusual    else None, delta_color="inverse" if unusual    else "off")
    c6.metric("Exceptions",  exceptions, delta=exceptions if exceptions else None, delta_color="inverse" if exceptions else "off")

    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("**Function Code Summary**")
        if unusual:
            st.warning("⚠ %d unusual function code(s) detected — check the Flag column." % unusual)
        st.dataframe(fc_df, use_container_width=True, hide_index=True)

        if not fc_df.empty:
            fig = px.bar(fc_df, x='Name', y='Count', color='Category',
                         title='Function Code Distribution',
                         color_discrete_map={'Read': '#4a90d9', 'Write': '#e05c5c',
                                             'Diagnostic': '#a0a0a0', 'Read+Write': '#c47bd9',
                                             'Unknown': '#ff9900'})
            fig.update_layout(title_x=0.5, xaxis_tickangle=-30)
            st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.markdown("**Unit IDs Seen**")
        st.dataframe(unit_df, use_container_width=True, hide_index=True)

    st.markdown("**Request Details**")
    st.dataframe(detail_df, use_container_width=True, hide_index=True)
    st.download_button("Download as PDF",
        data=generate_table_pdf("Modbus Request Details", detail_df, orientation="L"),
        file_name="modbus_breakdown.pdf", mime="application/pdf",
        key="dl_modbus_breakdown")

    # ── Exception Responses ────────────────────────────────────────────────────
    st.divider()
    st.markdown("**Exception Responses** (commands rejected by the PLC)")
    if exception_df.empty:
        st.success("No exception responses detected — all commands were accepted.")
    else:
        if any(exception_df['Security Note'] != ''):
            st.warning("⚠ %d exception(s) with security relevance detected — check the Security Note column." % int((exception_df['Security Note'] != '').sum()))
        st.dataframe(exception_df, use_container_width=True, hide_index=True)
        st.download_button("Download exceptions as PDF",
            data=generate_table_pdf("Modbus Exception Responses", exception_df, orientation="L"),
            file_name="modbus_exceptions.pdf", mime="application/pdf",
            key="dl_modbus_exceptions")


def RawDataView():
    pcap_data = select_active_pcap_data()
    if pcap_data:
        _sig = st.session_state.parsed_file_signature
        all_data = _cached_all_pcap(_sig, pcap_data, PD)
        dataframe_data = process_json_data(all_data)
        start_time, end_time, live_time_duration, live_time_duration_str = calculate_live_time(pcap_data)

        # Add live time information to the data frame
        # dataframe_data['Start Time'] = start_time
        # dataframe_data['End Time'] = end_time
        dataframe_data['Live Time Duration'] = live_time_duration_str
        all_columns = list(dataframe_data.columns)
        st.sidebar.header("Please Filter Here:")
        # st.sidebar.divider()
        # Filter reset button
        if st.sidebar.button("Reset Filters"):
            st.rerun()
        # Multiselect for filtering by protocol
        selected_protocols = st.sidebar.multiselect(
            "Select Protocol:",
            options=dataframe_data["Procotol"].unique(), default=None
        )
        # st.sidebar.divider()

        # Sidebar slider for filtering by length
        filter_value_len = st.sidebar.slider(
            "Filter by Numeric Column",
            min_value=min(dataframe_data["len"]),
            max_value=max(dataframe_data["len"]),
            value=(min(dataframe_data["len"]), max(dataframe_data["len"]))
        )
        # st.sidebar.divider()

        # Sidebar dropdown for filtering by Source - lists only the IPs actually present
        source_options = ["All"] + sorted({_strip_port(v) for v in dataframe_data["Source"].dropna()})
        filter_source = st.sidebar.selectbox("Filter by Source:", source_options)
        # st.sidebar.divider()

        # Sidebar dropdown for filtering by Destination - lists only the IPs actually present
        destination_options = ["All"] + sorted({_strip_port(v) for v in dataframe_data["Destination"].dropna()})
        filter_destination = st.sidebar.selectbox("Filter by Destination:", destination_options)
        # st.sidebar.divider()

        # Apply filters based on user selection
        if (
                selected_protocols is None or not selected_protocols) and not filter_value_len and filter_source == "All" and filter_destination == "All":
            st.write("All PCAPs:")
            Data_to_display_df = dataframe_data.copy()
            st.dataframe(Data_to_display_df, use_container_width=True)

        else:
            # Apply filters based on user input

            # Filter by protocol
            if selected_protocols is not None and selected_protocols:
                Data_to_display_df = dataframe_data[dataframe_data["Procotol"].isin(selected_protocols)]
            else:
                Data_to_display_df = dataframe_data

            # Filter by length
            Data_to_display_df = Data_to_display_df[
                (Data_to_display_df["len"] >= filter_value_len[0]) & (
                        Data_to_display_df["len"] <= filter_value_len[1])
                ]

            # Filter by Source
            if filter_source != "All":
                Data_to_display_df = Data_to_display_df[
                    Data_to_display_df["Source"].apply(_strip_port) == filter_source]

            # Filter by Destination
            if filter_destination != "All":
                Data_to_display_df = Data_to_display_df[
                    Data_to_display_df["Destination"].apply(_strip_port) == filter_destination]

            # Display the filtered dataframe
            st.write("Filtered PCAPs:")

            column_check = st.checkbox("Filter the data by column")
            if column_check:
                # Multiselect for filtering by columns
                selected_columns = st.multiselect(
                    "Select Columns to Display:",
                    options=all_columns, default=all_columns
                )
                Data_to_display_df = Data_to_display_df[selected_columns]
            # selected_columns = [col for col in Data_to_display_df.columns if st.checkbox(col, value=True )]
            st.dataframe(Data_to_display_df, use_container_width=True)

            st.subheader("Statistics of Selected Data")
            # Time Analysis
            Data_to_display_df['time'] = pd.to_datetime(Data_to_display_df['time'])
            st.subheader("Time Range:")
            st.write("Earliest timestamp:", Data_to_display_df['time'].min())
            st.write("Latest timestamp:", Data_to_display_df['time'].max())
            st.write("Duration:", Data_to_display_df['time'].max() - Data_to_display_df['time'].min())
            ####################################
            col1, col2 = st.columns(2)

            # Column 1: Packet Length Statistics
            with col1:
                st.subheader("Packet Length Statistics:")
                st.table(Data_to_display_df['len'].describe())

                # Source Counts
                _render_ip_counts("Source Counts:", Data_to_display_df['Source'], "source_ports_dropdown")

            # Column 2: Protocol Distribution and Destination Counts
            with col2:
                # Protocol Distribution
                protocol_counts = Data_to_display_df['Procotol'].value_counts(normalize=True)
                st.subheader("Protocol Distribution:")
                st.table(protocol_counts)

                # Destination Counts
                _render_ip_counts("Destination Counts:", Data_to_display_df['Destination'], "destination_ports_dropdown")

        show_modbus_breakdown(pcap_data)
    else:
        st.warning("Please upload a valid PCAP file.")



def DataPacketLengthStatistics(data):
    # st.write("Data Packet Length Statistics")
    data1 = {'pcap_len': list(data.keys()), 'count': list(data.values())}
    df1 = pd.DataFrame(data1)

    options = {
        "title": {"text": "Data Packet Length Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Packets",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df1['pcap_len'], df1['count'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')


def CommonProtocolStatistics(data):
    st.write("Common Protocol Statistics")
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    # plost.bar_chart(data=df2, bar='protocol_type', value='number_of_packets')

    options = {
        "xAxis": {
            "type": "category",
            "data": df2.protocol_type.tolist(),
        },
        "yAxis": {"type": "value"},
        "series": [{"data": df2.number_of_packets.tolist(), "type": "bar"}],
    }
    st_echarts(options=options, height="500px")

def CommonProtocolStatistics_ploty(data):
    # st.write('Common Protocol Statistics')
    data = {k: v for k, v in data.items() if v > 0}
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    fig = px.bar(df2, x='protocol_type', y='number_of_packets',color="protocol_type",title="Common Protocol Statistics")
    fig.update_layout(title_x=0.5)

    st.plotly_chart(fig)




def MostFrequentProtocolStatistics(data):
    # st.write("Data Packet Length Statistics")
    data3 = {'protocol_type': list(data.keys()), 'freq': list(data.values())}
    df3 = pd.DataFrame(data3)

    options = {
        "title": {"text": "Most Frequent Protocol Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Packets",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df3['protocol_type'], df3['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }


    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')


def HTTP_HTTPSAccessStatistics(key,value):
    # st.write("HTTP/HTTPS Access Statistics")
    data4 = {'HTTP/HTTPS key': list(key),
             'HTTP/HTTPS value': list(value)}
    df4 = pd.DataFrame(data4)
    fig = px.bar(df4, x='HTTP/HTTPS key', y='HTTP/HTTPS value',color="HTTP/HTTPS key",title="HTTP/HTTPS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)



def DNSAccessStatistics(key, value):
    # st.write("DNS Access Statistics")
    data5 = {'dns_key': list(key),
             'dns_value': list(value)}
    df5 = pd.DataFrame(data5)
    fig = px.bar(df5, x='dns_key', y='dns_value', color="dns_key",title="DNS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)


def InternalExternalIOChart(df):
    fig = px.bar(df, x='Direction', y='Packets', color='Remote Type', barmode='group',
                 title="Inbound/Outbound Packets by Internal vs External")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)


def common_protocol_df(data):
    data = {k: v for k, v in data.items() if v > 0}
    return pd.DataFrame({'Protocol': list(data.keys()), 'Packet Count': list(data.values())})


_PDF_EMOJI_MAP = {
    # Severity emoji — the word "High/Medium/Low" already follows, so just drop the emoji
    '🔴': '', '🟡': '', '🔵': '',
    '⬇': 'IN', '⬆': 'OUT',
    '🚨': '', '🔑': '', '🛡': '', '⚠': '',
}


def _pdf_sanitize(text):
    # Replace emoji with readable plain-text equivalents, then drop anything
    # outside Latin-1 so Helvetica doesn't raise FPDFUnicodeEncodingException.
    # Coerce non-strings (e.g. float NaN from None cells) to str first.
    if not isinstance(text, str):
        text = str(text)
    for emoji, replacement in _PDF_EMOJI_MAP.items():
        text = text.replace(emoji, replacement)
    return text.strip().encode('latin-1', errors='ignore').decode('latin-1')


_PDF_HEADING_STYLE = FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=(45, 75, 140))
_PDF_ROW_FILL     = (235, 240, 252)   # soft blue-grey for alternating rows


def _render_pdf_table(pdf, table_data, col_widths=None):
    # Reset fill/text colour so alternating row fills aren't tainted by
    # whatever section-header colour was set last.
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", size=8)
    with pdf.table(
        table_data,
        col_widths=col_widths,
        first_row_as_headings=True,
        headings_style=_PDF_HEADING_STYLE,
        cell_fill_color=_PDF_ROW_FILL,
        cell_fill_mode="ROWS",
        line_height=5,
    ):
        pass


def generate_table_pdf(title, df, orientation="P", col_widths=None):
    pdf = FPDF(orientation=orientation)
    pdf.set_margins(10, 10, 10)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, _pdf_sanitize(title), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    raw_rows = [list(df.columns)] + df.astype(str).values.tolist()
    table_data = [[_pdf_sanitize(cell) for cell in row] for row in raw_rows]
    _render_pdf_table(pdf, table_data, col_widths=col_widths)
    return bytes(pdf.output())


def _pdf_section(pdf, title):
    pdf.set_fill_color(28, 37, 65)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 9, _pdf_sanitize(title), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def _pdf_subsection(pdf, title):
    pdf.set_fill_color(70, 90, 130)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 7, _pdf_sanitize(title), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)


def _pdf_table(pdf, df, col_widths=None):
    if df is None or df.empty:
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 6, "No data found.", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)
        return
    raw_rows = [list(df.columns)] + df.astype(str).values.tolist()
    table_data = [[_pdf_sanitize(c) for c in row] for row in raw_rows]
    try:
        _render_pdf_table(pdf, table_data, col_widths=col_widths)
    except Exception:
        pdf.set_font("Helvetica", "I", 8)
        pdf.cell(0, 6, "Table could not be rendered (content too large).", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)


def _pdf_metric_row(pdf, metrics):
    box_w = int(pdf.epw / len(metrics))
    for label, value in metrics:
        pdf.set_fill_color(240, 240, 248)
        pdf.set_draw_color(150, 150, 200)
        pdf.set_font("Helvetica", "B", 14)
        x, y = pdf.get_x(), pdf.get_y()
        pdf.rect(x, y, box_w - 2, 16, style="FD")
        pdf.set_xy(x, y + 1)
        pdf.cell(box_w - 2, 7, _pdf_sanitize(str(value)), align="C")
        pdf.set_xy(x, y + 8)
        pdf.set_font("Helvetica", size=7)
        pdf.cell(box_w - 2, 6, _pdf_sanitize(label), align="C")
        pdf.set_xy(x + box_w, y)
    pdf.ln(20)


def generate_full_report(data_of_pcap, file_names):
    from datetime import datetime as _dt

    # Gather all data upfront — use cached wrappers so re-generating the report
    # within the same session hits the cache instead of recomputing everything.
    _sig = st.session_state.parsed_file_signature
    device_df    = _cached_device_inventory(_sig, data_of_pcap)
    firmware_df  = _cached_firmware_inventory(_sig, data_of_pcap)
    av_edr_df    = _cached_av_edr_inventory(_sig, data_of_pcap)
    alerts_df    = _cached_security_alerts(_sig, data_of_pcap)
    creds_df     = _cached_credential_exposure(_sig, data_of_pcap)
    cve_df       = get_cve_findings(data_of_pcap)
    fc_df, detail_df, unit_df, exception_df = _cached_modbus_breakdown(_sig, data_of_pcap)

    start_t, end_t, duration, duration_str = calculate_live_time(data_of_pcap)

    high_alerts = int((alerts_df['Severity'].str.startswith('🔴')).sum()) if not alerts_df.empty else 0
    med_alerts  = int((alerts_df['Severity'].str.startswith('🟡')).sum()) if not alerts_df.empty else 0
    low_alerts  = int((alerts_df['Severity'].str.startswith('🔵')).sum()) if not alerts_df.empty else 0

    pdf = FPDF(orientation="L")
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.set_margins(10, 10, 10)

    # ── Cover page ────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(28, 37, 65)
    pdf.rect(0, 0, 297, 210, style="F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 28)
    pdf.ln(40)
    pdf.cell(0, 14, "OT PCAP Analysis Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    pdf.ln(4)
    pdf.cell(0, 8, "Generated: %s" % _dt.now().strftime("%Y-%m-%d %H:%M"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 7, "Files analysed: %s" % ", ".join(file_names), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "Total packets: %d" % len(data_of_pcap), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "Capture duration: %s" % duration_str, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    # ── Executive Summary ─────────────────────────────────────────────────────
    pdf.add_page()
    _pdf_section(pdf, "Executive Summary")
    _pdf_metric_row(pdf, [
        ("Total Devices",    len(device_df)),
        ("High Alerts",      high_alerts),
        ("Medium Alerts",    med_alerts),
        ("Low Alerts",       low_alerts),
        ("CVEs Found",       len(cve_df)),
        ("Credentials Exposed", len(creds_df)),
        ("Modbus Requests",  int(fc_df['Count'].sum()) if not fc_df.empty else 0),
        ("Modbus Exceptions",len(exception_df)),
    ])

    # ── Device Inventory ──────────────────────────────────────────────────────
    pdf.add_page()
    _pdf_section(pdf, "Device Inventory")
    _pdf_table(pdf, device_df)

    # ── Firmware / Version Hints ──────────────────────────────────────────────
    pdf.add_page()
    _pdf_section(pdf, "Firmware / Version Hints")
    _pdf_table(pdf, firmware_df)

    # ── AV / EDR Vendor Traffic ───────────────────────────────────────────────
    pdf.add_page()
    _pdf_section(pdf, "AV / EDR Vendor Traffic")
    _pdf_table(pdf, av_edr_df)

    # ── Security Alerts ───────────────────────────────────────────────────────
    pdf.add_page()
    _pdf_section(pdf, "Security Alerts")
    _pdf_table(pdf, alerts_df)

    # ── Credential Exposure ───────────────────────────────────────────────────
    _pdf_section(pdf, "Credential Exposure")
    _pdf_table(pdf, creds_df)

    # ── CVE Findings ──────────────────────────────────────────────────────────
    pdf.add_page()
    _pdf_section(pdf, "CVE Findings")
    _pdf_table(pdf, cve_df)

    # ── Modbus Breakdown ──────────────────────────────────────────────────────
    pdf.add_page()
    _pdf_section(pdf, "Modbus Traffic Breakdown")
    _pdf_subsection(pdf, "Function Code Summary")
    _pdf_table(pdf, fc_df)
    _pdf_subsection(pdf, "Unit IDs Seen")
    _pdf_table(pdf, unit_df)
    _pdf_subsection(pdf, "Request Details")
    _pdf_table(pdf, detail_df)
    _pdf_subsection(pdf, "Exception Responses")
    _pdf_table(pdf, exception_df)

    return bytes(pdf.output())


def page_report():
    st.subheader("Full Analysis Report")
    if not st.session_state.pcap_data_by_file:
        st.warning("No data loaded. Upload a PCAP file first.")
        return

    data_of_pcap = select_active_pcap_data()
    if not data_of_pcap:
        st.warning("No valid data for the selected capture.")
        return

    st.markdown(
        "Generates a single PDF bundling all findings: device inventory, firmware hints, "
        "AV/EDR traffic, security alerts, credential exposure, CVE lookup, and Modbus breakdown."
    )

    if st.button("Generate Report", type="primary"):
        file_names = list(st.session_state.pcap_data_by_file.keys())
        with st.spinner("Building report — this may take a moment (CVE lookup is cached)…"):
            try:
                report_bytes = generate_full_report(data_of_pcap, file_names)
                st.success("Report ready.")
                st.download_button(
                    "Download PDF Report",
                    data=report_bytes,
                    file_name="ot_pcap_report_%s.pdf" % datetime.now().strftime("%Y%m%d_%H%M"),
                    mime="application/pdf",
                    key="dl_full_report",
                )
            except Exception as e:
                st.error("Report generation failed: %s" % e)


def DrawFoliumMap(data):
    m = folium.Map(location=[data.iloc[0]['Coordinates'][1], data.iloc[0]['Coordinates'][0]],
                   zoom_start=5)

    # Create MarkerCluster layer
    marker_cluster = MarkerCluster().add_to(m)

    # Add markers for each location in the DataFrame
    for index, row in data.iterrows():
        popup_text = f"IP Address: {row['IP_Address']}<br>Data Traffic: {row['Data_Traffic']}"

        folium.Marker(
            location=row['Coordinates'][::-1],
            popup=folium.Popup(popup_text, max_width=300),
            icon=folium.Icon(color='blue'),  # Customize marker color
        ).add_to(marker_cluster)

    # Display the map in Streamlit
    folium_static(m,width=1820 , height=600)

# ── Security analysis ─────────────────────────────────────────────────────────

_MODBUS_WRITE_LAYERS = (
    "ModbusPDU05WriteSingleCoilRequest",
    "ModbusPDU06WriteSingleRegisterRequest",
    "ModbusPDU0FWriteMultipleCoilsRequest",
    "ModbusPDU10WriteMultipleRegistersRequest",
    "ModbusPDU15WriteFileRecordRequest",
    "ModbusPDU16MaskWriteRegisterRequest",
    "ModbusPDU17ReadWriteMultipleRegistersRequest",
)


# ── Active Directory / Windows protocol detection ────────────────────────────
from scapy.layers.ntlm import NTLM_Header, NTLM_AUTHENTICATE, NTLM_AUTHENTICATE_V2
from scapy.layers.smb  import SMB_Header
from scapy.layers.smb2 import SMB2_Header, SMB2_Negotiate_Protocol_Response
from scapy.layers.ldap import LDAP, LDAP_BindRequest, LDAP_SearchRequest
from scapy.layers.kerberos import KerberosTCPHeader

_AD_PORTS = {
    88:   'Kerberos',
    389:  'LDAP',
    445:  'SMB',
    636:  'LDAPS',
    3268: 'LDAP Global Catalog',
    3269: 'LDAPS Global Catalog',
    135:  'MSRPC',
    137:  'NetBIOS-NS',
    138:  'NetBIOS-DGM',
    139:  'NetBIOS-SSN',
    5985: 'WinRM',
    5986: 'WinRM-HTTPS',
    593:  'RPC over HTTP',
}

_SMB2_DIALECTS = {
    0x0202: 'SMB 2.0.2', 0x0210: 'SMB 2.1',
    0x0300: 'SMB 3.0',   0x0302: 'SMB 3.0.2',
    0x0311: 'SMB 3.1.1', 0x02FF: 'SMB 2.x (wildcard)',
}

_NTLM_MSG_TYPES = {1: 'Negotiate', 2: 'Challenge', 3: 'Authenticate'}

_LDAP_OPS = {
    0: 'Bind',     1: 'Bind Response',  2: 'Unbind',
    3: 'Search',   4: 'Search Entry',   5: 'Search Done',
    6: 'Modify',   8: 'Add',            10: 'Delete',
    12: 'Modify DN', 14: 'Compare',     16: 'Abandon',
    23: 'Extended', 24: 'Extended Response',
}


def get_ad_detection(PCAPS):
    # Per-IP protocol presence (server side — IPs being contacted on AD ports)
    server_protocols = collections.defaultdict(set)   # ip -> set of protocol names
    client_protocols = collections.defaultdict(set)   # ip -> set of protocol names
    smb_versions     = []   # {src, dst, version, negotiated_dialect}
    smb1_pairs       = set()
    ntlm_rows        = []
    ldap_rows        = []
    ldap_search_count = collections.Counter()  # source IP -> count

    for pcap in PCAPS:
        if not pcap.haslayer("IP"):
            continue
        ip = pcap.getlayer("IP")
        src, dst = ip.src, ip.dst

        # Port-based AD protocol presence
        if pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            for port, proto in _AD_PORTS.items():
                if tcp.dport == port:
                    server_protocols[dst].add(proto)
                    client_protocols[src].add(proto)
                if tcp.sport == port:
                    server_protocols[src].add(proto)
                    client_protocols[dst].add(proto)
        if pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            for port, proto in _AD_PORTS.items():
                if udp.dport == port:
                    server_protocols[dst].add(proto)
                    client_protocols[src].add(proto)

        # SMBv1 detection
        if pcap.haslayer(SMB_Header):
            smb1_pairs.add((src, dst))

        # SMBv2 dialect negotiation
        if pcap.haslayer(SMB2_Negotiate_Protocol_Response):
            neg = pcap.getlayer(SMB2_Negotiate_Protocol_Response)
            dialect_val = int(neg.DialectRevision)
            dialect_str = _SMB2_DIALECTS.get(dialect_val, 'Unknown (0x%04x)' % dialect_val)
            smb_versions.append({
                'Server IP': src, 'Client IP': dst,
                'Dialect': dialect_str, 'Raw Value': '0x%04x' % dialect_val,
            })

        # NTLM
        if pcap.haslayer(NTLM_Header):
            hdr = pcap.getlayer(NTLM_Header)
            msg_type = int(hdr.MessageType)
            msg_name = _NTLM_MSG_TYPES.get(msg_type, 'Unknown')
            ntlm_version = '-'
            if msg_type == 3:
                if pcap.haslayer(NTLM_AUTHENTICATE_V2):
                    ntlm_version = 'NTLMv2'
                elif pcap.haslayer(NTLM_AUTHENTICATE):
                    auth = pcap.getlayer(NTLM_AUTHENTICATE)
                    # NTLMv1 NT response is exactly 24 bytes
                    ntlm_version = 'NTLMv1' if auth.NtChallengeResponseLen == 24 else 'NTLMv2'
            ntlm_rows.append({
                'Source IP': src, 'Dest IP': dst,
                'Message': msg_name, 'NTLM Version': ntlm_version,
            })

        # LDAP operations
        if pcap.haslayer(LDAP):
            ldap_pkt = pcap.getlayer(LDAP)
            op_id = int(ldap_pkt.protocolOp) if ldap_pkt.protocolOp is not None else -1
            op_name = _LDAP_OPS.get(op_id, 'Op %d' % op_id)
            detail = ''
            if pcap.haslayer(LDAP_BindRequest):
                bind = pcap.getlayer(LDAP_BindRequest)
                auth_type = str(type(bind.authentication).__name__)
                if 'simple' in auth_type.lower() or op_id == 0:
                    detail = 'Simple bind (plaintext credentials!)'
            if pcap.haslayer(LDAP_SearchRequest):
                ldap_search_count[src] += 1
            ldap_rows.append({
                'Source IP': src, 'Dest IP': dst,
                'Operation': op_name, 'Detail': detail,
            })

    # Build DataFrames
    proto_rows = []
    all_ips = set(server_protocols) | set(client_protocols)
    dc_candidates = {
        ip for ip in server_protocols
        if len({'Kerberos', 'LDAP', 'SMB'} & server_protocols[ip]) >= 2
    }
    for ip in sorted(all_ips):
        protos = (server_protocols.get(ip, set()) | client_protocols.get(ip, set()))
        proto_rows.append({
            'IP': ip,
            'AD Protocols Seen': ', '.join(sorted(protos)),
            'Likely DC': 'Yes' if ip in dc_candidates else '',
        })

    # Security findings specific to AD
    ad_alerts = []
    if smb1_pairs:
        ips = ', '.join('%s→%s' % p for p in sorted(smb1_pairs)[:5])
        ad_alerts.append({'Severity': '🔴 Critical', 'Finding': 'SMBv1 Detected',
                          'Detail': 'SMBv1 traffic found — vulnerable to EternalBlue (MS17-010). Pairs: %s' % ips})
    ntlm1 = [r for r in ntlm_rows if r['NTLM Version'] == 'NTLMv1']
    if ntlm1:
        ips = ', '.join(sorted({r['Source IP'] for r in ntlm1})[:5])
        ad_alerts.append({'Severity': '🔴 High', 'Finding': 'NTLMv1 Detected',
                          'Detail': 'NTLMv1 hashes are crackable offline in minutes. Sources: %s' % ips})
    plain_binds = [r for r in ldap_rows if 'plaintext' in r['Detail']]
    if plain_binds:
        ips = ', '.join(sorted({r['Source IP'] for r in plain_binds})[:5])
        ad_alerts.append({'Severity': '🔴 High', 'Finding': 'LDAP Simple Bind (Plaintext)',
                          'Detail': 'Credentials sent in cleartext over LDAP port 389. Sources: %s' % ips})
    enum_ips = {ip for ip, count in ldap_search_count.items() if count > 50}
    if enum_ips:
        ad_alerts.append({'Severity': '🟡 Medium', 'Finding': 'Possible LDAP Enumeration',
                          'Detail': 'High LDAP search volume (>50 queries) — possible BloodHound/AD enumeration. IPs: %s' % ', '.join(sorted(enum_ips))})
    if dc_candidates:
        ad_alerts.append({'Severity': '🔵 Info', 'Finding': 'Active Directory Found in Capture',
                          'Detail': 'Domain Controller(s) identified: %s — AD presence in OT network is an IT/OT convergence finding.' % ', '.join(sorted(dc_candidates))})
    winrm_ips = {ip for ip, protos in server_protocols.items() if 'WinRM' in protos}
    if winrm_ips:
        ad_alerts.append({'Severity': '🟡 Medium', 'Finding': 'WinRM Detected',
                          'Detail': 'Windows Remote Management (port 5985/5986) found — remote code execution protocol. IPs: %s' % ', '.join(sorted(winrm_ips))})

    return {
        'proto_df':   pd.DataFrame(proto_rows) if proto_rows else pd.DataFrame(columns=['IP', 'AD Protocols Seen', 'Likely DC']),
        'smb_df':     pd.DataFrame(smb_versions) if smb_versions else pd.DataFrame(columns=['Server IP', 'Client IP', 'Dialect', 'Raw Value']),
        'smb1_pairs': smb1_pairs,
        'ntlm_df':    pd.DataFrame(ntlm_rows).drop_duplicates() if ntlm_rows else pd.DataFrame(columns=['Source IP', 'Dest IP', 'Message', 'NTLM Version']),
        'ldap_df':    pd.DataFrame(ldap_rows).drop_duplicates() if ldap_rows else pd.DataFrame(columns=['Source IP', 'Dest IP', 'Operation', 'Detail']),
        'alerts_df':  pd.DataFrame(ad_alerts) if ad_alerts else pd.DataFrame(columns=['Severity', 'Finding', 'Detail']),
        'dc_candidates': dc_candidates,
    }


@st.cache_data(show_spinner=False)
def _cached_ad_detection(sig, _pcap):
    return get_ad_detection(_pcap)


def _security_scan(PCAPS):
    # Single pass over all packets collecting data for both alerts and
    # credential exposure — previously these were 7 separate full iterations.
    arp_ip_macs   = collections.defaultdict(set)
    modbus_writes  = collections.defaultdict(list)
    src_dst_ports  = collections.defaultdict(set)
    telnet_pairs   = set()
    ftp_pairs      = set()
    http_pairs     = set()
    cred_rows      = []

    for pcap in PCAPS:
        # ARP spoofing
        if pcap.haslayer("ARP"):
            arp = pcap.getlayer("ARP")
            if arp.op == 2:
                arp_ip_macs[arp.psrc].add(arp.hwsrc)

        if not pcap.haslayer("IP"):
            continue
        ip_layer = pcap.getlayer("IP")
        src, dst = ip_layer.src, ip_layer.dst

        # Modbus writes
        for layer_name in _MODBUS_WRITE_LAYERS:
            if pcap.haslayer(layer_name):
                modbus_writes[(src, dst)].append(
                    layer_name.replace("ModbusPDU", "").replace("Request", ""))
                break

        # TCP-specific checks
        if pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            sp, dp = tcp.sport, tcp.dport
            src_dst_ports[src].add((dst, dp))
            if sp == 23 or dp == 23:
                telnet_pairs.add((src, dst))
            if sp == 21 or dp == 21:
                ftp_pairs.add((src, dst))
            if sp == 80 or dp == 80:
                http_pairs.add((src, dst))

            # Credential extraction
            ts = datetime.fromtimestamp(float(pcap.time)).strftime('%Y-%m-%d %H:%M:%S')
            if pcap.haslayer("Raw"):
                payload_text = _to_text(pcap.getlayer("Raw").load) or ''
                if sp == 21 or dp == 21:
                    m = re.match(r'^(USER|PASS)\s+(\S+)', payload_text.strip(), re.IGNORECASE)
                    if m:
                        ctype = m.group(1).upper()
                        raw = m.group(2).strip()
                        cred_rows.append({'Time': ts, 'Protocol': 'FTP',
                                          'Source IP': src, 'Destination IP': dst,
                                          'Type': ctype,
                                          'Value': raw if ctype == 'USER' else '****',
                                          '_raw': raw})
                if sp == 23 or dp == 23:
                    if re.search(r'(login|username|user)\s*:', payload_text, re.IGNORECASE):
                        text_val = payload_text.strip()[:80]
                        cred_rows.append({'Time': ts, 'Protocol': 'Telnet',
                                          'Source IP': src, 'Destination IP': dst,
                                          'Type': 'Auth prompt', 'Value': text_val,
                                          '_raw': text_val})

            if pcap.haslayer(HTTPRequest):
                auth = pcap.getlayer(HTTPRequest).Authorization
                if auth:
                    auth_str = _to_text(auth) or ''
                    if 'Basic ' in auth_str:
                        try:
                            b64_part = auth_str.split('Basic ', 1)[1].strip()
                            decoded = base64.b64decode(b64_part + '==').decode('utf-8', errors='ignore')
                            if ':' in decoded:
                                username, password = decoded.split(':', 1)
                                ts = datetime.fromtimestamp(float(pcap.time)).strftime('%Y-%m-%d %H:%M:%S')
                                cred_rows.append({'Time': ts, 'Protocol': 'HTTP Basic Auth',
                                                  'Source IP': src, 'Destination IP': dst,
                                                  'Type': 'Credentials',
                                                  'Value': '%s:****' % username,
                                                  '_raw': decoded})
                        except Exception:
                            pass

    return {
        'arp_ip_macs':  dict(arp_ip_macs),
        'modbus_writes': dict(modbus_writes),
        'src_dst_ports': dict(src_dst_ports),
        'telnet_pairs': telnet_pairs,
        'ftp_pairs':    ftp_pairs,
        'http_pairs':   http_pairs,
        'cred_rows':    cred_rows,
    }


def get_security_alerts(PCAPS):
    s = _security_scan(PCAPS)
    alerts = []

    for ip, macs in s['arp_ip_macs'].items():
        if len(macs) > 1:
            alerts.append({'Severity': '🔴 High', 'Category': 'ARP Spoofing',
                            'Description': 'IP %s claimed by %d different MACs: %s' % (ip, len(macs), ', '.join(sorted(macs))),
                            'Affected IPs': ip})

    for (src, dst), cmds in s['modbus_writes'].items():
        counter = collections.Counter(cmds)
        summary = ', '.join('%s×%d' % (c, n) for c, n in counter.most_common(3))
        alerts.append({'Severity': '🔴 High', 'Category': 'Modbus Write',
                        'Description': '%s → %s: %d write command(s) — %s' % (src, dst, len(cmds), summary),
                        'Affected IPs': '%s → %s' % (src, dst)})

    for src, pairs in s['src_dst_ports'].items():
        if len(pairs) >= 20:
            alerts.append({'Severity': '🟡 Medium', 'Category': 'Port Scanning',
                            'Description': '%s contacted %d distinct destination/port combinations' % (src, len(pairs)),
                            'Affected IPs': src})

    if s['telnet_pairs']:
        ips = ', '.join('%s→%s' % p for p in sorted(s['telnet_pairs'])[:5])
        alerts.append({'Severity': '🟡 Medium', 'Category': 'Plaintext Protocol',
                        'Description': 'Telnet (port 23) detected — plaintext admin access. Pairs: %s%s' % (ips, ' …' if len(s['telnet_pairs']) > 5 else ''),
                        'Affected IPs': ', '.join(sorted({ip for pair in s['telnet_pairs'] for ip in pair}))})

    if s['ftp_pairs']:
        ips = ', '.join('%s→%s' % p for p in sorted(s['ftp_pairs'])[:5])
        alerts.append({'Severity': '🟡 Medium', 'Category': 'Plaintext Protocol',
                        'Description': 'FTP (port 21) detected — plaintext file transfer. Pairs: %s%s' % (ips, ' …' if len(s['ftp_pairs']) > 5 else ''),
                        'Affected IPs': ', '.join(sorted({ip for pair in s['ftp_pairs'] for ip in pair}))})

    if s['http_pairs']:
        alerts.append({'Severity': '🔵 Low', 'Category': 'Unencrypted HTTP',
                        'Description': 'Plain HTTP (port 80) detected across %d IP pair(s) — use HTTPS instead' % len(s['http_pairs']),
                        'Affected IPs': ', '.join(sorted({ip for pair in s['http_pairs'] for ip in pair})[:10])})

    if not alerts:
        return pd.DataFrame(columns=['Severity', 'Category', 'Description', 'Affected IPs'])
    return pd.DataFrame(alerts)


def get_credential_exposure(PCAPS):
    # Always drops _raw — safe for reports and PDF exports.
    rows = _security_scan(PCAPS)['cred_rows']
    if not rows:
        return pd.DataFrame(columns=['Time', 'Protocol', 'Source IP', 'Destination IP', 'Type', 'Value'])
    return pd.DataFrame(rows).drop_duplicates().drop(columns=['_raw'], errors='ignore')


def get_credential_exposure_full(PCAPS):
    # Keeps _raw column for the UI toggle — never exported to PDF.
    rows = _security_scan(PCAPS)['cred_rows']
    if not rows:
        return pd.DataFrame(columns=['Time', 'Protocol', 'Source IP', 'Destination IP', 'Type', 'Value', '_raw'])
    return pd.DataFrame(rows).drop_duplicates()


@st.cache_data(show_spinner=False)
def _cached_credential_exposure_full(sig, _pcap):
    return get_credential_exposure_full(_pcap)


@st.cache_data(ttl=86400, show_spinner=False)
def _query_nvd(keyword):
    try:
        resp = requests.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params={'keywordSearch': keyword, 'resultsPerPage': 10},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()
        cves = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', '')
            desc = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
            metrics = cve.get('metrics', {})
            severity = 'N/A'
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                if key in metrics and metrics[key]:
                    severity = metrics[key][0].get('cvssData', {}).get('baseSeverity', 'N/A')
                    break
            cves.append({'CVE ID': cve_id, 'Severity': severity, 'Summary': desc[:200]})
        return cves
    except Exception:
        return None


def get_cve_findings(data_of_pcap):
    firmware_hints = get_firmware_hints(data_of_pcap)
    rows = []
    seen_queries = {}

    for ip, hints in firmware_hints.items():
        for protocol, hint in hints:
            match = _match_known_software(protocol, hint)
            if not match:
                continue
            slug, version = match
            query = '%s %s' % (slug.replace('-', ' '), version)
            if query not in seen_queries:
                if seen_queries:          # not the first query — respect NVD rate limit
                    time.sleep(0.7)       # max ~5 req / 30 s for unauthenticated access
                seen_queries[query] = _query_nvd(query)
            cves = seen_queries[query]
            if not cves:
                continue
            for cve in cves:
                rows.append({
                    'IP': ip,
                    'Software': hint,
                    'CVE ID': cve['CVE ID'],
                    'CVE Severity': cve['Severity'],
                    'Summary': cve['Summary'],
                })

    if not rows:
        return pd.DataFrame(columns=['IP', 'Software', 'CVE ID', 'CVE Severity', 'Summary'])
    return pd.DataFrame(rows)


def page_security():
    st.subheader("Security Analysis")
    if not st.session_state.pcap_data_by_file:
        st.warning("No data loaded. Upload a PCAP file first.")
        return

    data_of_pcap = select_active_pcap_data()
    if not data_of_pcap:
        st.warning("No valid data for the selected capture.")
        return

    _sig = st.session_state.parsed_file_signature

    # ── Anomaly Alerts ────────────────────────────────────────────────────────
    st.markdown("### 🚨 Anomaly Alerts")
    alerts_df = _cached_security_alerts(_sig, data_of_pcap)
    if alerts_df.empty:
        st.success("No anomalies detected in this capture.")
    else:
        high   = alerts_df[alerts_df['Severity'].str.startswith('🔴')]
        medium = alerts_df[alerts_df['Severity'].str.startswith('🟡')]
        low    = alerts_df[alerts_df['Severity'].str.startswith('🔵')]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Alerts", len(alerts_df))
        c2.metric("🔴 High", len(high))
        c3.metric("🟡 Medium", len(medium))
        c4.metric("🔵 Low", len(low))
        st.dataframe(alerts_df, use_container_width=True, hide_index=True)
        st.download_button("Download as PDF",
            data=generate_table_pdf("Security Alerts", alerts_df, orientation="L"),
            file_name="security_alerts.pdf", mime="application/pdf",
            key="dl_security_alerts")

    st.divider()

    # ── Credential Exposure ───────────────────────────────────────────────────
    st.markdown("### 🔑 Credential Exposure")
    creds_df = _cached_credential_exposure(_sig, data_of_pcap)
    if creds_df.empty:
        st.success("No plaintext credentials detected.")
    else:
        st.warning("%d plaintext credential event(s) found." % len(creds_df))

        show_passwords = st.toggle(
            "Show passwords in plaintext",
            value=False,
            key="show_passwords_toggle",
            help="Passwords are masked by default. Enable to reveal captured values — handle with care.",
        )

        if show_passwords:
            full_df = _cached_credential_exposure_full(_sig, data_of_pcap)
            display_df = full_df.copy()
            if '_raw' in display_df.columns:
                display_df['Value'] = display_df['_raw']
                display_df = display_df.drop(columns=['_raw'])
        else:
            display_df = creds_df

        st.dataframe(display_df, use_container_width=True, hide_index=True)
        st.download_button("Download as PDF",
            data=generate_table_pdf("Credential Exposure", creds_df, orientation="L"),
            file_name="credential_exposure.pdf", mime="application/pdf",
            key="dl_credentials",
            help="PDF always exports with passwords masked.",
        )

    st.divider()

    # ── CVE Lookup ────────────────────────────────────────────────────────────
    st.markdown("### 🛡️ CVE Lookup")
    st.caption("Queries the NVD API for known CVEs matching detected firmware/software versions. Results cached for 24 h.")
    with st.spinner("Looking up CVEs…"):
        cve_df = get_cve_findings(data_of_pcap)
    if cve_df.empty:
        st.info("No CVEs found — either no recognisable software versions were detected, or none had matching NVD entries.")
    else:
        st.error("%d CVE(s) found across detected software." % len(cve_df))
        st.dataframe(cve_df, use_container_width=True, hide_index=True)
        st.download_button("Download as PDF",
            data=generate_table_pdf("CVE Findings", cve_df, orientation="L"),
            file_name="cve_findings.pdf", mime="application/pdf",
            key="dl_cves")

    st.divider()

    # ── Active Directory / Windows Protocol Detection ─────────────────────────
    st.markdown("### 🪟 Active Directory Detection")
    st.caption(
        "Detects AD-related protocols (Kerberos, LDAP, SMB, NTLM, DCE/RPC, WinRM, NetBIOS) "
        "and extracts security-relevant detail — NTLM version, SMB dialect, plaintext LDAP binds, "
        "likely Domain Controllers, and enumeration patterns. "
        "Finding AD traffic in an OT network is an IT/OT convergence finding."
    )

    ad = _cached_ad_detection(_sig, data_of_pcap)

    if ad['proto_df'].empty or ad['proto_df']['AD Protocols Seen'].eq('').all():
        st.info("No Active Directory / Windows protocol traffic detected in this capture.")
    else:
        # Security findings first
        if not ad['alerts_df'].empty:
            st.markdown("#### Security Findings")
            st.dataframe(ad['alerts_df'], use_container_width=True, hide_index=True)
            st.download_button("Download findings as PDF",
                data=generate_table_pdf("AD Security Findings", ad['alerts_df'], orientation="L"),
                file_name="ad_security_findings.pdf", mime="application/pdf",
                key="dl_ad_alerts")

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("#### Protocol Presence per IP")
            st.dataframe(ad['proto_df'], use_container_width=True, hide_index=True)

            if not ad['smb_df'].empty:
                st.markdown("#### SMB Dialect Negotiated")
                st.caption("SMBv1 is vulnerable to EternalBlue (MS17-010) — any presence is a critical finding.")
                if ad['smb1_pairs']:
                    st.error("SMBv1 traffic detected! %d session(s)" % len(ad['smb1_pairs']))
                st.dataframe(ad['smb_df'], use_container_width=True, hide_index=True)

        with col_right:
            if not ad['ntlm_df'].empty:
                st.markdown("#### NTLM Authentication")
                st.caption("NTLMv1 hashes can be cracked offline in minutes. NTLMv2 is stronger but still relayable.")
                ntlm1_count = int((ad['ntlm_df']['NTLM Version'] == 'NTLMv1').sum())
                ntlm2_count = int((ad['ntlm_df']['NTLM Version'] == 'NTLMv2').sum())
                c1, c2 = st.columns(2)
                c1.metric("NTLMv1 events", ntlm1_count, delta=ntlm1_count if ntlm1_count else None, delta_color="inverse" if ntlm1_count else "off")
                c2.metric("NTLMv2 events", ntlm2_count)
                st.dataframe(ad['ntlm_df'], use_container_width=True, hide_index=True)

        if not ad['ldap_df'].empty:
            st.markdown("#### LDAP Operations")
            st.caption("Simple bind operations send credentials in plaintext over port 389.")
            plain = int(ad['ldap_df']['Detail'].str.contains('plaintext', case=False, na=False).sum())
            if plain:
                st.error("%d plaintext LDAP bind(s) detected — credentials sent in cleartext." % plain)
            st.dataframe(ad['ldap_df'], use_container_width=True, hide_index=True)
            st.download_button("Download LDAP operations as PDF",
                data=generate_table_pdf("LDAP Operations", ad['ldap_df'], orientation="L"),
                file_name="ldap_operations.pdf", mime="application/pdf",
                key="dl_ldap")


# ─────────────────────────────────────────────────────────────────────────────

def build_topology(PCAPS):
    # Returns (nodes, edges) where:
    #   nodes: {ip: {'packets': int, 'bytes': int, 'internal': bool}}
    #   edges: {(src, dst): {'packets': int, 'bytes': int}}
    nodes = collections.defaultdict(lambda: {'packets': 0, 'bytes': 0, 'internal': True})
    edges = collections.defaultdict(lambda: {'packets': 0, 'bytes': 0})
    for pcap in PCAPS:
        if not pcap.haslayer("IP"):
            continue
        ip_layer = pcap.getlayer("IP")
        src, dst = ip_layer.src, ip_layer.dst
        pkt_len = len(corrupt_bytes(pcap))
        nodes[src]['packets'] += 1
        nodes[src]['bytes'] += pkt_len
        nodes[dst]['packets'] += 1
        nodes[dst]['bytes'] += pkt_len
        edges[(src, dst)]['packets'] += 1
        edges[(src, dst)]['bytes'] += pkt_len
    for ip, info in nodes.items():
        info['internal'] = classify_int_ext(ip) == "Internal"
    return dict(nodes), dict(edges)


def build_agraph_components(nodes, edges, min_packets, focus_nodes=None):
    visible_nodes = set()
    for (src, dst), info in edges.items():
        if info['packets'] >= min_packets:
            visible_nodes.add(src)
            visible_nodes.add(dst)

    max_bytes = max((n['bytes'] for n in nodes.values()), default=1) or 1
    ag_nodes = []
    for ip, info in nodes.items():
        if ip not in visible_nodes:
            continue
        size = 10 + 40 * (info['bytes'] / max_bytes)
        is_focus = focus_nodes and ip in focus_nodes
        if is_focus:
            color = "#FFD700"
        elif info['internal']:
            color = "#4a90d9"
        else:
            color = "#e05c5c"
        tooltip = (
            "%s\nType: %s\nPackets: %d\nBytes: %d%s"
        ) % (
            ip,
            "Internal" if info['internal'] else "External",
            info['packets'],
            info['bytes'],
            "\n[Filter match]" if is_focus else "",
        )
        ag_nodes.append(Node(id=ip, label=ip, title=tooltip, color=color, size=size))

    max_edge_pkts = max((e['packets'] for e in edges.values()), default=1) or 1
    ag_edges = []
    for (src, dst), info in edges.items():
        if info['packets'] < min_packets:
            continue
        width = 1 + 8 * (info['packets'] / max_edge_pkts)
        tooltip = "Packets: %d  Bytes: %d" % (info['packets'], info['bytes'])
        ag_edges.append(Edge(source=src, target=dst, title=tooltip, width=width, color="#aaaaaa"))

    config = Config(
        height=650, width="100%", directed=True, physics=True,
        stabilization=True, maxVelocity=50,
    )
    return ag_nodes, ag_edges, config


def page_topology():
    st.subheader("Network Topology")
    if not st.session_state.pcap_data_by_file:
        st.warning("No data loaded. Upload a PCAP file first.")
        return

    data_of_pcap = select_active_pcap_data()
    if not data_of_pcap:
        st.warning("No valid data for the selected capture.")
        return

    nodes, edges = _cached_topology(st.session_state.parsed_file_signature, data_of_pcap)
    if not edges:
        st.warning("No IP traffic found in this capture.")
        return

    col_filter, col_slider = st.columns([2, 3])
    with col_filter:
        ip_filter_input = st.text_input(
            "Focus on IP or network (CIDR)",
            value="",
            placeholder="e.g. 192.168.1.10 or 192.168.1.0/24",
            help="Shows only the matching IPs and their direct neighbours. Leave blank for the full map.",
            key="topology_ip_filter",
        )

    # Parse and apply the optional focus filter
    focus_network = parse_ip_filter(ip_filter_input) if ip_filter_input.strip() else None
    if ip_filter_input.strip() and focus_network is None:
        st.error("Invalid IP or CIDR — showing the full map instead.")

    if focus_network is not None:
        # Nodes that match the filter
        focus_nodes = {
            ip for ip in nodes
            if _ip_in_network(ip, focus_network)
        }
        if not focus_nodes:
            st.warning("No IPs in this capture match that filter — showing the full map.")
            focus_nodes = None
            visible_nodes = set(nodes.keys())
            visible_edges = edges
        else:
            # Expand to direct neighbours (1 hop) so you can see what they talk to
            neighbour_nodes = set()
            for (src, dst) in edges:
                if src in focus_nodes:
                    neighbour_nodes.add(dst)
                if dst in focus_nodes:
                    neighbour_nodes.add(src)
            visible_nodes = focus_nodes | neighbour_nodes
            visible_edges = {
                (s, d): info for (s, d), info in edges.items()
                if s in visible_nodes and d in visible_nodes
            }
            nodes = {ip: info for ip, info in nodes.items() if ip in visible_nodes}
            edges = visible_edges
    else:
        focus_nodes = None

    max_edge = max((e['packets'] for e in edges.values()), default=1)
    with col_slider:
        min_packets = st.slider(
            "Minimum packets per connection",
            min_value=1, max_value=max(2, max_edge), value=1, step=1,
            key="topology_min_packets",
        )

    col1, col2, col3 = st.columns(3)
    col1.metric("Unique IPs", len(nodes))
    col2.metric("Connections", sum(1 for e in edges.values() if e['packets'] >= min_packets))
    col3.metric("Total Packets", sum(e['packets'] for e in edges.values()))

    st.caption("🔵 Internal (RFC1918)  🔴 External (public)  🟡 Filter match — click a node to inspect its connections. Node size = traffic volume, edge thickness = packet count.")

    ag_nodes, ag_edges, config = build_agraph_components(nodes, edges, min_packets, focus_nodes=focus_nodes)
    clicked_node = agraph(nodes=ag_nodes, edges=ag_edges, config=config)

    # ── Node inspector — driven by clicking a node directly on the graph ──────
    if clicked_node:
        st.divider()
        st.subheader("Connections for  %s" % clicked_node)
        inbound_rows, outbound_rows = [], []
        for (src, dst), info in edges.items():
            if info['packets'] < min_packets:
                continue
            if dst == clicked_node:
                inbound_rows.append({
                    'Source IP': src,
                    'Type': classify_int_ext(src),
                    'Packets': info['packets'],
                    'Bytes': info['bytes'],
                })
            if src == clicked_node:
                outbound_rows.append({
                    'Destination IP': dst,
                    'Type': classify_int_ext(dst),
                    'Packets': info['packets'],
                    'Bytes': info['bytes'],
                })

        inbound_df  = pd.DataFrame(inbound_rows).sort_values('Packets', ascending=False)  if inbound_rows  else pd.DataFrame(columns=['Source IP', 'Type', 'Packets', 'Bytes'])
        outbound_df = pd.DataFrame(outbound_rows).sort_values('Packets', ascending=False) if outbound_rows else pd.DataFrame(columns=['Destination IP', 'Type', 'Packets', 'Bytes'])

        col_in, col_out = st.columns(2)
        with col_in:
            st.subheader("⬇ Inbound  (%d)" % len(inbound_df))
            st.dataframe(inbound_df, use_container_width=True, hide_index=True)
        with col_out:
            st.subheader("⬆ Outbound  (%d)" % len(outbound_df))
            st.dataframe(outbound_df, use_container_width=True, hide_index=True)


_NAV_TABS  = ["Home", "Upload File", "Raw Data & Filtering", "Analysis", "Topology", "Security", "Report", "Geoplots"]
_NAV_ICONS = ["house", "upload", "files", "graph-up", "diagram-3", "shield-exclamation", "file-earmark-text", "globe"]


def main():
    st.set_page_config(page_title="PCAP Dashboard", page_icon="📈", layout="wide")

    if "active_tab" not in st.session_state:
        st.session_state.active_tab = _NAV_TABS[0]

    active_idx = _NAV_TABS.index(st.session_state.active_tab)

    # ── Top horizontal navigation ─────────────────────────────────────────────
    selected = option_menu(
        menu_title=None,
        options=_NAV_TABS,
        icons=_NAV_ICONS,
        menu_icon="cast",
        default_index=0,
        orientation="horizontal",
        manual_select=active_idx,
        key="nav_top",
    )
    if selected and selected != st.session_state.active_tab:
        st.session_state.active_tab = selected
        st.rerun()

    selected = st.session_state.active_tab

    # Intro Page
    if selected == "Home":
        # Page header
        st.subheader("Understanding PCAP Files in Cybersecurity")
        Intro()

    # File uploader
    if selected == "Upload File":
        page_file_upload()
        page_display_info()

    # Raw Data Visualizer and Filtering
    if selected == "Raw Data & Filtering":
        st.subheader("Raw Data Can be Visualized Here")
        RawDataView()

    if selected == "Analysis":
        st.subheader("Dashboard")
        if "pcap_data" not in st.session_state:
            st.session_state.pcap_data = []
        # get analysis of data
        else:
            data_of_pcap = select_active_pcap_data()
            if not data_of_pcap:
                art = """
                .....+@*+@+..................................................*@+*@+.....
                ....%-....:*................................................*:....:@....
                .:%%*.....:*................................................*:.....*%%:.
                +=.......:@..................................................@-.......-*
                %..........*#..............................................#*..........%
                =*...-%:.....#+...................::::...................+%.....:%-..:#=
                ..:=-..+#:....:%=..........-*%%#+======+*#%#=:.........=%:....:#...-=:..
                .........*#.....-%-.....+%*==================+#%-....-%-.....#*.........
                ...........#*.....=%:-%*=========================#*-%=.....*#...........
                .............%+....-%+=============================#*....+%.............
                ..............:%=.#*=================================@-=%:..............
                ................=@====================================##................
                ................%===+*##%%%%%%%%%%%%%%%%%%%%%%%%###+===*=...............
                ...............@%%%####%%%%%@@@@@@@@@@@@@@@@%%%%%%###%%%@-..............
                ..........:+##%@%#*++++==========================++++*#%@@##*:..........
                .....*%@*+==========+#%%%%%@@%##**+++++**#%%@%%%%%%*==========+*%%*.....
                ...%+=========#@+::...................................:-%%=========+%...
                ...*%========*+........#@@@@%*............=%@@@@%:.......-@========%#...
                ......#@@#===*+.....=@@@@@@@@@@@........*@@@@@@@@@@+.....:@===#@@#:.....
                .............**....*@@@@@@@@@@@@@:.....%@@@@@@@@@@@@#....-@:............
                ..............%....@@@@@@@@@@@@@@@....=@@@@@@@@@@@@@@-...+=.............
                ..............*-...@@@@@@@@@@@@@@@....*@@@@@@@@@@@@@@-...%..............
                ...............@...#@@@@@@@@@@@@@=....:@@@@@@@@@@@@@@...#=..............
                ...............:%...%@@@@@@@@@@@*......=@@@@@@@@@@@@:..-+...............
                ................:#...:%@@@@@@@#....--....*@@@@@@@@=...+#................
                .................:%:.............+@@@@=..............#=.................
                ..................-%#............+@@@@=............=@=..................
                ................-%-..**:...........--............+#:.-%-................
                ..............:%=.....+%%+:...................=%%*.....=%:..............
                .............#+.....=%:..%=+%*=:.........=+%*-@..:%+.....+%.............
                ...........**.....-%-...:#*...%=:==**+=-=%...#+#...:%=.....*#...........
                .........+#:....-%-.....*@.:**#....-:....%**-.%@.....-%:.....#+.........
                ..:=-..=#:....:%=.......=*%..%.:-=+**+==:.%..%*@.......=%:....:#=..:-:..
                =#:..-%:.....#*..........@.=@*.....-:.....*%*.#:.........+#.....:%=..:#=
                %..........*#............=%...=#%*+++=*#%+:..*#............#*..........%
                *=.......:@...............-@:...............%+..............:@:.......-*
                .:%%*.....:*................##............*%:...............*:.....*#%:.
                ....%:....:*..................:%@#=::-*%@=..................*:....:@....
                .....+@++%*..................................................*%++@+.....
                """

                st.code(art)
            else:
                data_len_stats = pcap_len_statistic(data_of_pcap)  # protocol len statistics
                data_protocol_stats = common_proto_statistic(data_of_pcap, PD)  # count the occurrences of common network protocols
                data_count_dict = most_proto_statistic(data_of_pcap,
                                                       PD)  # counts the occurrences of each protocol and returns most common 10 protocols.
                http_key, http_value = https_stats_main(data_of_pcap)  # https Protocol Statistics
                dns_key, dns_value = dns_stats_main(data_of_pcap)  # DNS Protocol Statistics
                # Data Protocol analysis end

                # Traffic analysis start
                host_ip = get_host_ip(data_of_pcap)
                most_flow_dict = most_flow_statistic(data_of_pcap, PD)
                most_flow_dict = sorted(most_flow_dict.items(), key=lambda d: d[1], reverse=True)
                if len(most_flow_dict) > 10:
                    most_flow_dict = most_flow_dict[0:10]
                most_flow_key = list()
                for key, value in most_flow_dict:
                    most_flow_key.append(key)
                # Traffic analysis end

                # ///////////////////////////////////////////
                # ////     Data of Protocol Analysis    /////
                # ///////////////////////////////////////////
                # DataPacketLengthStatistics(data_len_stats)  #Piechart
                # # CommonProtocolStatistics(data_protocol_stats)
                # CommonProtocolStatistics_ploty(data_protocol_stats) #Barchart
                # MostFrequentProtocolStatistics(data_count_dict) #Piechart
                # HTTP_HTTPSAccessStatistics(http_key,http_value)  #Bar CHart axis -90
                # DNSAccessStatistics(dns_key,dns_value) #BarChart axis -90
                # col1, col2 = st.columns([2, 3])
                #
                # # Column 1: DataPacketLengthStatistics - Piechart
                # with col1:
                #     st.subheader("Data Packet Length Statistics")
                #     DataPacketLengthStatistics(data_len_stats)
                #
                #     # MostFrequentProtocolStatistics - Piechart
                #     st.subheader("Most Frequent Protocol Statistics")
                #     MostFrequentProtocolStatistics(data_count_dict)
                #
                # # Column 2: CommonProtocolStatistics_plotly - Barchart
                # with col2:
                #     st.subheader("Common Protocol Statistics")
                #     CommonProtocolStatistics_ploty(data_protocol_stats)
                #
                #     # HTTP_HTTPSAccessStatistics - BarChart axis -90
                #     st.subheader("HTTP/HTTPS Access Statistics")
                #     HTTP_HTTPSAccessStatistics(http_key, http_value)
                #
                #     # DNSAccessStatistics - BarChart axis -90
                #     st.subheader("DNS Access Statistics")
                #     DNSAccessStatistics(dns_key, dns_value)

                st.title(" Data of Protocol Analysis  ")
                # Create a 2x2 column layout
                col1, col2 = st.columns(2)

                # Column 1: Uneven row heights
                with col1:
                    # Row 1
                    with st.expander("Data Packet Length Statistics"):
                        DataPacketLengthStatistics(data_len_stats)

                    # Row 2 (smaller height)
                    with st.expander("Most Frequent Protocol Statistics"):
                        MostFrequentProtocolStatistics(data_count_dict)


                # Column 2: Uneven row heights
                with col2:
                    # Row 1
                    with st.expander("Common Protocol Statistics"):
                        CommonProtocolStatistics_ploty(data_protocol_stats)
                        st.download_button(
                            "Download as PDF",
                            data=generate_table_pdf("Common Protocol Statistics", common_protocol_df(data_protocol_stats)),
                            file_name="common_protocol_statistics.pdf",
                            mime="application/pdf",
                            key="download_common_protocol_stats_pdf",
                        )

                    # Row 2 (larger height)
                    with st.expander("HTTP/HTTPS Access Statistics Details"):
                        HTTP_HTTPSAccessStatistics(http_key, http_value)

                    # Row 3 (smaller height)
                    with st.expander("DNS Access Statistics"):
                        DNSAccessStatistics(dns_key, dns_value)

                # ///////////////////////////////////////////
                # ////        Device Inventory          /////
                # ///////////////////////////////////////////
                _sig = st.session_state.parsed_file_signature
                st.title("Device Inventory")
                device_df = _cached_device_inventory(_sig, data_of_pcap)
                st.dataframe(device_df, use_container_width=True)
                st.download_button(
                    "Download as PDF",
                    data=generate_table_pdf("Device Inventory", device_df, orientation="L", col_widths=(20, 30, 40, 60)),
                    file_name="device_inventory.pdf",
                    mime="application/pdf",
                    key="download_device_inventory_pdf",
                )

                st.title("Firmware/Version Hints")
                firmware_df = _cached_firmware_inventory(_sig, data_of_pcap)
                if firmware_df.empty:
                    st.info("No firmware/version hints found (requires unencrypted "
                            "HTTP/SNMP/Modbus/EtherNet-IP/FTP/Telnet/VNC/S7comm/BACnet/SSDP traffic).")
                else:
                    st.dataframe(firmware_df, use_container_width=True)
                    st.download_button(
                        "Download as PDF",
                        data=generate_table_pdf("Firmware/Version Hints", firmware_df, orientation="L", col_widths=(25, 25, 20, 60, 50)),
                        file_name="firmware_version_hints.pdf",
                        mime="application/pdf",
                        key="download_firmware_hints_pdf",
                    )

                st.title("AV/EDR Vendor Traffic")
                av_edr_df = _cached_av_edr_inventory(_sig, data_of_pcap)
                if av_edr_df.empty:
                    st.info("No AV/EDR vendor traffic detected (matches DNS queries, TLS SNI, and "
                            "HTTP Host/User-Agent against known antivirus/EDR vendor domains). "
                            "Absence doesn't mean no AV is installed - it may simply not have "
                            "phoned home during this capture, or use a non-cloud update server.")
                else:
                    st.caption(
                        "Presence only proves the host talked to that vendor's infrastructure, "
                        "not that the product is actively installed, running, or up to date."
                    )
                    st.dataframe(av_edr_df, use_container_width=True)
                    st.download_button(
                        "Download as PDF",
                        data=generate_table_pdf("AV/EDR Vendor Traffic", av_edr_df, orientation="L", col_widths=(25, 25, 40, 90)),
                        file_name="av_edr_vendor_traffic.pdf",
                        mime="application/pdf",
                        key="download_av_edr_pdf",
                    )

                # Inbound /Outbound

                st.title("Inbound /Outbound ")
                ip_filter_input = st.text_input(
                    "Filter by IP or network (CIDR)",
                    value=host_ip,
                    help="Enter a single IP (e.g. 192.168.1.10) or a network in CIDR notation "
                         "(e.g. 192.168.1.0/24). Inbound/Outbound below is computed relative to this value.",
                    key="io_ip_filter",
                )
                io_network = parse_ip_filter(ip_filter_input)
                if io_network is None:
                    st.error("Invalid IP or CIDR network. Showing results for the auto-detected host IP instead.")
                    io_network = parse_ip_filter(host_ip)

                # Internal vs External breakdown of the inbound/outbound traffic
                io_int_ext_df = internal_external_io_stats(data_of_pcap, io_network)
                with st.expander("Inbound/Outbound by Internal vs External IPs", expanded=True):
                    st.caption(
                        "Internal = private/RFC1918 address space, External = public address space, "
                        "for the remote side of each packet matching the filter above."
                    )
                    InternalExternalIOChart(io_int_ext_df)
                    st.dataframe(io_int_ext_df, use_container_width=True)
                    st.download_button(
                        "Download as PDF",
                        data=generate_table_pdf("Inbound/Outbound by Internal vs External IPs", io_int_ext_df),
                        file_name="inbound_outbound_internal_external.pdf",
                        mime="application/pdf",
                        key="download_io_int_ext_pdf",
                    )

                # IPs outside the filter's scope, tagged Internal/External
                outside_ip_df = outside_filter_ip_table(data_of_pcap, io_network)
                with st.expander("IPs Outside the Filter (Internal vs External)", expanded=True):
                    st.caption(
                        "Every remote IP seen talking to/from the filter above that falls outside it, "
                        "tagged Internal (private/RFC1918) or External (public)."
                    )
                    st.dataframe(outside_ip_df, use_container_width=True)
                    st.download_button(
                        "Download as PDF",
                        data=generate_table_pdf("IPs Outside the Filter", outside_ip_df, orientation="L"),
                        file_name="ips_outside_filter.pdf",
                        mime="application/pdf",
                        key="download_outside_filter_ip_pdf",
                    )




    if selected == "Topology":
        page_topology()

    if selected == "Security":
        page_security()

    if selected == "Report":
        page_report()

    if selected == "Geoplots":
        st.subheader("Geoplot")
        # ///////////////////////////////////////////
        # ////              Data of Geoplot     /////
        # ///////////////////////////////////////////
        if not os.path.exists(GEOIP_DB_PATH):
            st.warning(
                "GeoIP database not found at `%s`. Download the free MaxMind "
                "GeoLite2 City database (requires a free MaxMind account) and "
                "place the `.mmdb` file at that path to enable Geoplots." % GEOIP_DB_PATH
            )
        elif "pcap_data" not in st.session_state:
            st.session_state.pcap_data = []
            st.warning("No valid data for Geoplot.")
        else:
            data_of_pcap = select_active_pcap_data()
            if data_of_pcap:
                ipmap_result = ipmap(data_of_pcap)
                if ipmap_result.empty:
                    st.warning("No geolocatable IP addresses found in this capture "
                               "(likely only private/internal addresses).")
                else:
                    # Display the map in Streamlit
                    DrawFoliumMap(ipmap_result)
            else:
                st.warning("No valid data for Geoplot.")







if __name__ == "__main__":
    main()
