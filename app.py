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
from scapy.contrib.modbus import ModbusPDU2B0EReadDeviceIdentificationResponse, ModbusObjectId
import collections
import ipaddress
import re
import struct
import tempfile
import sys
import pandas as pd
from scapy.utils import corrupt_bytes
from streamlit_echarts import st_echarts
import geoip2.database
import pydeck as pdk
import folium
from streamlit_option_menu import option_menu
from utils.pcap_decode import PcapDecode
import time
import plotly.express as px
from fpdf import FPDF

PD = PcapDecode()  # Parser
PCAPS = None  # Packets


if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = None

if 'pcap_data' not in st.session_state:
    st.session_state.pcap_data = None

if 'pcap_data_by_file' not in st.session_state:
    st.session_state.pcap_data_by_file = {}

if 'parsed_file_signature' not in st.session_state:
    st.session_state.parsed_file_signature = None

if 'uploader_key_version' not in st.session_state:
    # Bumped whenever files are cleared/removed so the file_uploader widget
    # below is recreated with a fresh key - otherwise Streamlit keeps the
    # browser-side widget's previous selection and silently re-adds files
    # we just removed on the next rerun.
    st.session_state.uploader_key_version = 0

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
    combined = [packet for packets in st.session_state.pcap_data_by_file.values() for packet in packets]
    combined.sort(key=lambda p: p.time)
    st.session_state.pcap_data = combined
    st.session_state.parsed_file_signature = tuple(sorted((f.name, f.size) for f in st.session_state.uploaded_files))
    # Force the file_uploader widget to forget this file too, otherwise its
    # browser-side selection would re-add it on the next rerun.
    st.session_state.uploader_key_version += 1
    _reset_data_view_selector_if_stale()


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
                combined, pcap_by_file = parse_uploaded_files(uploaded_files)
                st.session_state.pcap_data = combined
                st.session_state.pcap_data_by_file = pcap_by_file
            st.session_state.parsed_file_signature = file_signature

        st.success(f"{len(uploaded_files)} file(s) uploaded successfully!")
        if st.button("Clear All Uploaded Files"):
            st.session_state.uploaded_files = None
            st.session_state.pcap_data = None
            st.session_state.pcap_data_by_file = {}
            st.session_state.parsed_file_signature = None
            st.session_state.uploader_key_version += 1
            _reset_data_view_selector_if_stale()
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
    # Display uploaded file information, each with its own delete button so
    # files can be removed individually instead of only all at once.
    if st.session_state.get("uploaded_files"):
        for uploaded_file in st.session_state.uploaded_files:
            col1, col2 = st.columns([5, 1])
            with col1:
                file_details = {"File Name": uploaded_file.name,
                                "File Type": uploaded_file.type,
                                "File Size": uploaded_file.size}
                st.write(file_details)
            with col2:
                if st.button("Remove", key="remove_file_%s_%d" % (uploaded_file.name, uploaded_file.size)):
                    remove_uploaded_file(uploaded_file.name, uploaded_file.size)
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


def RawDataView():
    pcap_data = select_active_pcap_data()
    if pcap_data:
        # Example: Get all PCAPs
        all_data = get_all_pcap(pcap_data, PD)
        dataframe_data = process_json_data(all_data)
        start_time, end_time, live_time_duration, live_time_duration_str = calculate_live_time(pcap_data)

        # Add live time information to the data frame
        # dataframe_data['Start Time'] = start_time
        # dataframe_data['End Time'] = end_time
        dataframe_data['Live Time Duration'] = live_time_duration_str
        all_columns = list(dataframe_data.columns)
        st.sidebar.header("P1ease Filter Here:")
        # st.sidebar.divider()
        # Filter reset button
        if st.sidebar.button("Reset Filters"):
            st.experimental_rerun()
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


def generate_table_pdf(title, df, orientation="P", col_widths=None):
    pdf = FPDF(orientation=orientation)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", size=9)
    table_data = [list(df.columns)] + df.astype(str).values.tolist()
    with pdf.table(table_data, col_widths=col_widths):
        pass
    return bytes(pdf.output())


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

def main():
    st.set_page_config(page_title="PCAP Dashboard", page_icon="📈", layout="wide")
    # download from Bootstrap
    selected = option_menu(
        menu_title=None,
        options=["Home", "Upload File", "Raw Data & Filtering", "Analysis","Geoplots"],
        icons=["house", "upload", "files", "graph-up","globe"],
        menu_icon="cast",
        default_index=0,
        orientation="horizontal"
    )

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
                st.title("Device Inventory")
                device_df = get_device_inventory(data_of_pcap)
                st.dataframe(device_df, use_container_width=True)
                st.download_button(
                    "Download as PDF",
                    data=generate_table_pdf("Device Inventory", device_df, orientation="L", col_widths=(20, 30, 40, 60)),
                    file_name="device_inventory.pdf",
                    mime="application/pdf",
                    key="download_device_inventory_pdf",
                )

                st.title("Firmware/Version Hints")
                firmware_df = get_firmware_inventory(data_of_pcap)
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
                av_edr_df = get_av_edr_inventory(data_of_pcap)
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
