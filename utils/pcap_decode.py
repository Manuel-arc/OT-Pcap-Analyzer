import io
import subprocess

import numpy as np
import pandas as pd

# Fields pulled from tshark in one subprocess call per uploaded file. This
# replaces scapy's rdpcap() (~5,850 packets/sec, full Python-object dissection
# of every packet) with Wireshark's compiled C dissectors (~23,300 packets/sec)
# for the generic per-packet classification every "fast path" function needs.
# _ws.col.Info gives a real Wireshark-quality summary string for the Raw Data
# table - cheap to always include (tested: ~2s difference over 338k packets),
# unlike scapy's p.summary() which dominated runtime when called per packet.
_TSHARK_FIELDS = [
    'frame.time_epoch', 'frame.len',
    'eth.src', 'eth.dst', 'eth.type',
    'ip.src', 'ip.dst', 'ip.proto', 'ip.ttl',
    'ipv6.src', 'ipv6.dst', 'ipv6.nxt',
    'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport',
    'arp.opcode', 'icmpv6.type', 'dns.qry.name',
    '_ws.col.Info', '_ws.col.Protocol',
]


class PcapDecode:
    def __init__(self):
        with open('utils/protocol/ETHER', 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]

        with open('utils/protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        with open('utils/protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        with open('utils/protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

        with open('utils/protocol/UDP', 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]

    def build_dataframe(self, pcap_path):
        # One tshark subprocess call extracts generic per-packet fields via
        # Wireshark's compiled dissectors (see _TSHARK_FIELDS comment above).
        # -E quote=d + pandas' default quotechar keeps embedded commas in the
        # Info column from corrupting the field boundaries.
        cmd = ['tshark', '-r', pcap_path, '-n', '-T', 'fields']
        for field in _TSHARK_FIELDS:
            cmd += ['-e', field]
        cmd += ['-E', 'separator=,', '-E', 'quote=d', '-E', 'occurrence=f']
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        df = pd.read_csv(
            io.StringIO(proc.stdout), header=None, names=_TSHARK_FIELDS,
            dtype=str, keep_default_na=False, na_values=[],
        )
        return self._classify(df)

    def _classify(self, df):
        # Vectorized re-implementation of the priority logic in ip_decode/
        # tcp_decode/udp_decode below: PORT_DICT (well-known ports) wins over
        # TCP_DICT/UDP_DICT (registered ports), dst port is checked before src
        # port, TCP is checked before UDP, IPv4 before IPv6, and a packet with
        # no Ethernet layer at all falls back to 'Unknow' - matching the
        # original nested-if behavior exactly so callers see identical output.
        def num(col):
            return pd.to_numeric(df[col].replace('', np.nan), errors='coerce')

        has_eth = df['eth.src'] != ''
        has_ip = df['ip.src'] != ''
        has_ipv6 = (~has_ip) & (df['ipv6.src'] != '')

        tcp_sport, tcp_dport = num('tcp.srcport'), num('tcp.dstport')
        udp_sport, udp_dport = num('udp.srcport'), num('udp.dstport')
        has_tcp = tcp_dport.notna() & (has_ip | has_ipv6)
        has_udp = (~has_tcp) & udp_dport.notna() & (has_ip | has_ipv6)

        def port_lookup(dport, sport):
            return (dport.map(self.PORT_DICT)
                    .fillna(sport.map(self.PORT_DICT)))

        tcp_proto = port_lookup(tcp_dport, tcp_sport) \
            .fillna(tcp_dport.map(self.TCP_DICT)) \
            .fillna(tcp_sport.map(self.TCP_DICT)).fillna('TCP')
        udp_proto = port_lookup(udp_dport, udp_sport) \
            .fillna(udp_dport.map(self.UDP_DICT)) \
            .fillna(udp_sport.map(self.UDP_DICT)).fillna('UDP')

        ip_other = num('ip.proto').map(self.IP_DICT).fillna('IPv4')
        ipv6_other = num('ipv6.nxt').map(self.IP_DICT).fillna('IPv6')
        eth_type_num = df['eth.type'].map(lambda x: int(x, 16) if x else np.nan)
        # Frames with no real EtherType (802.3/LLC framing - e.g. STP BPDUs)
        # have nothing to look up in ETHER_DICT; tshark's own protocol column
        # is a far better fallback than a blank label for those.
        ether_other = eth_type_num.map(self.ETHER_DICT) \
            .fillna(eth_type_num.map(lambda x: hex(int(x)) if pd.notna(x) else np.nan)) \
            .fillna(df['_ws.col.Protocol'])

        l3_src = df['ip.src'].where(has_ip, df['ipv6.src'].where(has_ipv6, df['eth.src']))
        l3_dst = df['ip.dst'].where(has_ip, df['ipv6.dst'].where(has_ipv6, df['eth.dst']))
        port_src = tcp_sport.where(has_tcp, udp_sport.where(has_udp, np.nan))
        port_dst = tcp_dport.where(has_tcp, udp_dport.where(has_udp, np.nan))
        has_port = has_tcp | has_udp
        port_suffix_src = ':' + port_src.astype('Int64').astype(str)
        port_suffix_dst = ':' + port_dst.astype('Int64').astype(str)

        out = pd.DataFrame({
            'time': pd.to_datetime(num('frame.time_epoch'), unit='s'),
            'Source': (l3_src + port_suffix_src.where(has_port, '')),
            'Destination': (l3_dst + port_suffix_dst.where(has_port, '')),
            'Procotol': np.select(
                [~has_eth, has_tcp, has_udp, has_ip, has_ipv6],
                ['Unknow', tcp_proto, udp_proto, ip_other, ipv6_other],
                default=ether_other,
            ),
            'len': num('frame.len').astype('Int64'),
            'info': df['_ws.col.Info'],
            # Raw typed fields, for fast-path functions that classify packets
            # differently than the Source/Destination/Procotol columns above
            # (e.g. common_proto_statistic's ARP/ICMP/DNS-first bucketing) or
            # that just need plain IP/MAC/port access without string parsing.
            'ip_src': df['ip.src'].replace('', np.nan),
            'ip_dst': df['ip.dst'].replace('', np.nan),
            'ip_ttl': num('ip.ttl'),
            'ipv6_src': df['ipv6.src'].replace('', np.nan),
            'ipv6_dst': df['ipv6.dst'].replace('', np.nan),
            'eth_src': df['eth.src'].replace('', np.nan),
            'eth_dst': df['eth.dst'].replace('', np.nan),
            'eth_type': eth_type_num,
            'tcp_sport': tcp_sport, 'tcp_dport': tcp_dport,
            'udp_sport': udp_sport, 'udp_dport': udp_dport,
            'has_arp': df['arp.opcode'] != '',
            'has_icmp': (num('ip.proto') == 1) | (num('icmpv6.type') == 135),
            'dns_qry_name': df['dns.qry.name'].replace('', np.nan),
        })
        out.loc[~has_eth, ['Source', 'Destination']] = 'Unknow'
        return out
