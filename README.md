# OT-PCAP-Analyzer

A Streamlit dashboard for analyzing PCAP/CAP network captures, with a focus on
OT/ICS protocol traffic (Modbus, DNP3, S7comm, BACnet, Profinet) alongside
standard IT traffic analysis.

Built on top of [paresh2806/PCAP-Analyzer](https://github.com/paresh2806/PCAP-Analyzer),
extended with OT protocol identification, device inventory, and some QOL changes.

## Features

- **Upload** one or more `.pcap` / `.cap` / `.csv` files at a time, added
  incrementally without losing previously uploaded files.
- **Raw Data & Filtering** — full packet table with sidebar filters by
  protocol, length, source, and destination, plus summary statistics for the
  filtered selection.
- **Per-file or combined view** — inspect a single uploaded capture on its
  own, or all uploaded captures merged into one time-sorted view.
- **Protocol Analysis**:
  - Packet-length distribution, most-frequent protocols, HTTP/HTTPS and DNS
    access statistics.
  - Common protocol statistics (packet count) and total protocol packet flow
    (bytes), both resolving OT protocols by well-known port/EtherType —
    **Modbus**, **DNP3**, **S7comm**, **BACnet**, **EtherNet/IP**, **IEC-104**,
    **OPC UA**, **Profinet** — instead of lumping everything into generic
    TCP/UDP buckets.
  - Time-flow, inbound/outbound traffic, and per-IP traffic charts.
- **Device Inventory** — every MAC address seen, resolved to a manufacturer
  via the IEEE OUI database (e.g. Siemens, Rockwell/Allen-Bradley, Schneider
  Electric), paired with the IP address(es) it used.
- **Geoplots** — geolocates external peer IPs (via MaxMind GeoLite2) and
  plots them on a map; gracefully skipped for captures with only
  private/internal IP traffic.

## Requirements

- Python 3.9+
- A MaxMind GeoLite2 City database at `utils/GeoIP/GeoLite2-City.mmdb`
  (already included in this repo)

## Installation

```bash
git clone https://github.com/Manuel-arc/OT-PCAP-Analyzer.git
cd OT-PCAP-Analyzer
pip install -r requirements.txt
```

## Usage

```bash
streamlit run app.py
```

Then open the URL Streamlit prints (default `http://localhost:8501`), go to
**Upload File**, upload one or more captures, and explore the **Raw Data &
Filtering**, **Analysis**, and **Geoplots** tabs.

Sample OT captures are included under the repo root for quick testing:
`Modbus.pcap`, `2-S7comm-VarService-CyclicData-1s.pcap`,
`BACnetARRAY-element-0.pcap`, `DNP3-Read.pcap`, `DNP3-Malformed.pcap`.

## Project structure

```
app.py                      # Streamlit app (UI + analysis logic)
utils/
  pcap_decode.py             # Packet -> protocol/source/destination decoder
  protocol/                  # Port/EtherType -> protocol name lookup tables
  GeoIP/GeoLite2-City.mmdb   # MaxMind GeoLite2 City database
requirements.txt
```
