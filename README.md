# Flowstat

A small utility to summarize all flows in a live capture or pcap file.

IMPORTANT NOTE: If your user has no privilege to open interfaces, run script with sudo

# Install

This tool requires tshark to be present. Install it via your package manager.

For debian-like os'es:

```bash
apt install tshark
```

For MacOS:

```bash
brew install wireshark
```

and then run `pip3 install -r requirements.txt`.

NOTE: Due to a bug in pyshark, the script fails in some pcap files due to xml parsing errors. To fix that, execute the following command to patch pyshark:

```bash
python3 pyshark_patch.py
```

# Usage

```bash
python3 flowstat.py <interface name or pcap file name>
```

Tool can operate with live capture or pcap files.

## Live capture

Specify interface name as last parameter.

```bash
python3 flowstat.py eth1
```

If you want to open all available devices, just run script with no arguments.

```bash
python3 flowstat.py
```

## Pcap

Specify pcap file path as last parameter.

```bash
python3 flowstat.py /home/nettsi/h323_001.pcap
```

## Example output

```text
✘-INT ~/workspace/scratchpad/flowstat [master ↑·1|…1] 
16:07 $ python3 flowstat.py any
Press Ctrl+C to stop live capture
[[192.168.1.24     @ 39682]] >>> [[192.168.1.21     @ 8009 ]]  TCP   178 bytes
[[192.168.1.21     @ 8009 ]] >>> [[192.168.1.24     @ 39682]]  TCP   178 bytes
[[192.168.1.24     @ 39682]] >>> [[192.168.1.21     @ 8009 ]]  TCP   68 bytes
[[127.0.0.1        @ 46624]] >>> [[127.0.0.1        @ 60008]]  TCP   68 bytes
[[127.0.0.1        @ 60008]] >>> [[127.0.0.1        @ 46624]]  TCP   68 bytes
[[192.168.1.24     @ 45408]] >>> [[198.252.206.25   @ 443  ]]  TCP   68 bytes
[[198.252.206.25   @ 443  ]] >>> [[192.168.1.24     @ 45408]]  TCP   68 bytes
^CYou pressed Ctrl+C!
> Flow summary
╒════╤══════════════╤═══════════════╤══════════════════╤════════════════════╤═════════════════════╤════════════╤════════════╤════════════════╤═════════════════════════╕
│    │ Source IP    │   Source Port │ Destination IP   │   Destination Port │ Layer Composition   │ L4 Proto   │ L7 Proto   │   Packet Count │   Total Traffic (bytes) │
╞════╪══════════════╪═══════════════╪══════════════════╪════════════════════╪═════════════════════╪════════════╪════════════╪════════════════╪═════════════════════════╡
│  0 │ 192.168.1.24 │         39682 │ 192.168.1.21     │               8009 │ SLL > IP > TCP      │ TCP        │ TCP        │              3 │                     424 │
├────┼──────────────┼───────────────┼──────────────────┼────────────────────┼─────────────────────┼────────────┼────────────┼────────────────┼─────────────────────────┤
│  1 │ 127.0.0.1    │         46624 │ 127.0.0.1        │              60008 │ SLL > IP > TCP      │ TCP        │ TCP        │              2 │                     136 │
├────┼──────────────┼───────────────┼──────────────────┼────────────────────┼─────────────────────┼────────────┼────────────┼────────────────┼─────────────────────────┤
│  2 │ 192.168.1.24 │         45408 │ 198.252.206.25   │                443 │ SLL > IP > TCP      │ TCP        │ TCP        │              2 │                     136 │
╘════╧══════════════╧═══════════════╧══════════════════╧════════════════════╧═════════════════════╧════════════╧════════════╧════════════════╧═════════════════════════╛
```
