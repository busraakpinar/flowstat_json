#!/usr/bin/env python3

import os
import sys
import signal
import pyshark
import threading
import socket
import json
from pathlib import Path
from tabulate import tabulate


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    try:
        cap.force_stop()
    except:
        exit(0)

UNITS = {1000: ['KB', 'MB', 'GB'],
            1024: ['KiB', 'MiB', 'GiB']}

def approximate_size(size, flag_1024_or_1000=True):
    mult = 1024 if flag_1024_or_1000 else 1000
    for unit in UNITS[mult]:
        size = size / mult
        if size < mult:
            return '{0:.3f} {1}'.format(size, unit)

class PacketCapture(threading.Thread):
    capture = 1

    def __init__(self, target_name):
        threading.Thread.__init__(self)
        self.target_name = target_name
        self.is_live = not ".pcap" in self.target_name
        self.l2_conversation_info = dict()
        self.l4_conversation_info = dict()
        self.print_flow_table_enabled = True
        self.dump_expected_json_enabled = True
        self.running_as_application = False

    def set_print_flow_table(self, value:bool):
        self.print_flow_table_enabled = value
    
    def set_dump_expected_json_enabled(self, value:bool):
        self.dump_expected_json_enabled = value

    def set_running_as_application(self, value:bool):
        self.running_as_application = value

    @staticmethod
    def make_two_tuple(srcmac, dstmac):
        return (min(srcmac,dstmac), max(srcmac,dstmac))

    @staticmethod
    def make_five_tuple(srcip, srcport, dstip, dstport, l4proto):
        return (min(srcip, dstip), min(srcport,dstport), max(srcip,dstip), max(srcport,dstport), l4proto)

    def print_flow_table(self):

        if not self.print_flow_table_enabled:
            return

        print("> Flow summary")

        print( tabulate(
            self.l4_conversation_info.values(), 
            headers=["Source IP", "Source Port", "Destination IP", "Destination Port", "Layer Composition", "L4 Proto", "L7 Proto", "Packet Count", "Total Traffic (bytes)"], 
            tablefmt="fancy_grid", 
            showindex="always" 
        ) )
        pass

    def dump_expected_json(self):

        if not self.dump_expected_json_enabled:
            return

        d = dict()
        d["total_flow_count"] = len(self.l4_conversation_info.values())
        d["flows"] = list()

        flow_id = 1
        for flow_info in self.l4_conversation_info.values():
            d["flows"].append(
                { 
                    "flow_id" : flow_id ,
                    "protocol_name": flow_info[6]
                }
            )

            flow_id = flow_id + 1
            pass
        
        file_path = Path(self.target_name)
        json_file_name = file_path.stem + ".json"

        with open(json_file_name, 'w') as f:
            f.write(json.dumps(d, indent=2))


    def packet_callback(self, pkt):
        try:
            capture_length = pkt.captured_length
            protocol =  pkt.transport_layer
            protocol_l7 =  pkt.highest_layer
            # print(pkt)
            if hasattr(pkt, "ip"):
                src_addr = pkt.ip.src
                dst_addr = pkt.ip.dst
            elif hasattr(pkt, "ipv6"):
                src_addr = pkt.ipv6.src
                dst_addr = pkt.ipv6.dst
            else:
                # Non-IP packet
                return 
            src_port = pkt[pkt.transport_layer].srcport
            
            dst_port = pkt[pkt.transport_layer].dstport
            five_tuple = PacketCapture.make_five_tuple(src_addr, src_port, dst_addr, dst_port, protocol)
            layers = pkt.layers
            layer_composition = " > ".join([str(layer.layer_name).upper() for layer in layers])

            # (mgilor): Hack to show `real` L7 protocol when wireshark dissects some
            # fake layers
            if len(layers) > 4:
                # Skip vssmonitoring ethernet trailer
                if layers[3].layer_name.upper() == "VSSMONITORING":
                    protocol = layers[2].layer_name.upper()
                elif layers[3].layer_name != "tpkt":
                    protocol_l7 = layers[3].layer_name.upper()
                
            if self.is_live:
                print("[[{0:16} @ {1:5}]] >>> [[{2:16} @ {3:5}]]  {4:5} {5} bytes".format(src_addr, src_port, dst_addr, dst_port, protocol, capture_length))
            if five_tuple in self.l4_conversation_info:
                if protocol_l7 not in  ("TCP", "UDP"):
                    self.l4_conversation_info[five_tuple] = (src_addr, src_port, dst_addr, dst_port, layer_composition, protocol, protocol_l7, self.l4_conversation_info[five_tuple][7] + 1, int(self.l4_conversation_info[five_tuple][8]) + int(capture_length))
                else:
                    self.l4_conversation_info[five_tuple] = (
                        self.l4_conversation_info[five_tuple][0], 
                        self.l4_conversation_info[five_tuple][1], 
                        self.l4_conversation_info[five_tuple][2], 
                        self.l4_conversation_info[five_tuple][3], 
                        self.l4_conversation_info[five_tuple][4], 
                        self.l4_conversation_info[five_tuple][5],
                        self.l4_conversation_info[five_tuple][6],
                        self.l4_conversation_info[five_tuple][7] + 1,
                        int(self.l4_conversation_info[five_tuple][8]) + int(capture_length),
                    )
            else:
                self.l4_conversation_info[five_tuple] = (src_addr, src_port, dst_addr, dst_port, layer_composition, protocol, protocol_l7, 1, int(capture_length))

           
        except AttributeError as e:
            # print(e)
            # ignore packets that aren't TCP/UDP or IPv4
            pass

    def force_stop(self):
        self.stop()
        raise Exception("interrupted")

    def stop(self):
        self.capture = 0
        self.print_flow_table()
        self.dump_expected_json()
        

    def run(self):
        if ".pcap" in self.target_name:
            capture = pyshark.FileCapture(self.target_name, disable_protocol="data-text-lines")
            print(capture.get_parameters())
            capture.apply_on_packets(self.packet_callback)
            if self.running_as_application:
                os.kill(os.getpid(), signal.SIGINT)
            else:
                self.stop()

        else:
            capture = pyshark.LiveCapture(interface=self.target_name)
            capture.apply_on_packets(self.packet_callback)
            try:
                for packet in capture.sniff_continuously():
                    if not self.capture:
                        capture.stop()
                        capture.close()
            except pyshark.capture.capture.TSharkCrashException:
                self.exited = 1
                print("Capture has crashed")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C to stop live capture')

    if len(sys.argv) == 1:
        cap = PacketCapture("Any")
    else:
        cap = PacketCapture(sys.argv[1])
    cap.set_running_as_application(True)
    cap.run()
    signal.pause()
    cap.stop()


