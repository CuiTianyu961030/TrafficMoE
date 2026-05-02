from flowcontainer.extractor import extract
import binascii
import scapy.all as scapy
from collections import defaultdict
import numpy as np
import os


MAX_PACKET_NUMBER = 300 
MAX_PACKET_LENGTH_IN_FLOW = 256
HEX_PACKET_START_INDEX = 76 


class FlowRecord:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, n_packet, n_up_packet, n_down_packet, bytes,
                 avg_payload_length, avg_packet_length, pre_packet_length, pre_payload_length, max_ttl, min_ttl,
                 avg_ttl, max_window_size, min_window_size, avg_window_size, duration, avg_interval, max_interval,
                 packet_speed, byte_speed):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.n_packet = n_packet
        self.n_up_packet = n_up_packet
        self.n_down_packet = n_down_packet
        self.bytes = bytes
        self.avg_payload_length = avg_payload_length
        self.avg_packet_length = avg_packet_length
        self.pre_packet_length = pre_packet_length
        self.pre_payload_length = pre_payload_length
        self.max_ttl = max_ttl
        self.min_ttl = min_ttl
        self.avg_ttl = avg_ttl
        self.max_window_size = max_window_size
        self.min_window_size = min_window_size
        self.avg_window_size = avg_window_size
        self.duration = duration
        self.avg_interval = avg_interval
        self.max_interval = max_interval
        self.packet_speed = packet_speed
        self.byte_speed = byte_speed


def normalization_src_dst(src, sport, dst, dport):
    if sport < dport:
        return dst, dport, src, sport
    elif sport == dport:
        src_ip = "".join(src.split('.'))
        dst_ip = "".join(dst.split('.'))
        if int(src_ip) < int(dst_ip):
            return dst, dport, src, sport
        else:
            return src, sport, dst, dport
    else:
        return src, sport, dst, dport


def build_flow_data(pcap_file, flow_feature="PLS"):

    build_data = []

    # Packet Length Sequences(PLS) features for flow-level detection
    if flow_feature == "PLS":
        packets = scapy.rdpcap(pcap_file)
        flows = defaultdict(lambda: {'bytes': []})

        for packet in packets:
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                else:
                    continue
                proto = packet["IP"].proto

                ip_src, sport, ip_dst, dport = normalization_src_dst(ip_src, sport, ip_dst, dport)

                flow_tuple = (ip_src, ip_dst, sport, dport, proto)
                flows[flow_tuple]["bytes"].append(str(len(packet)))

        for flow_tuple in flows.keys():
            flow_data = ", ".join(flows[flow_tuple]["bytes"])
            build_data.append(flow_data)

    # Packet Direction Sequences(PDS) features for flow-level detection
    elif flow_feature == "PDS":
        packets = scapy.rdpcap(pcap_file)
        flows = defaultdict(lambda: {'direction': []})

        for packet in packets:
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                else:
                    continue
                proto = packet["IP"].proto

                ip_src, sport, ip_dst, dport = normalization_src_dst(ip_src, sport, ip_dst, dport)

                flow_tuple = (ip_src, ip_dst, sport, dport, proto)
                flows[flow_tuple]["direction"].append(str(1 if (packet.haslayer("TCP") or packet.haslayer("UDP")) and packet.sport == sport else -1))

        for flow_tuple in flows.keys():
            flow_data = ", ".join(flows[flow_tuple]["direction"])
            build_data.append(flow_data)

    # Packet Arrival Interval(PAI) features for flow-level detection
    elif flow_feature == "PAI":

        packets = scapy.rdpcap(pcap_file)
        flows = defaultdict(lambda: {'pkt_time_list': []})

        for packet in packets:
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                else:
                    continue
                proto = packet["IP"].proto

                ip_src, sport, ip_dst, dport = normalization_src_dst(ip_src, sport, ip_dst, dport)

                flow_tuple = (ip_src, ip_dst, sport, dport, proto)
                flows[flow_tuple]["pkt_time_list"].append(packet.time)

        for flow_tuple in flows.keys():
            flow_seq = []
            time_seq = flows[flow_tuple]["pkt_time_list"]
            for i, arrival_time in enumerate(time_seq):
                if i >= min(MAX_PACKET_NUMBER, len(time_seq) - 1):
                    break
                flow_seq.append(str((time_seq[i + 1] - time_seq[i]) * 1000))
            flow_data = ", ".join(flow_seq)
            build_data.append(flow_data)

    # Flow Statistics(FS) features for flow-level detection
    elif flow_feature == "FS":
        packets = scapy.rdpcap(pcap_file)
        flows = defaultdict(lambda: {'n_packet': 0,
                                     'n_up_packet': 0,
                                     'n_down_packet': 0,
                                     'bytes': 0,
                                     'avg_payload_length': 0.00,
                                     'avg_packet_length': 0.00,
                                     'pre_packet_length': 0.00,
                                     'pre_payload_length': 0.00,
                                     'max_ttl': -1,
                                     'min_ttl': 1e8,
                                     'avg_ttl': 0.00,
                                     'max_window_size': -1,
                                     'min_window_size': 1e8,
                                     'avg_window_size': 0.00,
                                     'pkt_time_list': [],
                                     'pkt_interval_list': [],
                                     'duration': 0.00,
                                     'avg_interval': 0.00,
                                     'max_interval': 0.00,
                                     'packet_speed': 0.00,
                                     'byte_speed': 0.00
                                     })

        for packet in packets:
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                else:
                    continue
                proto = packet["IP"].proto

                ip_src, sport, ip_dst, dport = normalization_src_dst(ip_src, sport, ip_dst, dport)

                flow_tuple = (ip_src, ip_dst, sport, dport, proto)
                flows[flow_tuple]["n_packet"] += 1
                flows[flow_tuple]["n_up_packet"] += 1 if (packet.haslayer("TCP") or packet.haslayer("UDP")) and packet.sport == sport else 0
                flows[flow_tuple]["n_down_packet"] += 1 if (packet.haslayer("TCP") or packet.haslayer("UDP")) and packet.dport == sport else 0
                flows[flow_tuple]["bytes"] += len(packet)
                flows[flow_tuple]["avg_packet_length"] += len(packet)
                flows[flow_tuple]["avg_payload_length"] += len(packet.payload)
                flows[flow_tuple]["pre_packet_length"] += len(packet) if flows[flow_tuple]["n_packet"] <= 10 else 0
                flows[flow_tuple]["pre_payload_length"] += len(packet) if flows[flow_tuple]["n_packet"] <= 10 else 0
                flows[flow_tuple]["max_ttl"] = max(flows[flow_tuple]["max_ttl"], packet["IP"].ttl)
                flows[flow_tuple]["min_ttl"] = min(flows[flow_tuple]["min_ttl"], packet["IP"].ttl)
                flows[flow_tuple]["avg_ttl"] += packet["IP"].ttl
                flows[flow_tuple]["max_window_size"] = max(flows[flow_tuple]["max_window_size"], packet["TCP"].window) if packet.haslayer("TCP") else -1
                flows[flow_tuple]["min_window_size"] = min(flows[flow_tuple]["min_window_size"], packet["TCP"].window) if packet.haslayer("TCP") else -1
                flows[flow_tuple]["avg_window_size"] += packet["TCP"].window if packet.haslayer("TCP") else 0
                flows[flow_tuple]["pkt_time_list"].append(packet.time)
                flows[flow_tuple]["pkt_interval_list"].append(packet.time - flows[flow_tuple]["pkt_time_list"][0])

        for flow_tuple in flows.keys():
            flows[flow_tuple]["avg_packet_length"] = round(flows[flow_tuple]["avg_packet_length"] / flows[flow_tuple]["n_packet"], 2)
            flows[flow_tuple]["avg_payload_length"] = round(flows[flow_tuple]["avg_payload_length"] / flows[flow_tuple]["n_packet"], 2)
            flows[flow_tuple]["pre_packet_length"] = round(flows[flow_tuple]["pre_packet_length"] / 10, 2)
            flows[flow_tuple]["pre_payload_length"] = round(flows[flow_tuple]["pre_payload_length"] / 10, 2)
            flows[flow_tuple]["avg_ttl"] = round(flows[flow_tuple]["avg_ttl"] / flows[flow_tuple]["n_packet"], 2)
            flows[flow_tuple]["avg_window_size"] = round(flows[flow_tuple]["avg_window_size"] / flows[flow_tuple]["n_packet"], 2)
            flows[flow_tuple]["duration"] = round(flows[flow_tuple]["pkt_time_list"][-1] - flows[flow_tuple]["pkt_time_list"][0], 5)
            flows[flow_tuple]["avg_interval"] = round(sum(flows[flow_tuple]["pkt_interval_list"]) / len(flows[flow_tuple]["pkt_interval_list"]), 5)
            flows[flow_tuple]["max_interval"] = round(np.max(flows[flow_tuple]["pkt_interval_list"]), 5)
            flows[flow_tuple]["packet_speed"] = round(flows[flow_tuple]["n_packet"] / flows[flow_tuple]["duration"] if flows[flow_tuple]["duration"] != 0 else flows[flow_tuple]["n_packet"], 2)
            flows[flow_tuple]["byte_speed"] = round(flows[flow_tuple]["bytes"] / flows[flow_tuple]["duration"] if flows[flow_tuple]["duration"] != 0 else flows[flow_tuple]["bytes"], 2)

        flow_records = []
        for flow_tuple, counts in flows.items():
            flow_records.append(FlowRecord(*flow_tuple, counts["n_packet"], counts["n_up_packet"], counts["n_down_packet"], counts["bytes"],
                 counts["avg_payload_length"], counts["avg_packet_length"], counts["pre_packet_length"], counts["pre_payload_length"], counts["max_ttl"], counts["min_ttl"],
                 counts["avg_ttl"], counts["max_window_size"], counts["min_window_size"], counts["avg_window_size"], counts["duration"], counts["avg_interval"], counts["max_interval"],
                 counts["packet_speed"], counts["byte_speed"]))

        for flow_record in flow_records:

            build_data.append("n_packet: " + str(flow_record.n_packet) +
                           ", n_up_packet: " + str(flow_record.n_up_packet) +
                           ", n_down_packet: " + str(flow_record.n_down_packet) +
                           ", bytes: " + str(flow_record.bytes) +
                           ", avg_payload_length: " + str(flow_record.avg_payload_length) +
                           ", avg_packet_length: " + str(flow_record.avg_packet_length) +
                           ", pre_packet_length: " + str(flow_record.pre_packet_length) +
                           ", pre_payload_length: " + str(flow_record.pre_payload_length) +
                           ", max_ttl: " + str(flow_record.max_ttl) +
                           ", min_ttl: " + str(flow_record.min_ttl) +
                           ", avg_ttl: " + str(flow_record.avg_ttl) +
                           ", max_window_size: " + str(flow_record.max_window_size) +
                           ", min_window_size: " + str(flow_record.min_window_size) +
                           ", avg_window_size: " + str(flow_record.avg_window_size) +
                           ", duration: " + str(flow_record.duration) +
                           ", avg_interval: " + str(flow_record.avg_interval) +
                           ", max_interval: " + str(flow_record.max_interval) +
                           ", packet_speed: " + str(flow_record.packet_speed) +
                           ", byte_speed: " + str(flow_record.byte_speed)
            )

    # Burst Features(BF) for flow-level detection
    elif flow_feature == "BF":
        packets = scapy.rdpcap(pcap_file)
        flows = defaultdict(lambda: {'bytes': [],
                                     'direction': []})

        for packet in packets:
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                else:
                    continue
                proto = packet["IP"].proto

                ip_src, sport, ip_dst, dport = normalization_src_dst(ip_src, sport, ip_dst, dport)

                flow_tuple = (ip_src, ip_dst, sport, dport, proto)
                flows[flow_tuple]["bytes"].append(len(packet) * (1 if (packet.haslayer("TCP") or packet.haslayer("UDP")) and packet.sport == sport else -1))

        for flow_tuple in flows.keys():
            flow_seq = []
            length_seq = flows[flow_tuple]["bytes"]
            burst_length = 0
            for i, packet_length in enumerate(length_seq):
                if i >= MAX_PACKET_NUMBER:
                    break
                if burst_length == 0:
                    burst_length += packet_length
                    continue
                if (burst_length > 0 and packet_length > 0) or (burst_length < 0 and burst_length < 0):
                    burst_length += packet_length
                else:
                    flow_seq.append(str(abs(burst_length)))
                    burst_length = 0
            if burst_length != 0:
                flow_seq.append(str(abs(burst_length)))

            flow_data = ", ".join(flow_seq)
            build_data.append(flow_data)

    # Raw Packet(RP) features for flow-level detection
    elif flow_feature == "RP":
        build_data = []

        packets = scapy.rdpcap(pcap_file)
        flows = defaultdict(lambda: {'packet_list': []})

        for i, packet in enumerate(packets):
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                else:
                    continue
                proto = packet["IP"].proto

                ip_src, sport, ip_dst, dport = normalization_src_dst(ip_src, sport, ip_dst, dport)

                flow_tuple = (ip_src, ip_dst, sport, dport, proto)
                flows[flow_tuple]["packet_list"].append(i)

        for flow_tuple in flows.keys():
            hex_stream = []
            for _, i in enumerate(flows[flow_tuple]["packet_list"]):
                if _ >= MAX_PACKET_NUMBER:
                    break
                packet_data = packets[i].copy()
                data = (binascii.hexlify(bytes(packet_data)))

                packet_string = data.decode()
                hex_stream.append(packet_string[HEX_PACKET_START_INDEX:min(len(packet_string), MAX_PACKET_LENGTH_IN_FLOW)])

            flow_data = "<pck>" + "<pck>".join(hex_stream)
            build_data.append(flow_data)

    # Packet Headers(PH) for flow-level detection
    elif flow_feature == "PH":
        build_data = []

        packets = scapy.rdpcap(pcap_file)
        flows = defaultdict(lambda: {'packet_list': []})

        i = 0
        for packet in packets:
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                else:
                    continue
                proto = packet["IP"].proto

                ip_src, sport, ip_dst, dport = normalization_src_dst(ip_src, sport, ip_dst, dport)

                flow_tuple = (ip_src, ip_dst, sport, dport, proto)
                flows[flow_tuple]["packet_list"].append(i)
                i += 1


        tmp_path = "PHtmp1.txt"

        # tshark 3.6.16
        # fields = ["frame.encap_type", "frame.time", "frame.offset_shift", "frame.time_epoch", "frame.time_delta",
        #           "frame.time_relative", "frame.number", "frame.len", "frame.marked", "frame.protocols", "eth.dst",
        #           "eth.dst_resolved", "eth.dst.oui", "eth.dst.oui_resolved", "eth.dst.lg", "eth.dst.ig", "eth.src",
        #           "eth.src_resolved", "eth.src.oui", "eth.src.oui_resolved", "eth.src.lg", "eth.src.ig", "eth.type",
        #           "ip.version", "ip.hdr_len", "ip.dsfield", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len", "ip.id",
        #           "ip.flags", "ip.flags.rb", "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl", "ip.proto",
        #           "ip.checksum", "ip.checksum.status", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
        #           "tcp.completeness", "tcp.len", "tcp.seq", "tcp.nxtseq", "tcp.ack", "tcp.hdr_len", "tcp.flags",
        #           "tcp.flags.res", "tcp.flags.ns", "tcp.flags.cwr", "tcp.flags.ecn", "tcp.flags.urg", "tcp.flags.ack",
        #           "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.str", "tcp.window_size",
        #           "tcp.window_size_scalefactor", "tcp.checksum", "tcp.checksum.status", "tcp.urgent_pointer", "tcp.time_relative",
        #           "tcp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.analysis.push_bytes_sent", "tcp.segment", "tcp.segment.count",
        #           "tcp.reassembled.length", "tls.record.content_type", "tls.record.version", "tls.record.length", "tcp.payload"]

        # tshark 2.6.10
        fields = ["ip.version", "ip.hdr_len", "ip.dsfield", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len",
                  "ip.id", "ip.flags", "ip.flags.rb", "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl",
                  "ip.proto", "ip.checksum", "ip.checksum.status",
                  "tcp.stream", "tcp.len", "tcp.seq", "tcp.nxtseq", "tcp.ack", "tcp.hdr_len", "tcp.flags",
                  "tcp.flags.res", "tcp.flags.ns", "tcp.flags.cwr", "tcp.flags.ecn", "tcp.flags.urg",
                  "tcp.flags.ack", "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.str",
                  "tcp.window_size", "tcp.window_size_scalefactor", "tcp.checksum", "tcp.checksum.status",
                  "tcp.urgent_pointer", "tcp.time_relative", "tcp.time_delta", "tcp.analysis.bytes_in_flight",
                  "tcp.analysis.push_bytes_sent", "tcp.segment", "tcp.segment.count", "tcp.reassembled.length", "tcp.payload",
                  "udp.srcport", "udp.dstport", "udp.length", "udp.checksum", "udp.checksum.status", "udp.stream", "data.len"]

        extract_str = " -e " + " -e ".join(fields) + " "
        cmd = "tshark -r " + pcap_file + extract_str + "-T fields -Y 'tcp or udp' > " + tmp_path
        os.system(cmd)

        packet_dataset = []
        with open(tmp_path, "r", encoding="utf-8") as fin:
            lines = fin.readlines()
        for line in lines:
            packet_data = ""
            values = line[:-1].split("\t")

            packet_data += fields[0] + ": " + values[0]
            for field, value in zip(fields[1:], values[1:]):
                if field == "tcp.flags.str":
                    value = value.encode("unicode_escape").decode("unicode_escape")
                if field == "tcp.payload":
                    value = value[:1000] if len(value) > 1000 else value
                if value == "":
                    continue
                packet_data += ", "
                packet_data += field + ": " + value

            packet_dataset.append(packet_data)

        for flow_tuple in flows.keys():
            i = flows[flow_tuple]["packet_list"][0]
            if i < len(packet_dataset):
                build_data.append(packet_dataset[i])

    return build_data
