from flowcontainer.extractor import extract
import binascii
import scapy.all as scapy
from scapy.all import load_layer
import re
import os


# load_layer("tls")

MAX_PACKET_LENGTH = 1024
HEX_PACKET_START_INDEX = 0  # 0 # 48 # 76


def build_packet_data(pcap_file, packet_feature="PH"):
    build_data = []

    # Raw Packet(RP) features for packet-level detection
    if packet_feature == "RP":

        packets = scapy.rdpcap(pcap_file)

        for packet in packets:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))

            packet_string = data.decode()

            # byte_list = re.findall(".{2}", packet_string)
            # packet_string = " ".join(byte_list)

            build_data.append(packet_string[HEX_PACKET_START_INDEX:min(len(packet_string), MAX_PACKET_LENGTH)])

    # Packet Headers(PH) features for packet-level detection
    elif packet_feature == "PH":
        tmp_path = "tmp1.txt"

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
        fields = ["ip.version", "ip.hdr_len", "ip.dsfield", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len", "ip.id",
                  "ip.flags", "ip.flags.rb", "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl", "ip.proto",
                  "ip.checksum", "ip.checksum.status", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
                  "tcp.len", "tcp.seq", "tcp.nxtseq", "tcp.ack", "tcp.hdr_len", "tcp.flags",
                  "tcp.flags.res", "tcp.flags.ns", "tcp.flags.cwr", "tcp.flags.ecn", "tcp.flags.urg", "tcp.flags.ack",
                  "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.str",
                  "tcp.window_size", "tcp.window_size_scalefactor", "tcp.checksum", "tcp.checksum.status", "tcp.urgent_pointer",
                  "tcp.time_relative", "tcp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.analysis.push_bytes_sent", "tcp.segment",
                  "tcp.segment.count", "tcp.reassembled.length", "tcp.payload", "udp.srcport", "udp.dstport", "udp.length",
                  "udp.checksum", "udp.checksum.status", "udp.stream", "data.len"]
        # "eth.dst", "eth.dst_resolved", "eth.src", "eth.src_resolved",
        # "frame.encap_type", "frame.time", "frame.offset_shift", "frame.time_epoch", "frame.time_delta",
        #                   "frame.time_relative", "frame.number", "frame.len", "frame.marked", "frame.protocols", "eth.type",

        extract_str = " -e " + " -e ".join(fields) + " "
        cmd = "tshark -r " + pcap_file + extract_str + "-T fields -Y 'tcp or udp' > " + tmp_path
        os.system(cmd)

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

            build_data.append(packet_data)

    return build_data



