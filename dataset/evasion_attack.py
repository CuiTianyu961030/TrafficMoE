import copy
import os
from scapy.all import rdpcap, PcapWriter, IP, TCP, Packet
import numpy as np
import random
from tqdm import tqdm

evasion_attack = "wtf_pad"

dataset_path = "/mnt/data/traffic_data/Mirai-IOT-split/splitcap/"
output_path = "/mnt/data/traffic_data/evasion_attack/raw_mirai/"
wtf_pad_path = "/mnt/data/traffic_data/evasion_attack/wtf-pad_mirai/"
front_path = "/mnt/data/traffic_data/evasion_attack/front_mirai/"
dfd_path = "/mnt/data/traffic_data/evasion_attack/dfd_mirai/"
text_attack_path = "/mnt/data/traffic_data/evasion_attack/text_attack_mirai/"


def bulid_dataset():
    files = os.listdir(dataset_path)
    for file in files:
        os.makedirs(os.path.join(output_path, file))
        pcaps = os.listdir(os.path.join(dataset_path, file))
        for i, pcap in enumerate(pcaps):
            if i >= 5000:
                break
            os.system(f"cp {os.path.join(os.path.join(dataset_path, file), pcap)} {os.path.join(os.path.join(output_path, file), pcap)}")


def sample_interarrival(n):

    return np.random.exponential(scale=0.05, size=n)


def wtf_pad_pcap(in_pcap, out_pcap):
    pkts = rdpcap(in_pcap)
    writer = PcapWriter(out_pcap, sync=True)

    flows = {}
    for pkt in pkts:
        if IP not in pkt: continue
        key = (pkt[IP].src, pkt[IP].dst,
               pkt.sport if TCP in pkt else pkt[IP].proto,
               pkt.dport if TCP in pkt else 0,
               pkt.proto)
        flows.setdefault(key, []).append(pkt)

    for key, flow in flows.items():
        flow.sort(key=lambda p: p.time)
        pads = list(sample_interarrival(len(flow)*3))
        pad_idx = 0
        next_pad_time = flow[0].time + pads[pad_idx]

        for pkt in flow:
            writer.write(pkt)

            while next_pad_time < pkt.time:
                fake = pkt.copy()
                fake.time = next_pad_time
                if TCP in fake:
                    fake[TCP].flags = "A"
                    fake[TCP].seq = 0
                    fake[TCP].chksum = None
                fake.remove_payload()
                writer.write(fake)

                pad_idx += 1
                if pad_idx >= len(pads): break
                next_pad_time += pads[pad_idx]

            if pad_idx >= len(pads)-1:
                pads = list(sample_interarrival(len(flow)*3))
                pad_idx = 0
                next_pad_time = pkt.time + pads[pad_idx]

    writer.close()
    print(f"Wrote padded pcap to {out_pcap}")


def front_process_flow(pkts, front_window=0.05, jitter_scale=0.02, reorder_window=3):

    times = np.array([int(p.time) for p in pkts])
    t0 = times[0]

    n_front = max(min(len(pkts), int(len(pkts)*0.2)), 1)  
    front_times = np.linspace(t0, t0 + front_window, n_front, endpoint=False)
    new_times = list(front_times)

    for i in range(n_front, len(pkts)):
        delta = times[i] - times[i-1]
        jitter = np.random.normal(scale=jitter_scale)
        new_times.append(new_times[-1] + max(delta + jitter, 0.0))
    new_times = np.array(new_times)

    for i in range(len(new_times)):
        j_max = min(len(new_times), i + reorder_window)

        if j_max - i > 1:
            j = np.random.randint(i, j_max)
            new_times[i], new_times[j] = new_times[j], new_times[i]

    out = []
    for pkt, t in zip(pkts, new_times):
        p2 = copy.copy(pkt)
        p2.time = float(t)
        out.append(p2)

    out.sort(key=lambda p: p.time)
    return out


def pcap_front(in_file, out_file):
    all_pkts = rdpcap(in_file)
    writer = PcapWriter(out_file, sync=True)

    flows = {}
    for p in all_pkts:
        if not hasattr(p, 'time') or not hasattr(p, 'payload'): continue
        tpl = (p.src, p.dst,
               getattr(p, p.lastlayer().name).sport if hasattr(p.lastlayer().name, 'sport') else 0,
               getattr(p, p.lastlayer().name).dport if hasattr(p.lastlayer().name, 'dport') else 0,
               p.proto if hasattr(p, 'proto') else 0)
        flows.setdefault(tpl, []).append(p)

    for flow_pkts in flows.values():
        flow_pkts.sort(key=lambda p: p.time)
        new_flow = front_process_flow(flow_pkts,
                                      front_window=0.05,
                                      jitter_scale=0.02,
                                      reorder_window=4)
        for p in new_flow:
            writer.write(p)

    writer.close()
    print(f"FRONT processed pcap written to {out_file}")


def dfd_process_pcap(input_pcap: str, output_pcap: str, perturbation_rate: float):

    packets = rdpcap(input_pcap)
    packets = sorted(packets, key=lambda pkt: pkt.time)

    writer = PcapWriter(output_pcap, sync=True)

    last_burst_len = 0         
    burst_count = 0            
    ack_cache = []             

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            writer.write(pkt)
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]
        is_outgoing = True if tcp.dport else False  
        is_incoming = not is_outgoing

        if is_outgoing:

            burst_count += 1

            if burst_count == 2 and last_burst_len > 0:
                num_injections = int(round(perturbation_rate * last_burst_len))

                for i in range(num_injections):
                    if not ack_cache:
                        break

                    ack_pkt = ack_cache[i % len(ack_cache)]
                    fake = copy.copy(ack_pkt)
                    fake.time = pkt.time  
                    writer.write(fake)


            if tcp.flags == 'A' and len(pkt.payload) == 0:
                ack_cache.append(pkt.copy())

                if len(ack_cache) > 100:
                    ack_cache.pop(0)

            writer.write(pkt)

        else:
            if burst_count > 0:
                last_burst_len = burst_count
                burst_count = 0
            writer.write(pkt)

    writer.close()
    print(f"[DFD] Done: {output_pcap}")


def build_bigram_vocab(pkts):

    vocab = set()
    for pkt in pkts:
        if "Raw" in pkt:
            hexstr = bytes(pkt["Raw"].load).hex()

            for i in range(0, len(hexstr) - 3, 4):
                token = hexstr[i:i+4]
                vocab.add(token)
    return list(vocab)


def obfuscate_payload(pkt, vocab, rate):

    raw = bytes(pkt["Raw"].load)
    hexstr = raw.hex()
    new_tokens = []

    for i in range(0, len(hexstr), 4):
        token = hexstr[i:i+4]
        if len(token) < 4:

            new_tokens.append(token)
        else:
            if random.random() < rate:

                repl = random.choice(vocab)

                if repl == token and len(vocab) > 1:
                    repl = random.choice([t for t in vocab if t != token])
                new_tokens.append(repl)
            else:
                new_tokens.append(token)
    new_hex = ''.join(new_tokens)
    return bytes.fromhex(new_hex)


def obfuscate_pcap(input_pcap, output_pcap, rate):

    pkts = rdpcap(input_pcap)

    vocab = build_bigram_vocab(pkts)
    print(f"[+] Built bigram vocab of size {len(vocab)}")

    pw = PcapWriter(output_pcap, sync=True)
    for pkt in pkts:

        if "Raw" in pkt and IP in pkt and TCP in pkt:

            newpkt = pkt.copy()

            newpkt["Raw"].load = obfuscate_payload(newpkt, vocab, rate)

            del newpkt[IP].chksum
            del newpkt[TCP].chksum
            pw.write(newpkt)
        else:
            pw.write(pkt)
    pw.close()
    print(f"[+] Obfuscated pcap written to {output_pcap}")


if __name__ == "__main__":
    # bulid_dataset()
    files = os.listdir(output_path)
    for file in files:
        if evasion_attack  == "wtf_pad":
            os.makedirs(os.path.join(wtf_pad_path, file))
        elif evasion_attack  == "front":
            os.makedirs(os.path.join(front_path, file))
        elif evasion_attack  == "dfd":
            os.makedirs(os.path.join(dfd_path, file))
        elif evasion_attack  == "text_attack":
            os.makedirs(os.path.join(text_attack_path, file))
        pcaps = os.listdir(os.path.join(output_path, file))
        for pcap in tqdm(pcaps):
            input_pcap = os.path.join(os.path.join(output_path, file), pcap)
            if evasion_attack  == "wtf_pad":
                output_pcap = os.path.join(os.path.join(wtf_pad_path, file), pcap)
                wtf_pad_pcap(input_pcap, output_pcap)
            elif evasion_attack  == "front":
                output_pcap = os.path.join(os.path.join(front_path, file), pcap)
                pcap_front(input_pcap, output_pcap)
            elif evasion_attack  == "dfd":
                output_pcap = os.path.join(os.path.join(dfd_path, file), pcap)
                dfd_process_pcap(input_pcap, output_pcap, 0.2)
            elif evasion_attack  == "text_attack":
                output_pcap = os.path.join(os.path.join(text_attack_path, file), pcap)
                obfuscate_pcap(input_pcap, output_pcap, 0.2)

    # wtf_pad_pcap("input.pcap", "output_wtfpad.pcap")
    # pcap_front("input.pcap", "output_front.pcap")
    # dfd_process_pcap(input_pcap, output_pcap, rate)
    # obfuscate_pcap(args.inp, args.out, args.rate)
