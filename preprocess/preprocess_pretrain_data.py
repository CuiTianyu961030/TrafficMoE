from flow_data_preprocess import build_flow_data
import random
from tqdm import tqdm
import json
import os

input = "/mnt/data/traffic_data/pretrain_traffic"
feature = "PAI"
output_path = "data/pretrain/"


def preprocess(input, feature, output_path):
    dataset = []

    files = os.listdir(input)
    build_data = []
    for file in tqdm(files):

        file_path = os.path.join(input, file)
        try:
            pcap_data = build_flow_data(file_path, feature)
            build_data.extend(pcap_data)
        except:
            print("error packet")

    text_data = build_text_dataset(build_data, feature=feature)
    dataset.extend(text_data)

    output_path = os.path.join(output_path, feature)
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    random.shuffle(dataset)
    with open(os.path.join(output_path, "pretrain.jsonl"), "w", encoding="utf-8") as fin:
        for data in dataset:
            json.dump(data, fin)
            fin.write("\n")


def build_text_dataset(traffic_data, label=None, feature=None):

    features = {
        "PLS": "Packet Length Sequences",
        "PDS": "Packet Direction Sequences",
        "PAI": "Packet Arrival Interval",
        "FS": "Flow Statistics",
        "BF": "Burst Features",
        "PH": "Packet Headers",
        "RP": "Raw Packets"
    }

    instruction = "Given the following " + features[feature] + ". Please determine which category the feature belongs to: "

    dataset = []
    for i, data in enumerate(traffic_data):
        dataset.append(
            {
                "text": instruction + data
            }
        )

    return dataset


def main():

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    preprocess(input, feature, output_path)



if __name__ == "__main__":
    main()

