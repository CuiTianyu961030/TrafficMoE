from flow_data_preprocess import build_flow_data
from packet_data_preprocess import build_packet_data
import random
import json
import os


MAX_SAMPLING_NUMBER = 5000  # 5000 # number of samples per class
TRAINING_SAMPLE_RATIO = 0.95


def split_dataset(build_data, sampling=True):
    # random.shuffle(build_data)
    if sampling is True:
        train_nb = int(min(MAX_SAMPLING_NUMBER, len(build_data)) * TRAINING_SAMPLE_RATIO)
        test_nb = int(min(MAX_SAMPLING_NUMBER, len(build_data)) * (1 - TRAINING_SAMPLE_RATIO))
    else:
        train_nb = int(len(build_data) * TRAINING_SAMPLE_RATIO)
        test_nb = int(len(build_data) * (1 - TRAINING_SAMPLE_RATIO))
    train_data = build_data[:train_nb]
    test_data = build_data[train_nb:train_nb + test_nb]

    return train_data, test_data


def write_dataset(dataset, output_path):
    # random.shuffle(dataset)
    with open(output_path, "w", encoding="utf-8") as fin:
        for data in dataset:
            json.dump(data, fin)
            fin.write("\n")
        # json.dump(dataset, fin, indent=4, separators=(',', ': '))


def write_labels(labels, output_path):
    label_dict = {}
    for i, label in enumerate(labels):
        label_dict[label] = i
    with open(output_path, "w", encoding="utf-8") as fin:
        json.dump(label_dict, fin, indent=4, separators=(',', ': '))


def build_dataset(path, file, feature):
    build_data = []
    files_path = os.path.join(path, file)
    pcaps = os.listdir(files_path)
    for pcap in pcaps:
        pcap_data = build_flow_data(os.path.join(files_path, pcap), feature)
        build_data.extend(pcap_data)

    train_data, test_data = split_dataset(build_data)

    return train_data, test_data


def save_dataset(output_path, train_dataset, test_dataset):
    write_dataset(train_dataset, os.path.join(output_path, "train.jsonl"))
    write_dataset(test_dataset, os.path.join(output_path, "test.jsonl"))


def build_text_dataset(traffic_data, label=None, feature=None):
    """Building the text datasets of traffic detection task"""

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
    output = label

    dataset = []
    for i, data in enumerate(traffic_data):
        dataset.append(
            {
                "prompt_id": i,
                "messages": [
                    {
                        "content": instruction + data,
                        "role": "user"
                    },
                    {
                        "content": output,
                        "role": "assistant"
                    }
                ]
            }
        )

    return dataset
