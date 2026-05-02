import os
import json

data_path = "/mnt/data/route_data/recon-iot-2023/RP/train.jsonl"
label_path = "/mnt/data/route_data/recon-iot-2023/RP/label.jsonl"
save_path = "/mnt/data/route_data/unknown_recon/"


def build_data():
    with open(data_path, "r", encoding="utf-8") as fin:
        dataset = fin.readlines()

    with open(label_path, "r", encoding="utf-8") as fin:
        label = json.load(fin)
    for key in label.keys():
        if key == "Benign":
            continue
        new_dataset = []
        for data in dataset:
            data_dict = json.loads(data)
            if key == data_dict["messages"][1]["content"] or data_dict["messages"][1]["content"] == "Benign":
                if key == data_dict["messages"][1]["content"]:
                    data = data.replace(key, "Attack")
                new_dataset.append(data)
        with open(save_path + key + ".jsonl", "w", encoding="utf-8") as fin:
            fin.writelines(new_dataset)



if __name__ == "__main__":
    build_data()
