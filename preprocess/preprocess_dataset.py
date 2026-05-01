import random

from preprocess_utils import (
    write_labels,
    build_dataset,
    save_dataset,
    build_text_dataset
)
from tqdm import tqdm
import argparse
import os


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, help="raw dataset path", required=True)
    parser.add_argument("--feature", type=str, help="expert features", required=True, choices=["PLS", "PDS", "PAI", "FS", "BF", "PH", "RP"])
    parser.add_argument("--output_path", type=str, help="output dataset path", required=True)

    args = parser.parse_args()
    return args


def preprocess(args):
    train_dataset = []
    test_dataset = []
    labels = []

    files = os.listdir(args.input)
    labels.extend(files)

    for file in tqdm(files):
        train_data, test_data = build_dataset(args.input, file, args.feature)

        train_text_data = build_text_dataset(train_data, label=file, feature=args.feature)
        test_text_data = build_text_dataset(test_data, label=file, feature=args.feature)

        train_dataset.extend(train_text_data)
        test_dataset.extend(test_text_data)

    output_path = os.path.join(args.output_path, args.feature)
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    random.shuffle(train_dataset)
    save_dataset(output_path, train_dataset, test_dataset)
    write_labels(labels, os.path.join(output_path, "label.jsonl"))



def main():
    args = get_args()

    if not os.path.exists(args.output_path):
        os.makedirs(args.output_path)

    preprocess(args)



if __name__ == "__main__":
    main()
