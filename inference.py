import csv
import os.path
import tqdm
import torch
import numpy as np
import json
import random
import time
import sys
# sys.path.append(code_path)  # append the path where mistral-inference was cloned

# from model.transformer import Transformer
from mistral_inference.transformer import Transformer
from mistral_inference.generate import generate
from mistral_common.tokens.tokenizers.mistral import MistralTokenizer
from mistral_common.protocol.instruct.messages import UserMessage
from mistral_common.protocol.instruct.request import ChatCompletionRequest

from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score,  confusion_matrix, classification_report

os.environ["CUDA_VISIBLE_DEVICES"] = "0, 1, 2, 3, 4"

dataset_name = "mirai-iot-2023"
n_expert = 3
is_sample = True


def test_set_to_prompt(test_set):

    test_prompts = []
    target_responses = []

    for test_data in test_set:
        test_prompts.append(json.loads(test_data)["messages"][0]["content"])
        target_responses.append(json.loads(test_data)["messages"][1]["content"])

    return test_prompts, target_responses


def evaluation(predict_responses, target_responses, label_dict):
    preds = []
    labels = []
    for predict_response, target_response in zip(predict_responses, target_responses):
        if "。" in predict_response and "。" in target_response:
            predict_response = predict_response[:-1]
            target_response = target_response[:-1]
        if ' ' not in predict_response:
            if predict_response not in label_dict.keys():
                preds.append(len(label_dict.keys()))
                print("generated mistake labels:", predict_response)
            else:
                preds.append(label_dict[predict_response])
            labels.append(label_dict[target_response])
        else:
            if predict_response.split(" ")[-1] not in label_dict.keys():
                preds.append(len(label_dict.keys()))
                print("generated mistake labels:", predict_response.split(" ")[-1])
            else:
                preds.append(label_dict[predict_response.split(" ")[-1]])
            labels.append(label_dict[target_response.split(" ")[-1]])

    print("acc:", accuracy_score(labels, preds))
    print("precision:", precision_score(labels, preds, average='weighted'))
    print("recall:", recall_score(labels, preds, average='weighted'))
    print("f1:", f1_score(labels, preds, average='weighted'))
    print("confusion matrix:\n", confusion_matrix(labels, preds))
    print("classification report:\n", classification_report(labels, preds))


def load_model(path):
    lora_path = "/mnt/data/run_dir/" + path + "/checkpoints/checkpoint_000200/consolidated/lora.safetensors"

    model = Transformer.from_folder("/mnt/data/models/mistral/7B/")  # change to extracted model dir
    model.load_lora(lora_path)

    return model


def route_result(moe_result, sorted_perplexity):
    pred = {}
    for i in range(n_expert):
        expert_i = sorted_perplexity[i][0]
        predict = moe_result[int(expert_i)]["predict"]
        prob = moe_result[int(expert_i)]["probability"]
        print("Expert %s: %s, Prob: %s" % (expert_i, predict, prob))
        if predict not in pred.keys():
            pred[predict] = prob
        else:
            pred[predict] += prob
    sorted_items = sorted(pred.items(), key=lambda x: x[1], reverse=True)
    return sorted_items[0][0]


def model_classifier(prompts, targets, label_dict):
    tokenizer = MistralTokenizer.from_file(
        "/mnt/data/models/mistral/7B/tokenizer.model.v3")  # change to extracted tokenizer file

    predict_responses = []
    target_responses = targets[0]
    for j in tqdm.tqdm(range(len(prompts[0]))):
        moe_result = {}
        perplexity = {}

        for i, expert_name in enumerate(["PLS", "PDS", "PAI", "FS", "BF", "PH", "RP"]):

            moe_result[i] = {"predict": "", "probability": 0}

            # if expert_name == "PLS" or expert_name == "PDS" or expert_name == "PAI":
            #     continue

            # expert = load_model(os.path.join(dataset_name, "route/" + expert_name)) # ustc-tfc-2016 / iscx-vpn-2016

            time_start = time.time()
            expert = load_model(os.path.join(dataset_name, expert_name + "_route")) # others
            time_end = time.time()
            print(f"Loading Model Time: {time_end - time_start} s")
            completion_request = ChatCompletionRequest(
                messages=[UserMessage(content=prompts[i][j])])
            tokens = tokenizer.encode_chat_completion(completion_request).tokens
            out_tokens, _ = generate([tokens], expert, max_tokens=64, temperature=0.0,
                                     eos_id=tokenizer.instruct_tokenizer.tokenizer.eos_id)
            perplexity[str(i)] = np.exp(-np.mean(_[0][-len(out_tokens[0]):]))

            result = tokenizer.instruct_tokenizer.tokenizer.decode(out_tokens[0])
            prob = np.round(np.exp(np.sum(_[0][-len(out_tokens[0]):]))*100, 2)

            # prob = 1

            moe_result[i] = {"predict": result, "probability": prob}
            # print("Expert %s: %s, Prob: %s" % (i, result, prob))

        sorted_perplexity = sorted(perplexity.items(), key=lambda x: x[1])

        final_result = route_result(moe_result, sorted_perplexity)
        predict_responses.append(final_result)

        print("Predict: ", final_result)
        print("Label: ", target_responses[j])

    evaluation(predict_responses, target_responses, label_dict)


def model_classifier_test():
    path = "/mnt/data/route_data/" + dataset_name
    test_files = [os.path.join(path, os.path.join(i, "test.jsonl")) for i in ["PLS", "PDS", "PAI", "FS", "BF", "PH", "RP"]]
    label_file = os.path.join(path, "PLS/label.jsonl")

    time_start = time.time()
    with open(label_file, "r", encoding="utf-8") as fin:
        label_dict = json.load(fin)

    prompts = []
    targets = []
    for test_file in test_files:
        with open(test_file, "r", encoding="utf-8") as fin:
            test_set = fin.readlines()

        test_prompts, target_responses = test_set_to_prompt(test_set)
        prompts.append(test_prompts)
        targets.append(target_responses)

    if is_sample is True:
        prompts, targets = sample_test(prompts, targets)

    time_end = time.time()
    print(f"Loading Dataset Time: {time_end - time_start} s")

    model_classifier(prompts, targets, label_dict)


def sample_test(prompts, targets):
    index = random.sample(range(len(prompts[0])), 100)
    sample_prompts = []
    sample_targets = []
    for prompt, target in zip(prompts, targets):
        sample_prompt = [prompt[i] for i in index]
        sample_target = [target[i] for i in index]
        sample_prompts.append(sample_prompt)
        sample_targets.append(sample_target)

    return sample_prompts, sample_targets


if __name__ == "__main__":

    model_classifier_test()