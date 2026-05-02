# TrafficMoE

> **Perplexity-Guided Dynamic Expert Routing for Feature-Agnostic Traffic Detection**


## Overview

This repository contains the official implementation of **TrafficMoE**, **a perplexity-guided Mixture-of-Experts (MoE) framework for feature-agnostic network intrusion detection**. Unlike existing ML-based NIDS that rely on fixed, task-specific feature spaces and degrade significantly under evasion attacks and zero-day threats, TrafficMoE dynamically routes each network flow to the most suitable experts based on model perplexity, enabling robust detection across diverse real-world traffic conditions.

<p align="center">
  <img src="images/overview.png" width="1000" alt="TrafficMoE Overview"/>
</p>


## Key Features

- 🔀 **Perplexity-Guided Routing** — Model perplexity as a universal signal to route experts by capturing subtle deviations between real-world attacks and training knowledge for each flow.
- 🧠 **Mixture-of-Experts Architecture** — Dynamically activates a subset of seven specialized experts spanning varying traffic detection views extracted from the general high-dimensional feature space.
- 🛡️ **Feature-Agnostic Detection** — Robust against diverse existing attacks, evasion attacks, and previously unseen zero-day threats through adaptively selecting the most suitable feature subspaces for traffic detection.

---

## Installation

Please clone the repo and install the required environment by runing the following commands.

```bash
# Create a virtual environment
conda create -n trafficmoe python=3.10
conda activate trafficmoe

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### 1. Dataset Preprocessing

Load the raw traffic dataset with the .pcap format to extract preprocessed datasets for model training.

- **Pre-train Dataset Preprocessing**:
```bash
python preprocess/preprocess_pretarin_data.py

```
- **Fine-tune Dataset Preprocessing**:
```bash
python preprocess/preprocess_dataset.py --input /Your/Raw/Dataset/Path/CIC-IOT-2023/DDoS/ --feature PLS --output_path route_data/ddos-iot-2023
```

- **Input**: specify the raw traffic dataset and the type of `feature` for mixtures of expert learning.
- **Output**: the preprocessed datasets for training an expert in TrafficMoE.

You can also use the bash script `scripts/preprocessing.sh` to preprocess datasets for all seven experts.

### 2. Training

Config the training parameters in `config/7B.yaml` and train TrafficMoE by using `torchrun`.

```bash
python -m utils.validate_data --train_yaml example/7B.yaml
torchrun --nproc-per-node 8 --master_port $RANDOM -m train example/7B.yaml
```

- **Input**: the preprocessed datasets and the base model specified in the config file.
- **Output**: the model weights of TrafficMoE saved in the `run_dir`.

You can also use the bash script `scripts/train.sh` to train all experts in TrafficMoE directly.

### 3. Inference & Evaluation

Run the inference script to realize dynamic flow routing on benchmark datasets and evalute the overall performance.

```bash
python inference.py
```
- **Input**: the benchmark dataset name and the model path of TrafficMoE.
- **Output**: the prediction results of flows and the overall performance with Acc, precision, recall and F1 metric.

---

## Datasets

### Pre-train Datasets

TrafficMoE is pre-trained by using 420 million large-scale unlabeled traffic flows from the open-sourced WIDE MAWI datasets.

| Dataset | Description |
|---------|-------------|
| WIDE MAWI datasets | Real-world backbone network traffic datasets built by the WIDE MAWI project |

We provide the examples of the pre-train data in `dataset/pretrain_data`.

### Benchmark Datasets

TrafficMoE is evaluated on the following public benchmark datasets:

| Dataset | Description |
|---------|-------------|
| CIC-IOT datasets | Real-world IoT device traffic and various novel attacks |
| CIC-IDS datasets | Common intrusion detection benchmark with many classic attacks  |
| USTC-TFC datasets | Encrypted and plain-text malware traffic to build application-specific attacks |
| ISCX-Botnet datasets  | Various botnet families to conduct attacks with C2 channels |
| DAPT datasets | Sophisticated multi-stage attacks to form advanced persistent threats |

Preprocessed versions of all datasets used in our experiments are provided in `dataset/route_data`.

### Evasion Attacks

We provide 4 evasion methods to reshape the attack traffic mentioned above, constructing 240 evasion attacks for evaluation. The evasion methods including:

| Evasion Attacks | Description |
|---------|-------------|
| FRONT | Attackers inject dummy packets at the front of flows and randomizes the number and distribution of dummy packets |
| WTF-PAD | Attackers fill up sparse gaps in flows with dummy packets based on the distribution of inter-packet arrival time |
| DFD | Attackers inject dummy packets within every outgoing burst to break the inherent burst patterns preserved in traffic |
| TextAttack | Attackers utilize the half-byte level of disturbance on raw packet data to generate adversarial samples against pre-trained models |

The script of building evasion attacks is `dataset/evasion_attack.py`. Using the following command to generate evasion attack traffic: 
```bash
python dataset/evasion_attack.py
```
- **Input**: load the existing attack datatsets with .pcap format and specify the type of the evasion method in `evasion_attack`.
- **Output**: output the evasion traffic of the input datasets by using the specified evasion method.

### Unknown Attacks

We provide the script of building unknown attack detection settings in `dataset/unknown_attack.py`.
```bash
python dataset/unknown_attack.py
```
- **Input**: the preprocessed datasets with different types of attacks.
- **Output**: the train and test datasets, each containing one different type of attack for evaluation under unknown attack settings.


## Repository Structure

```bash
├── config  # Configs of hyper-parameters for training
├── dataset  # Preprocessed datasets for training TrafficMoE
│   ├── pretrain_data  # Examples of preprocessed pre-training datasets
│   └── route_data  # Benchmark datasets
├── finetune  # Dataloader and loss calculating
│   ├── __init__.py
│   ├── args.py
│   ├── checkpointing.py
│   ├── data
│   │   ├── __init__.py
│   │   ├── args.py
│   │   ├── data_loader.py
│   │   ├── dataset.py
│   │   ├── exceptions.py
│   │   └── tokenize.py
│   ├── distributed.py
│   ├── eval.py
│   ├── loss.py
│   ├── mixed_precision.py
│   ├── monitoring
│   │   ├── __init__.py
│   │   ├── metrics_logger.py
│   │   └── utils.py
│   ├── utils.py
│   └── wrapped_model.py
├── images
├── model  # Main architecture of the model
│   ├── __init__.py
│   ├── args.py
│   ├── lora.py
│   ├── moe.py
│   ├── rope.py
│   └── transformer.py
├── preprocess  # Scripts for preprocessing raw traffic datasets
│   ├── flow_data_preprocess.py
│   ├── packet_data_preprocess.py
│   ├── preprocess_dataset.py
│   ├── preprocess_pretrain_data.py
│   └── preprocess_utils.py
├── README.md
├── requirements.txt
├── train.py  # Scripts for model training 
├── inference.py  # Scripts for flow routing with model perplexity
└── utils
```

---
