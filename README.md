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

```bash
python preprocess/preprocess_dataset.py --input /Your/Raw/Dataset/Path/CIC-IOT-2023/DDoS/ --feature PLS --output_path route_data/ddos-iot-2023
```

### 2. Training

```bash

```

### 3. Inference & Evaluation

```bash
```

---

## Datasets

### Pre-train Datasets

TrafficMoE is pre-trained by using 420 million large-scale unlabeled traffic flows from the open-sourced WIDE MAWI datasets.

| Dataset | Description |
|---------|-------------|
| WIDE MAWI datasets | Real-world backbone network traffic datasets built by the WIDE MAWI project |

We provide the examples of the pretrain data in `dataset/pretrain_data`.

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
| TextAttack | attackers utilize the half-byte level of disturbance on raw packet data to generate adversarial samples against pre-trained models |

The scripts of building evasion attacks are shown in `dataset/evasion_attack.py`. Using the following command to generate evasion attack traffic: 
```bash
python evasion_attack.py
```

### Unknown Attacks


## Repository Structure

```bash
├── config
│   └── 7B.yaml
├── dataset
│   ├── pretrain_data
│   └── route_data
├── finetune
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
├── model
│   ├── __init__.py
│   ├── args.py
│   ├── lora.py
│   ├── moe.py
│   ├── rope.py
│   └── transformer.py
├── preprocess
│   ├── flow_data_preprocess.py
│   ├── packet_data_preprocess.py
│   ├── preprocess_dataset.py
│   ├── preprocess_pretrain_data.py
│   └── preprocess_utils.py
├── README.md
├── requirements.txt
├── train.py
├── inference.py
└── utils
```

---
