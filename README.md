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

### 1. Flow Preprocess

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



### Benchmark Datasets

TrafficMoE is evaluated on the following public benchmark datasets:

| Dataset | Description |
|---------|-------------|
| CIC-IOT datasets | Real-world IoT device traffic and various novel attacks |
| CIC-IDS datasets | Common intrusion detection benchmark with many classic attacks  |
| USTC-TFC datasets | Encrypted and plain-text malware traffic to build application-specific attacks |
| ISCX-Botnet datasets  | Various botnet families to conduct attacks with C2 channels |
| DAPT datasets | Sophisticated multi-stage attacks to form ad- vanced persistent threats |

Preprocessed versions of all datasets used in our experiments are provided in the repository.

### Evasion Attacks



### Unknown Attacks


## Repository Structure

```
TrafficMoE/
├── checkpoints/          # Pre-trained expert model weights
├── data/                 # Sample data and preprocessed datasets
├── figures/              # Paper figures
├── models/
│   ├── experts/          # Seven expert network implementations
│   ├── router.py         # Perplexity-guided routing module
│   └── aggregator.py     # Perplexity-weighted prediction aggregation
├── pipeline/
│   ├── flow_recorder.py  # DPDK-based flow recording module
│   └── async_pipeline.py # Asynchronous inference pipeline
├── scripts/              # Training and evaluation scripts
├── evaluate.py           # Evaluation entry point
├── detect.py             # Inference entry point
├── train.py              # Training entry point
└── requirements.txt
```

---
