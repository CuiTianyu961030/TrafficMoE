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
# Clone the repository
git clone https://github.com/***/TrafficMoE.git
cd TrafficMoE

# Create a virtual environment
conda create -n trafficmoe python=3.10
conda activate trafficmoe

# Install dependencies
pip install -r requirements.txt
```

## Quick Start


---

## Datasets

TrafficMoE is evaluated on the following public benchmark datasets:

| Dataset | Description |
|---------|-------------|
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Common intrusion detection benchmark |
| [CIC-IOT](https://www.unb.ca/cic/datasets/iotdataset-2022.html) | IoT traffic with attack scenarios |
| [USTC-TFC](https://github.com/yungshenglu/USTC-TFC2016) | Encrypted traffic classification |
| [ISCX-Botnet](https://www.unb.ca/cic/datasets/botnet.html) | Botnet traffic detection |
| [DAPT2020](https://github.com/DAPT2020) | Advanced persistent threat dataset |

Preprocessed versions of all datasets used in our experiments are provided in the repository.


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
