# TrafficMoE

> **Perplexity-Guided Dynamic Expert Routing for Feature-Agnostic Traffic Detection**

---

## Overview

This repository contains the official implementation of **TrafficMoE**, a perplexity-guided Mixture-of-Experts (MoE) framework for feature-agnostic network intrusion detection. Unlike existing ML-based NIDS that rely on fixed, task-specific feature spaces and degrade significantly under evasion attacks and zero-day threats, TrafficMoE dynamically routes each network flow to the most suitable experts based on model perplexity, enabling robust detection across diverse real-world traffic conditions.

<p align="center">
  <img src="images/overview.png" width="800" alt="TrafficMoE Overview"/>
</p>

---

## Key Features

- 🔀 **Perplexity-Guided Routing** — Uses model perplexity as a universal signal to dynamically select the most suitable experts for each flow
- 🧠 **Mixture-of-Experts Architecture** — Seven specialized experts spanning raw traffic, sequence-feature, and statistical-feature views
- 🛡️ **Feature-Agnostic Detection** — Robust against evasion attacks and previously unseen zero-day threats without relying on fixed feature spaces

---

