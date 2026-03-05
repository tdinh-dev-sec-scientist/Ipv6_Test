# The Invisible Tunnel: Exploiting Protocol Complexity for Distributed Steganography in IPv6 Extension Headers and Flow Labels

![Research Status](https://img.shields.io/badge/Research-Posters_at_the_Capitol_2026-gold) ![University](https://img.shields.io/badge/Institution-Austin_Peay_State_University-red) ![Language](https://img.shields.io/badge/Language-Python_3.x-blue)

[cite_start]This repository contains the research and proof-of-concept (PoC) framework for **"The Invisible Tunnel,"** a project officially selected for the **2026 Student Posters at the Capitol** program at the Tennessee State Capitol[cite: 1, 15].

---

## 📌 Executive Summary
[cite_start]As the global transition from IPv4 to IPv6 accelerates to address address exhaustion and routing efficiency [cite: 7][cite_start], it introduces structural complexities that many enterprise security systems are not yet designed to handle[cite: 8]. [cite_start]This research investigates a critical vulnerability within the IPv6 Extension Header (EH) mechanism[cite: 9].

* [cite_start]**The Problem**: Parsing deeply nested EH chains imposes significant computational overhead, leading many commercial firewalls to skip EH inspection entirely, creating a blind spot[cite: 9].
* [cite_start]**The Attack**: By embedding XOR-encrypted command-and-control (C2) data into PadN padding options and synchronizing transmission through pseudo-random Flow Label manipulation, an attacker can operate a shadow network invisible to conventional intrusion detection systems (IDS)[cite: 11].
* [cite_start]**The Defense**: We propose a behavioral defense using a **Deep Learning Autoencoder** capable of detecting the covert channel purely through anomalous reconstruction error[cite: 14].



---

## 🛠️ Technical Implementation

### 1. Offensive Framework (Python & Scapy)
[cite_start]The offensive framework was developed using the **Scapy** library to provide low-level access to IPv6 header fields not typically exposed by standard OS networking stacks[cite: 17].

* [cite_start]**Protocol Camouflage**: Covert packets mimic standard TLS/HTTPS handshake steps by initiating as TCP SYN requests to destination port 443[cite: 19].
* [cite_start]**EH Manipulation**: The `Next Header` field is changed from 6 (TCP) to 60 (Destination Options), shifting the protocol identifier chain and blinding packet sniffers that rely on Next Header matching[cite: 22].
* [cite_start]**Steganographic Embedding**: C2 payloads are XOR-encrypted and injected into the **PadN** option bytes of a Destination Options Extension Header[cite: 20].
* [cite_start]**Flow Label Authentication**: A shared Pseudo-Random Number Generator (PRNG) is used to write values into the 20-bit Flow Label field, providing robust authentication without a dedicated handshake[cite: 23, 24, 25].

### 2. Defensive Model (Deep Learning)
[cite_start]The defensive strategy utilizes a deep neural network Autoencoder trained exclusively on benign baseline traffic[cite: 27, 32].



[Image of Autoencoder neural network architecture]


* [cite_start]**Feature Extraction**: The pipeline isolates the 20-bit Flow Label (normalized to $[0, 1]$ over $1,048,575$) and the PadN option length[cite: 31].
* [cite_start]**Anomaly Detection**: During inference, the model computes the **Mean Squared Error (MSE)** for each packet[cite: 34].
    $$MSE = \frac{1}{n} \sum_{i=1}^{n} (Y_i - \hat{Y}_i)^2$$
* [cite_start]**Thresholding**: Covert packets—characterized by mathematically unnatural PRNG-distributed Flow Labels—produce anomalously high reconstruction errors that exceed a statistically derived detection threshold[cite: 35].

---

## 📊 Experimental Results
[cite_start]The framework demonstrates the operational risks highlighted in **CVE-2024-38063**, confirming that EH-targeted attacks are viable against modern enterprise infrastructure[cite: 15, 74].

| Detection Method | Outcome | Root Cause |
| :--- | :--- | :--- |
| **Standard BPF Filtering** | [cite_start]**Failed** [cite: 40] | [cite_start]Next Header shift (6 to 60) rendered payload invisible[cite: 41, 42]. |
| **Deep Learning AE** | [cite_start]**Successful** [cite: 43] | [cite_start]Identified unnatural PRNG Flow Label variance and non-zero PadN lengths[cite: 46]. |

---

## 🚀 Quick Start: Running the Simulation

### 1. Generate Benign Traffic (Baseline)
[cite_start]Capture organic IPv6 traffic to establish a behavioral baseline for the Autoencoder[cite: 28, 29].
```bash
python scripts/capture_traffic.py --output data/benign.pcap --duration 600

2. Execute the Attack

Start the listener and send a command via the steganographic tunnel.
Bash

# Start the listener (Implant)
python offensive/implant.py --secret "shared_secret"

# Send a command from the C2 Server
python offensive/c2_server.py --target <IMPLANT_IP> --cmd "whoami" --secret "shared_secret"

3. Train & Detect

Train the model on benign data and run the detection engine.
Bash

# Train the Autoencoder
python defensive/train.py --input data/benign.pcap --model models/ae_detector.h5

# Run real-time detection
python defensive/detect.py --model models/ae_detector.h5 --interface eth0

🤝 Acknowledgements

Sincere gratitude to Dr. James Church for his continuous mentorship and technical guidance. Special thanks to the Austin Peay State University Department of Computer Science & IT and the Office of Student Research and Innovation (OSRI) for their funding and support.
📜 References

    Deering, S., & Hinden, R. (2017). RFC 8200: IPv6 Specification. IETF.

    Biondi, P. (2024). Scapy: Interactive packet manipulation program.

    MSRC (2024). CVE-2024-38063: Windows TCP/IP Remote Code Execution Vulnerability.
