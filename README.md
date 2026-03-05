# The Invisible Tunnel: Exploiting Protocol Complexity for Distributed Steganography in IPv6 Extension Headers and Flow Labels

![Research Status](https://img.shields.io/badge/Research-Posters_at_the_Capitol_2026-gold) ![University](https://img.shields.io/badge/Institution-Austin_Peay_State_University-red) ![Language](https://img.shields.io/badge/Language-Python_3.x-blue)

This repository contains the research and proof-of-concept (PoC) framework for **"The Invisible Tunnel,"** a project officially selected for the **2026 Student Posters at the Capitol** program at the Tennessee State Capitol.

---

## 📌 Executive Summary
As the global transition from IPv4 to IPv6 accelerates to address address exhaustion and routing efficiency, it introduces structural complexities that many enterprise security systems are not yet designed to handle. This research investigates a critical vulnerability within the IPv6 Extension Header (EH) mechanism.

**The Problem**: Parsing deeply nested EH chains imposes significant computational overhead, leading many commercial firewalls to skip EH inspection entirely, creating a blind spot[cite: 9].
**The Attack**: By embedding XOR-encrypted command-and-control (C2) data into PadN padding options and synchronizing transmission through pseudo-random Flow Label manipulation, an attacker can operate a shadow network invisible to conventional intrusion detection systems (IDS)[cite: 11].
**The Defense**: We propose a behavioral defense using a 
**Deep Learning Autoencoder** capthat detects the covert channel solely through anomalous reconstruction errors

---

## 🛠️ Technical Implementation

### 1. Offensive Framework (Python & Scapy)
The offensive framework was developed using the **Scapy** library to provide low-level access to IPv6 header fields not typically exposed by standard OS networking stacks.

**Protocol Camouflage**: Covert packets mimic standard TLS/HTTPS handshake steps by initiating as TCP SYN requests to destination port 443.
**EH Manipulation**: The `Next Header` field is changed from 6 (TCP) to 60 (Destination Options), shifting the protocol identifier chain and blinding packet sniffers that rely on Next Header matching.
**Steganographic Embedding**: C2 payloads are XOR-encrypted and injected into the **PadN** option bytes of a Destination Options Extension Header.
**Flow Label Authentication**: A shared Pseudo-Random Number Generator (PRNG) is used to write values into the 20-bit Flow Label field, providing robust authentication without a dedicated handshake.

### 2. Defensive Model (Deep Learning)
The defensive strategy utilizes a deep neural network Autoencoder trained exclusively on benign baseline traffic.




**Feature Extraction**: The pipeline isolates the 20-bit Flow Label (normalized to $[0, 1]$ over $1,048,575$) and the PadN option length.
**Anomaly Detection**: During inference, the model computes the **Mean Squared Error (MSE)** for each packet.
    $$MSE = \frac{1}{n} \sum_{i=1}^{n} (Y_i - \hat{Y}_i)^2$$
**Thresholding**: Covert packets—characterized by mathematically unnatural PRNG-distributed Flow Labels—produce anomalously high reconstruction errors that exceed a statistically derived detection threshold.

---

## 📊 Experimental Results
The framework demonstrates the operational risks highlighted in **CVE-2024-38063**, confirming that EH-targeted attacks are viable against modern enterprise infrastructure.

| Detection Method | Outcome | Root Cause |
| :--- | :--- | :--- |
| **Standard BPF Filtering** | **Failed**  | Next Header shift (6 to 60) rendered payload invisible. |
| **Deep Learning AE** | **Successful** | Identified unnatural PRNG Flow Label variance and non-zero PadN lengths. |

---

## 🚀 Quick Start: Running the Simulation

### 1. Generate Benign Traffic (Baseline)
Capture organic IPv6 traffic to establish a behavioral baseline for the Autoencoder.
```bash
python scripts/capture_traffic.py --output data/benign.pcap --duration 600

2. Execute the Attack

Start the listener and send a command via the steganographic tunnel.
Bash
# Open 3 terminals
# Terminal 1
# Start tcpdump to catch normal packets:
sudo tcpdump -i lo0 -w normal.pcap

# Then ctrl-C

# Start tcp dumpt to catch malicious packets:
sudo tcpdump -i lo0 -w malicious.pcap

#Terminal 2 
# Start the listener 
sudo python3 receiver_padn.py

#Terminal 3
# Send a command from the C2 Server
sudo python3 sender_padn.py

# Then run:
sudo python3 pcap_extractor.py
3. Train & Detect

Train the model on benign data and run the detection engine.
Bash

# Train the Autoencoder
python3 generate results.py

# Run real-time detection


🤝 Acknowledgements

Sincere gratitude to Dr. James Church for his continuous mentorship and technical guidance. Special thanks to the Austin Peay State University Department of Computer Science & IT and the Office of Student Research and Innovation (OSRI) for their funding and support.
📜 References

    Deering, S., & Hinden, R. (2017). RFC 8200: IPv6 Specification. IETF.

    Biondi, P. (2024). Scapy: Interactive packet manipulation program.

    MSRC (2024). CVE-2024-38063: Windows TCP/IP Remote Code Execution Vulnerability.
