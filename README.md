# IPv6 Invisible Tunnel: Header-Based Covert Channel PoC

This repository contains a **Proof of Concept (PoC)** tool developed for expert-level research into IPv6 network steganography. I designed this script to demonstrate how distributed covert channels can be established by exploiting the complexity of IPv6 extension headers and the architectural design of the Flow Label field.

## 🚀 Overview

The goal of this project is to create an "Invisible Tunnel" that exfiltrates data by hiding it in plain sight. Unlike traditional exfiltration that uses the packet payload, this tool injects secret data directly into the **Protocol Headers**, making it nearly invisible to standard firewalls and signature-based Intrusion Detection Systems (IDS).

## ✨ Key Features

* **Flow Label Manipulation:** Encodes 20 bits of data per packet into the `Flow Label` field.
* **Extension Header Injection:** Utilizes the `Destination Options` header (Type 60) to hide variable-length strings within `PadN` options.
* **Traffic Camouflage:** Wraps covert data within standard `ICMPv6 Echo Request` (Ping) packets to blend in with legitimate network diagnostic traffic.
* **distributed Steganography:** Spreads the "secret" across multiple header fields to minimize the statistical signature in any single field.

## 🧠 How It Works

I designed this tool to exploit two specific "blind spots" in modern network security:

1. **The Entropy Gap:** Per **RFC 6437**, Flow Labels are intended to be pseudo-random for load balancing. Because my encrypted data is statistically identical to random noise, I can smuggle 20 bits per packet without triggering entropy-based anomalies. 


2. **The "Skip" Rule:** Standard IPv6 processing requires routers and middleboxes to ignore or "skip" unknown options in padding fields (`PadN`). I use this as a "dead drop" for secret data, knowing that most inspection engines bypass these fields to maintain high-speed throughput. 



## 🛡️ Research Context: CVE-2024-38063

This research is a direct response to the fragility of IPv6 stack processing.

* **The Link:** Recent critical vulnerabilities like **CVE-2024-38063** proved that even modern OS kernels (like the Windows TCP/IP stack) struggle with the integer arithmetic required to parse complex Extension Header chains under load. 


* **The Inversion:** While CVE-2024-38063 used malformed headers to crash systems, my tool uses **compliant but complex** header chains to evade inspection. If the kernel struggles to parse these headers for functional reasons, security engines likely lack the granular visibility to detect the data hidden within them. 



## 🛠️ Requirements

* **Python 3.x**
* **Scapy Library:** `pip install scapy`
* **OS:** Linux (Kali/Ubuntu recommended) or macOS.
* **Privileges:** Root/Sudo access is mandatory for raw socket manipulation.

## 💻 Usage

1. **Configure the script:** Update the `target_ip` and your `secret_data` in the script.
2. **Run with privileges:**
```bash
sudo python3 ip6.py

```
Run next 2 command lines in 2 different terminal
```bash
sudo python3 receiver.py

```
```bash
sudo python3 sender.py

```


3. **Verify via Wireshark:** Capture traffic and inspect the `Flow Label` (look for your hex value, e.g., `0xABCDE`) and the `Destination Options` header to see your hidden string.

## 📜 Disclaimer

This tool is for **educational and defensive research purposes only**. I created it to help network administrators and researchers identify visibility gaps in IPv6 infrastructure and "Shadow Networks." Unauthorized use of this tool against systems you do not own is strictly prohibited.

---

