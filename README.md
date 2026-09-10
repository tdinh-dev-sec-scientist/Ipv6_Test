# The Invisible Tunnel: Exploiting Protocol Complexity for Distributed Steganography in IPv6 Extension Headers and Flow Labels

![Research Status](https://img.shields.io/badge/Research-Posters_at_the_Capitol_2026-gold) ![University](https://img.shields.io/badge/Institution-Austin_Peay_State_University-red) ![Language](https://img.shields.io/badge/Language-Python_3.x-blue)

This repository contains the research and proof-of-concept (PoC) framework for **"The Invisible Tunnel,"** a project officially selected for the **2026 Student Posters at the Capitol** program at the Tennessee State Capitol.

## Research Paper
You can read the preliminary draft of our paper here:
👉 [Download/Read the Paper PDF](https://www.overleaf.com/read/fhtvydkvphmw#a8f36a)

---
## Attack, Detection, and Limits

Research code for a structurally RFC-8200-compliant IPv6 Destination-Options
covert channel and an evaluation of behavioral detection against it, including an
adaptive (marginal-matching) adversary. Benign traffic is real IPv6 from the
MAWI archive; the detection task is evaluated leak-free.


## Repository layout

| File | Role |
|------|------|
| `generate_normal_ipv6.py` | Synthetic benign generator (per-flow-constant Flow Labels, Session IDs).  |
| `sender.py` / `receiver.py` / `ip6.py` | The covert C2 channel (live demo) and its packet construction. `sender.py --generate` also writes reproducible covert CSVs. |
| `gen_covert.py` | Covert-base generator: `--prng {mt,csprng}` and a marginal-matching adaptive mode (`--mimic-mode marginal --mimic-bits k`). |
| `parse_mawi_pcap.py` | Feature extraction from any IPv6 PCAP (5-tuple IAT; PadN in Hop-by-Hop **and** Destination Options; PadN length vs. non-zero content; drop accounting). |
| `gen_final.py` | Main detection pipeline: 6 features, leak-free 60/20/20 malicious split, 5 models (AE, One-Class SVM, LOF, Random Forest, RBF-SVM), ablation, McNemar. |
| `experiment3_deconfounded.py` | Adaptive experiment reporting **per-covert-packet AUC** and **capacity** separately (de-confounds the aggregate curve). |
| `ocsvm_diagnostic.py` | Scaler × ν × γ sweep diagnosing One-Class SVM sensitivity. |
| `d3_replay.py` | Exact stateless RFC-8200 "D3" defense (flags non-zero PadN content), replayed over PCAPs; reports detection and false positives. |
| `d3_ipv6_padn.rules` | Suricata companion rule (a coarser approximation of D3). |



## Data

Benign traffic is the MAWI Working Group Traffic Archive
(<http://mawi.wide.ad.jp/mawi/>), samplepoint-F trace **202604301400** in our runs;
~21% of that trace is IPv6, yielding the 1,000,000-packet benign corpus. MAWI has
its own terms — download it yourself rather than expecting it here. Covert traffic
is synthesized locally (below).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # then: pip freeze > requirements.txt to pin
```

## Reproducing the pipeline

```bash
# 1. Benign features from a MAWI PCAP  ->  normal_mawi.csv
python3 parse_mawi_pcap.py --pcap 202604301400.pcap.gz --out normal_mawi.csv --max-packets 1000000

# 2. Covert bases
python3 sender.py   --generate --out malicious.csv            --sessions 1200 --padn-mode on    # naive PadN channel
python3 gen_covert.py           --out malicious_flowlabel.csv  --sessions 1200                    # Flow-Label channel (PadN off)

# 3. Naive-channel detection (leak-free split, AE on [0,1] scale)
python3 gen_final.py --normal normal_mawi.csv --malicious malicious.csv

# 4. De-confounded adaptive result (per-covert-packet AUC + capacity)
python3 experiment3_deconfounded.py --normal normal_mawi.csv --malicious malicious_flowlabel.csv \
    --seeds 5 --max_fit 50000 --out exp3_deconf

# 5. Generator comparison (MT vs CSPRNG) and marginal-matching adversary
python3 gen_covert.py --out cov_csprng.csv --sessions 1200 --prng csprng
python3 gen_covert.py --out cov_marg_4.csv --sessions 1200 --mimic-mode marginal --mimic-bits 4 --normal normal_mawi.csv
python3 experiment3_deconfounded.py --normal normal_mawi.csv --malicious cov_csprng.csv --seeds 5 --max_fit 50000 --out exp_csprng
python3 experiment3_deconfounded.py --normal normal_mawi.csv --malicious cov_marg_4.csv --seeds 5 --max_fit 50000 --out exp_marg_4

# 6. D3 defense replayed over PCAPs
python3 d3_replay.py --pcap malicious_raw.pcap --label covert
python3 d3_replay.py --pcap 202604301400.pcap.gz --label benign --max-packets 1000000
```

## What the experiments show:

- **Naive PadN channel is trivially separable.** Real MAWI benign carries non-zero
  PadN content in 0.0000% of 1e6 packets, so a one-line RFC-8200 rule (`d3_replay.py`)
  matches the supervised models; ML adds nothing here.
- **Adaptive channel, de-confounded.** Aggregate AUC falls with mimicry, but
  *per-covert-packet* detectability stays flat (~0.92) — the fall reflects
  vanishing covert capacity, not per-packet evasion.
- **Generator-agnostic.** Mersenne Twister vs. a keyed CSPRNG give per-covert AUC
  within ~0.007; the signal is the marginal mismatch with benign, not the generator.
- **Marginal-matching adversary.** Drawing Flow Labels to match the benign marginal
  collapses per-covert AUC to ~0.53–0.56, but emitted entropy saturates near ~6
  bits/packet — a hard capacity ceiling set by benign entropy.

Numbers above come from runs on the MAWI corpus; rerun the commands to reproduce
them in your environment.

## License / ethics

Covert-channel code is for defensive research and was tested on an isolated
testbed. Add a license file (e.g., MIT) before publishing.
