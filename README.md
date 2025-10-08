# ICS/SCADA Network Anomaly Detection System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![ML](https://img.shields.io/badge/ML-Isolation%20Forest-orange.svg)](https://scikit-learn.org/)

**AI-powered threat detection system for Industrial Control Systems and SCADA networks.**

Detects sophisticated attacks including **Lateral Movement**, **Data Exfiltration**, and **ICS-specific anomalies** using unsupervised machine learning and rule-based detection.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Usage](#usage)
- [Detection Methodology](#detection-methodology)
- [Configuration](#configuration)
- [Output & Results](#output--results)
- [Troubleshooting](#troubleshooting)

---

## Features

- ✅ **Unsupervised ML Detection** - Isolation Forest algorithm for zero-day threats
- ✅ **Multi-Protocol Support** - Modbus, DNP3, S7, OPC UA, EtherNet/IP, IEC 61850
- ✅ **PCAP Analysis** - Direct integration with Wireshark capture files
- ✅ **Real-time Capable** - Low-latency detection pipeline
- ✅ **Multi-format Input** - CSV, Excel, JSON, PCAP/PCAPNG
- ✅ **Comprehensive Reporting** - Automated threat analysis reports
- ✅ **Production Ready** - Docker support, SIEM integration

---

## Quick Start

### Installation

```bash
# Clone repository
git clone <repository-url>
cd forecasting-ai

# Install dependencies
pip install -r requirements.txt

# Install PCAP support (optional)
pip install scapy pyshark
```

### Run Demo

```bash
# Automated end-to-end demo
python demo.py

# Analyze PCAP from Wireshark
python demo_pcap.py --pcap capture.pcap --detailed
```

---

## Architecture

### System Design

```
┌─────────────────┐
│  Data Sources   │
│ CSV/PCAP/Excel  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Network Loader  │
│  Feature Eng.   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ML Engine       │
│ Isolation Forest│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Threat Analyzer │
│ Rule-based Det. │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Reports &     │
│     Alerts      │
└─────────────────┘
```

### Components

| Component | Description | Technology |
|-----------|-------------|------------|
| **Data Loader** | Multi-format ingestion | Pandas, Scapy, PyShark |
| **Feature Engine** | Extract 23+ network features | NumPy, Pandas |
| **ML Model** | Unsupervised anomaly detection | Scikit-learn (Isolation Forest) |
| **Threat Analyzer** | Rule-based classification | Custom algorithms |
| **Reporter** | Generate analysis reports | Text/JSON output |

---

## Usage

### 1. Automated Demo (Recommended)

```bash
python demo.py
```

**Pipeline:** Data Generation → Model Training → Threat Detection → Report Generation

### 2. PCAP Analysis

```bash
python demo_pcap.py --pcap capture.pcap --detailed
```

**Parameters:**
- `--pcap` - Path to .pcap/.pcapng file
- `--detailed` - Enable comprehensive threat analysis
- `--model` - Custom model path (optional)
- `--output` - Output directory (default: `output/pcap_analysis`)

### 3. Manual Workflow

```bash
# Step 1: Generate training data
python scripts/generate_network_data.py

# Step 2: Train model on clean traffic
python train.py --data data/normal_traffic.csv --contamination 0.05

# Step 3: Detect anomalies
python detect.py --data data/test_traffic.csv --detailed
```

### 4. Data Format

**Supported formats:** CSV, Excel, JSON, PCAP, PCAPNG

**Required schema:**
```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration
1696789123,10.0.1.100,10.0.1.10,54321,502,TCP,2048,15,1.2
```

**Field specifications:**
- `timestamp` - Unix timestamp or ISO datetime
- `src_ip`, `dst_ip` - IPv4/IPv6 addresses
- `src_port`, `dst_port` - Port numbers (1-65535)
- `protocol` - TCP/UDP/ICMP/ICS protocols
- `bytes` - Total bytes transferred
- `packets` - Packet count
- `duration` - Flow duration (seconds)

---

## Output & Results

### Output Files

```
output/
├── anomaly_model.pkl          # Trained ML model
├── training_metadata.json     # Training configuration & metrics
├── anomalies_detected.csv     # All detected anomalies
├── lateral_movement.csv       # Lateral movement events
├── data_exfiltration.csv      # Data exfiltration attempts
├── ics_anomalies.csv          # ICS-specific anomalies
└── attack_summary.txt         # Comprehensive analysis report
```

### Risk Scoring

| Score Range | Risk Level | Action Required |
|-------------|------------|-----------------|
| < -0.5 | 🔴 **High** | Immediate investigation |
| -0.5 to -0.3 | 🟡 **Medium** | Review within 24h |
| > -0.3 | 🟢 **Low** | Monitor |

### Supported ICS Protocols

| Port  | Protocol     | Application | Standard |
|-------|--------------|-------------|----------|
| 102   | Siemens S7   | PLC communication | Proprietary |
| 502   | Modbus TCP   | Industrial automation | Open |
| 2404  | IEC 61850    | Substation automation | IEC |
| 20000 | DNP3         | SCADA systems | IEEE 1815 |
| 44818 | EtherNet/IP  | Industrial Ethernet | ODVA |
| 47808 | BACnet       | Building automation | ASHRAE |
| 4840  | OPC UA       | Industrial IoT | OPC Foundation |

---

## Detection Methodology

### Machine Learning Approach

**Algorithm:** Isolation Forest (Unsupervised Learning)

- **Training Phase:** Learn normal traffic baseline from clean data
- **Detection Phase:** Flag deviations from learned patterns
- **Advantages:** Zero-day detection, no signature updates required
- **Features:** 23+ engineered features (traffic metrics, protocols, timing, network patterns)

### Rule-based Detection

#### 1. Lateral Movement Detection

**Indicators:**
- Port scanning patterns (multiple ports targeted)
- Host scanning behavior (multiple destinations)
- Rapid connection attempts to diverse targets
- Abnormal service enumeration

**Output Fields:**
- `lateral_score` - Risk score (0-100)
- `is_port_scan` - Boolean flag
- `is_host_scan` - Boolean flag
- `is_high_risk` - Critical pattern detected

#### 2. Data Exfiltration Detection

**Indicators:**
- Abnormally large outbound transfers
- Connections to external/untrusted IPs
- Off-hours activity (night/weekend)
- Suspicious protocols (FTP, HTTP POST)

**Output Fields:**
- `exfil_score` - Risk score (0-100)
- `mb_transferred` - Data volume (MB)
- `is_large_transfer` - Transfer > 10MB
- `is_unusual_time` - Off-hours flag

#### 3. ICS-Specific Anomaly Detection

**Critical Patterns:**
- 🚨 ICS devices communicating with external networks
- 🚨 Non-ICS devices accessing ICS protocols
- ⚠️ ICS traffic during maintenance windows
- ⚠️ Sudden traffic volume changes (±50%)

**Output Fields:**
- `type` - Anomaly classification
- `severity` - Risk level (low/medium/high/critical)
- `count` - Number of occurrences
- `description` - Detailed explanation

---

## Configuration

### Model Training

```bash
python train.py \
  --data data/normal_traffic.csv \
  --output output/model.pkl \
  --contamination 0.05
```

**Contamination Parameter Tuning:**

| Value | Profile | Use Case | False Positive Rate |
|-------|---------|----------|---------------------|
| 0.01-0.03 | Conservative | Production (high precision) | Very Low |
| 0.05 | Balanced ⭐ | General purpose | Low |
| 0.10-0.15 | Aggressive | Threat hunting | Medium-High |

### Detection Configuration

```bash
python detect.py \
  --data data/test_traffic.csv \
  --model output/model.pkl \
  --detailed \
  --output output/results.csv
```

**Command-line Arguments:**
- `--data` - Input traffic data path
- `--model` - Trained model path
- `--detailed` - Enable comprehensive threat analysis
- `--output` - Output file path

---

## Project Structure

```
forecasting-ai/
│
├── README.md                      # Documentation
├── requirements.txt               # Python dependencies
│
├── Core Scripts
│   ├── demo.py                    # Automated demo pipeline
│   ├── demo_pcap.py               # PCAP analysis demo
│   ├── train.py                   # Model training
│   └── detect.py                  # Anomaly detection
│
├── src/                          # Source code
│   ├── network_loader.py         # Data ingestion & preprocessing
│   └── anomaly_detector.py       # ML models & threat detection
│
├── scripts/                      # Utility scripts
│   └── generate_network_data.py  # Sample data generator
│
├── data/                         # Input datasets
├── output/                       # Detection results
└── docker/                       # Docker configuration
```

---

## Troubleshooting

### Common Issues

#### No Anomalies Detected

**Symptom:** Detection returns 0 anomalies

**Solutions:**
```bash
# Increase sensitivity
python train.py --contamination 0.10

# Verify input data format
python -c "import pandas as pd; print(pd.read_csv('data/traffic.csv').columns)"

# Check model training
python train.py --data data/normal_traffic.csv --verbose
```

#### High False Positive Rate

**Symptom:** Too many benign flows flagged

**Solutions:**
```bash
# Decrease sensitivity
python train.py --contamination 0.01

# Retrain with more diverse normal traffic
# Ensure training data covers all normal patterns
```

#### PCAP Processing Errors

**Issue:** Cannot read .pcap files

**Solutions:**
```bash
# Install PCAP dependencies
pip install scapy pyshark

# Verify file format
file capture.pcap  # Should show: "tcpdump capture file"

# Try smaller files (< 100MB)
# Check file permissions
```

#### Import Errors

```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Verify Python version (3.8+)
python --version
```

---

## Example Output

### Detection Results

```
════════════════════════════════════════════════════════════
🔍 ICS/SCADA ANOMALY DETECTION RESULTS
════════════════════════════════════════════════════════════

📊 GENERAL ANOMALIES: 47 detected (0.47%)

🎯 DETAILED THREAT ANALYSIS
────────────────────────────────────────────────────────────
🚨 Lateral Movement: 3 suspicious activities
   └─ 192.168.1.99 → multiple destinations (score: 12.5)

🚨 Data Exfiltration: 2 suspicious transfers
   └─ 192.168.1.15 → external IPs (21.6 MB transferred)

🚨 ICS Anomalies: 5 types detected
   └─ CRITICAL: ICS device external communication (10 events)

🔴 TOP 10 HIGH-RISK ANOMALIES:
1. 10.0.1.100 → 203.45.67.89:443 | 5.2MB | score: -0.95
2. 192.168.1.15 → 8.8.8.8:53 | 3.1MB | score: -0.87
...
```

---

## Best Practices

### Training Phase

| Practice | Description | Impact |
|----------|-------------|--------|
| ✅ **Clean Training Data** | Use only verified normal traffic | High accuracy |
| ✅ **Diverse Sampling** | Include all protocols, devices, time periods | Reduced false positives |
| ✅ **Minimum Dataset Size** | ≥1000 flows recommended | Statistical significance |
| ✅ **Regular Retraining** | Monthly or after network changes | Maintain accuracy |

### Detection Phase

- **Manual Review:** Validate top 10 anomalies before action
- **Tuning:** Adjust contamination based on false positive rate
- **Correlation:** Cross-reference with SIEM/IDS logs
- **Prioritization:** Critical ICS anomalies → High scores → Medium scores

### Production Deployment

- **Integration:** Connect to SIEM (Splunk, ELK, QRadar)
- **Alerting:** Real-time notifications for critical events
- **Automation:** Scheduled detection (cron/systemd)
- **Documentation:** Maintain incident response playbook

---

## License

MIT License - See [LICENSE](LICENSE) file for details

---

## Contributing

Contributions welcome! Please follow:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open Pull Request

---

## Contact & Support

- **Issues:** [GitHub Issues](https://github.com/your-repo/issues)
- **Documentation:** [Wiki](https://github.com/your-repo/wiki)
- **Email:** security@yourcompany.com

---

**🔐 Secure your ICS/SCADA infrastructure with AI-powered threat detection**

```bash
python demo.py  # Get started in 3 minutes
```
