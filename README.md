# 🔒 ICS/SCADA Network Anomaly Detection

AI-powered system phát hiện tấn công mạng trong môi trường công nghiệp (Industrial Control Systems / SCADA).

---

## 🎯 Mục đích

Phát hiện 3 loại mối đe dọa chính:

1. **Lateral Movement** - Kẻ tấn công di chuyển ngang trong mạng
2. **Data Exfiltration** - Đánh cắp và chuyển dữ liệu ra ngoài
3. **ICS Anomalies** - Bất thường trong thiết bị SCADA/PLC

---

## 🚀 Quick Start (3 phút)

```bash
# 1. Cài đặt
pip install -r requirements.txt

# 2. Chạy demo tự động
python demo.py
```

Demo sẽ:
- ✅ Generate 10,000 network flows (normal + anomalies)
- ✅ Train Isolation Forest model
- ✅ Detect threats và classify
- ✅ Generate reports trong `output/`

---

## 📊 Input Data Format

Hệ thống đọc NetFlow/packet metadata từ **CSV, Excel, JSON, PCAP**:

### PCAP Files (Wireshark)
```bash
# Phân tích trực tiếp file .pcap từ Wireshark
python demo_pcap.py --pcap capture.pcap --detailed
```

### CSV/Excel/JSON Format
```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration
1696789123,10.0.1.100,10.0.1.10,54321,502,TCP,2048,15,1.2
```

**Required columns:**
- `timestamp`: Unix timestamp hoặc datetime
- `src_ip`, `dst_ip`: IP addresses
- `src_port`, `dst_port`: Port numbers
- `protocol`: TCP/UDP/ICMP
- `bytes`: Total bytes transferred
- `packets`: Packet count
- `duration`: Flow duration (seconds)

**Export từ:** Wireshark (.pcap), Zeek, nfdump, Suricata

---

## 🔧 Sử dụng

### Option 1: Demo tự động (Recommended)

```bash
python demo.py
```

### Option 2: PCAP Analysis (Wireshark files)

```bash
# Phân tích file .pcap trực tiếp từ Wireshark
python demo_pcap.py --pcap your_capture.pcap --detailed

# Hoặc với dữ liệu mẫu
python scripts/generate_pcap_data.py  # Tạo dữ liệu mẫu
python demo_pcap.py --pcap data/sample_pcap_data.csv --detailed
```

### Option 3: Manual steps

```bash
# Generate sample data
python scripts/generate_network_data.py

# Train model trên normal traffic
python train.py --data data/network_traffic.csv

# Detect anomalies
python detect.py --data data/network_traffic.csv --detailed
```

### Option 4: Docker

```bash
cd docker
docker-compose up demo
```

---

## 📈 Output Files

```
output/
├── anomaly_model.pkl          # Trained model
├── training_metadata.json     # Training info
├── anomalies_detected.csv     # All anomalies
├── lateral_movement.csv       # Lateral movement events
├── data_exfiltration.csv      # Data exfiltration attempts
└── ics_anomalies.csv         # ICS-specific anomalies
```

**Anomaly Score:**
- **< -0.5**: 🔴 High risk (investigate now)
- **-0.5 to -0.3**: 🟡 Medium risk
- **> -0.3**: 🟢 Low risk

---

## 🔌 ICS Protocols

System nhận diện các protocol công nghiệp:

| Port  | Protocol     | Use Case |
|-------|--------------|----------|
| 102   | Siemens S7   | PLC communication |
| 502   | Modbus TCP   | Industrial automation |
| 2404  | IEC 61850    | Substation automation |
| 20000 | DNP3         | SCADA |
| 44818 | EtherNet/IP  | Industrial Ethernet |
| 47808 | BACnet       | Building automation |
| 4840  | OPC UA       | Industrial IoT |

---

## 🔍 Detection Methods

### Machine Learning
- **Isolation Forest** (unsupervised)
- Learns normal baseline
- Detects deviations automatically
- No signatures needed

### Rule-based
- **Lateral Movement**: Multiple destinations + port scanning
- **Data Exfiltration**: Large outbound + external IPs + unusual time
- **ICS Anomalies**: Unexpected connections + traffic spikes

---

## ⚙️ Configuration

### Training

```bash
python train.py \
  --data data/normal_traffic.csv \
  --output output/model.pkl \
  --contamination 0.05  # Expected % anomalies (default 5%)
```

**Contamination tuning:**
- `0.01-0.03`: Conservative (low false positives)
- `0.05`: Balanced ✅ (recommended)
- `0.10-0.15`: Aggressive (catch more)

### Detection

```bash
python detect.py \
  --data data/test_traffic.csv \
  --model output/model.pkl \
  --detailed  # Enable threat analysis
```

---

## 🐳 Docker

### Quick demo
```bash
cd docker
docker-compose up demo
```

### Separate steps
```bash
docker-compose up train   # Train model
docker-compose up detect  # Detect anomalies
```

### Custom data
Edit `docker-compose.yml`:
```yaml
command: [
  "python", "train.py",
  "--data", "data/your_traffic.csv"
]
```

---

## 📁 Project Structure

```
forecasting-ai/
├── README.md                  # This file
├── demo.py                    # Auto demo script
├── demo_pcap.py               # PCAP analysis demo
├── train.py                   # Training script
├── detect.py                  # Detection script
├── requirements.txt           # Dependencies
│
├── src/
│   ├── network_loader.py      # Load NetFlow/PCAP data
│   └── anomaly_detector.py    # ML models + detection
│
├── scripts/
│   ├── generate_network_data.py  # Sample data generator
│   └── generate_pcap_data.py     # PCAP sample data
│
├── data/                      # Input data
├── output/                    # Results
├── config/                    # Config files
└── docker/                    # Docker setup
```

---

## 🎓 How It Works

### Training Phase
1. Load clean normal traffic
2. Extract features (traffic metrics, protocols, time, network patterns)
3. Train Isolation Forest model
4. Save model to `output/anomaly_model.pkl`

### Detection Phase
1. Load trained model
2. Process test traffic
3. Calculate anomaly scores
4. Flag deviations from baseline
5. Classify threats (Lateral Movement, Data Exfil, ICS)
6. Generate reports

### Features Used
- Traffic: bytes, packets, duration, bytes_per_packet, packets_per_second
- Protocol: TCP/UDP, ICS protocols
- Time: hour, day_of_week, night/weekend
- Network: unique_destinations, connection diversity

---

## 💡 Best Practices

### Training
- ✅ Use **clean normal traffic only** (no attacks)
- ✅ Include diverse traffic (all protocols, devices, times)
- ✅ Minimum 1000+ flows
- ✅ Retrain monthly

### Detection
- ✅ Review top anomalies manually
- ✅ Tune contamination based on false positive rate
- ✅ Cross-reference with SIEM/IDS
- ✅ Prioritize high-score anomalies

### Production
- ✅ Integrate with SIEM (Splunk, ELK)
- ✅ Set up alerts for high-risk events
- ✅ Schedule periodic detection
- ✅ Maintain incident response playbook

---

## 🧪 Testing

```bash
# Generate test data
python scripts/generate_network_data.py

# Run demo
python demo.py

# Should detect ~500 anomalies (5%)
```

---

## 🛠️ Troubleshooting

**No anomalies detected:**
```bash
python train.py --contamination 0.10  # Increase to 10%
```

**Too many false positives:**
```bash
python train.py --contamination 0.01  # Decrease to 1%
```

**Import errors:**
```bash
pip install -r requirements.txt
```

**File not found:**
```bash
python scripts/generate_network_data.py
```

---

## 📦 Dependencies

```
pandas==2.1.4          # Data processing
numpy==1.26.2          # Numerical operations
scikit-learn==1.3.2    # ML (Isolation Forest)
joblib==1.3.2          # Model persistence
openpyxl==3.1.2        # Excel support
matplotlib==3.8.2      # Visualization
seaborn==0.13.0        # Plots
pyyaml==6.0.1          # Config
scapy==2.5.0           # PCAP parsing
dpkt==1.9.8            # Packet analysis
pyshark==0.6           # Wireshark integration
```

---

## 🔗 Integration

### With SIEM

```python
from src.anomaly_detector import ICSAnomalyDetector

detector = ICSAnomalyDetector()
detector.load_model('output/anomaly_model.pkl')
results = detector.predict(your_netflow_data)

# Send to SIEM
high_risk = results[results['anomaly_score'] < -0.5]
send_to_siem(high_risk)
```

### Continuous Monitoring

```bash
# Cron job (every hour)
0 * * * * cd /app && python detect.py --data /data/latest.csv --detailed
```

---

## 🚨 Example Results

```
🔍 GENERAL ANOMALIES: 47 detected (0.47%)

🎯 DETAILED THREAT ANALYSIS
─────────────────────────────────────────────────
🚨 Lateral Movement: 3 suspicious activities
🚨 Data Exfiltration: 2 suspicious transfers
🚨 ICS Anomalies: 5 anomaly types

🔴 TOP 10 ANOMALIES:
timestamp            src_ip        dst_ip       bytes    score
2025-10-08 09:15:23  10.0.1.100   203.45.67.89  5000000  -0.95
```

---

## 📞 Next Steps

1. **Test**: Run `python demo.py`
2. **Use your data**: Export NetFlow, train, detect
3. **Integrate**: Connect to SIEM
4. **Deploy**: Use Docker for production
5. **Monitor**: Set up alerts

---

## 🏆 Features

✅ Zero-day detection (behavior-based)
✅ ICS protocol-aware
✅ No signatures needed
✅ Low false positive rate
✅ Real-time capable
✅ Production-ready (Docker)
✅ Interpretable results

---

**🔐 Protect your ICS/SCADA network with AI! 🚀**

Run: `python demo.py`
