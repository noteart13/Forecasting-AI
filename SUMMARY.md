# 📋 Project Summary

## 🎯 Mục đích

**ICS/SCADA Network Anomaly Detection System**

Hệ thống AI phát hiện tấn công mạng trong môi trường công nghiệp (Industrial Control Systems / SCADA).

---

## ✅ Hoàn thành

### 🔧 Core Components

✅ **network_loader.py** - Đọc NetFlow/packet metadata từ CSV, Excel, JSON
✅ **anomaly_detector.py** - ML models (Isolation Forest) + rule-based detection
✅ **train.py** - Training script
✅ **detect.py** - Detection & threat analysis script
✅ **generate_network_data.py** - Sample data generator

### 🎯 Threats Detected

1. **Lateral Movement** - Kẻ tấn công di chuyển ngang trong mạng
2. **Data Exfiltration** - Đánh cắp dữ liệu ra bên ngoài  
3. **ICS Anomalies** - Bất thường trong thiết bị SCADA/PLC

### 🔌 ICS Protocols

- S7 (Port 102)
- Modbus (Port 502)
- IEC 61850 (Port 2404)
- DNP3 (Port 20000)
- EtherNet/IP (Port 44818)
- BACnet (Port 47808)
- OPC UA (Port 4840)

---

## 📁 Cấu trúc Clean

```
personal-website/
├── 📄 README.md              # Full documentation
├── 📄 QUICKSTART.md          # Quick start guide
├── 📄 requirements.txt       # Dependencies
│
├── 🐍 train.py               # Training script
├── 🐍 detect.py              # Detection script
│
├── 📂 src/
│   ├── network_loader.py     # Data loader
│   └── anomaly_detector.py   # ML models
│
├── 📂 scripts/
│   └── generate_network_data.py  # Sample data generator
│
├── 📂 data/                  # Input NetFlow data
├── 📂 output/                # Detection results
├── 📂 config/                # Config files
└── 📂 docker/                # Docker setup
```

**Chỉ 2 file .md chính:**
- `README.md` - Documentation đầy đủ
- `QUICKSTART.md` - Hướng dẫn nhanh

---

## 🚀 Usage

```bash
# 1. Generate sample data
python scripts/generate_network_data.py

# 2. Train on normal traffic
python train.py --data data/network_traffic.csv

# 3. Detect anomalies
python detect.py --data data/network_traffic.csv --detailed
```

---

## 📊 Input Format

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration
1696789123,10.0.1.100,10.0.1.10,54321,502,TCP,2048,15,1.2
```

Hỗ trợ xuất từ:
- Wireshark
- Zeek/Bro
- nfdump
- Suricata
- Custom tools

---

## 📈 Output

```
output/
├── anomaly_model.pkl           # Trained model
├── training_metadata.json      # Training info
├── anomalies_detected.csv      # All anomalies
├── lateral_movement.csv        # Lateral movement
├── data_exfiltration.csv       # Data exfiltration
└── ics_anomalies.csv          # ICS-specific
```

---

## 🔍 Detection Methods

### Machine Learning
- **Isolation Forest** - Unsupervised anomaly detection
- Features: traffic metrics, protocol info, time patterns, connection diversity

### Rule-based
- **Lateral Movement**: Multiple destinations + port scanning
- **Data Exfiltration**: Large outbound transfers to external IPs
- **ICS Anomalies**: Unexpected connections, unusual timing

---

## ⚙️ Configuration

```python
contamination=0.05  # 5% expected anomalies
```

Adjust dựa trên:
- 0.01-0.03: Conservative
- 0.05: Balanced (recommended)
- 0.10-0.15: Aggressive

---

## 🎓 Key Concepts

### Training Phase
- Input: **Clean normal traffic only**
- Model learns baseline behavior
- Output: `anomaly_model.pkl`

### Detection Phase  
- Input: **Any traffic** (normal + anomalous)
- Model flags deviations from baseline
- Output: Anomalies with scores

### Anomaly Score
- Negative values (lower = more anomalous)
- Threshold at 95th percentile for threats

---

## 🔒 Security Features

✅ Detects zero-day attacks (behavior-based)
✅ No signatures needed
✅ Real-time capable
✅ Low false positive rate (with proper training)
✅ ICS protocol-aware
✅ Interpretable results

---

## 💡 Best Practices

1. ✅ Train chỉ trên **clean normal traffic**
2. ✅ Retrain model **monthly**
3. ✅ Human review **top anomalies**
4. ✅ Integrate với **SIEM/SOC**
5. ✅ Set alerts cho **high-score anomalies**

---

## 📦 Dependencies

```
pandas - Data processing
numpy - Numerical operations
scikit-learn - ML models (Isolation Forest)
joblib - Model persistence
openpyxl - Excel support
pyyaml - Config files
```

---

**System ready for production! 🔐🚀**
