# 🔒 ICS/SCADA Network Anomaly Detection

AI-powered system để phát hiện bất thường trong mạng công nghiệp (Industrial Control Systems / SCADA).

## 🎯 Phát hiện các mối đe dọa

✅ **Lateral Movement** - Kẻ tấn công di chuyển ngang trong mạng
✅ **Data Exfiltration** - Đánh cắp và chuyển dữ liệu ra ngoài  
✅ **ICS Anomalies** - Hành vi bất thường trong thiết bị SCADA/PLC

## 🚀 Quick Start

```bash
# 1. Cài đặt
pip install -r requirements.txt

# 2. Tạo dữ liệu mẫu
python scripts/generate_network_data.py

# 3. Train model trên normal traffic
python train.py --data data/network_traffic.csv

# 4. Phát hiện anomalies
python detect.py --data data/network_traffic.csv --detailed
```

## 📊 Định dạng Input Data

Hệ thống đọc NetFlow / packet metadata từ CSV, Excel, JSON:

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration
1696789123,10.0.1.100,10.0.1.10,54321,502,TCP,2048,15,1.2
```

**Columns:**
- `timestamp`: Unix timestamp hoặc datetime
- `src_ip`, `dst_ip`: IP addresses
- `src_port`, `dst_port`: Port numbers
- `protocol`: TCP/UDP/ICMP
- `bytes`: Total bytes transferred
- `packets`: Packet count
- `duration`: Connection duration (seconds)

## 🔧 Workflow

### 1. Training (Normal Traffic)

```bash
python train.py --data data/normal_traffic.csv --output output/model.pkl
```

Train model trên dữ liệu **normal traffic** để học baseline behavior.

### 2. Detection (Test Traffic)

```bash
# Basic detection
python detect.py --data data/test_traffic.csv

# Detailed threat analysis
python detect.py --data data/test_traffic.csv --detailed
```

Output files:
- `output/anomalies_detected.csv` - All anomalies
- `output/lateral_movement.csv` - Lateral movement events
- `output/data_exfiltration.csv` - Data exfil attempts
- `output/ics_anomalies.csv` - ICS-specific issues

## 📁 Cấu trúc

```
personal-website/
├── src/
│   ├── network_loader.py      # Đọc NetFlow data
│   └── anomaly_detector.py    # ML models
├── scripts/
│   └── generate_network_data.py  # Tạo sample data
├── data/                       # Input data
├── output/                     # Detection results
├── train.py                    # Training script
├── detect.py                   # Detection script
└── requirements.txt
```

## 🎯 ICS Protocols được hỗ trợ

- **Port 102**: Siemens S7
- **Port 502**: Modbus TCP
- **Port 2404**: IEC 61850 MMS
- **Port 20000**: DNP3
- **Port 44818**: EtherNet/IP
- **Port 47808**: BACnet
- **Port 4840**: OPC UA

## 🔍 Detection Methods

### 1. Lateral Movement
- Một source IP kết nối với nhiều destinations khác nhau
- Port scanning behavior
- Failed connection attempts

### 2. Data Exfiltration
- Large outbound data transfers
- Connections từ ICS network ra external IPs
- Unusual upload patterns
- Transfers vào giờ không bình thường

### 3. ICS Anomalies
- ICS devices kết nối unexpected hosts
- ICS traffic vào giờ bất thường (đêm/cuối tuần)
- Sudden changes trong traffic patterns
- Non-ICS devices accessing ICS ports

## 📈 Example Output

```
🔍 GENERAL ANOMALIES: 47 detected (0.47%)

🎯 DETAILED THREAT ANALYSIS
─────────────────────────────────────────────────
🚨 Lateral Movement: 3 suspicious activities detected
🚨 Data Exfiltration: 2 suspicious transfers detected
🚨 ICS Anomalies: 5 anomaly types detected

🔴 TOP 10 ANOMALIES:
timestamp            src_ip        dst_ip       dst_port  bytes    anomaly_score
2025-10-08 09:15:23  10.0.1.100   203.45.67.89  443      50000000  -0.95
```

## ⚙️ Configuration

Model parameters trong `train.py`:

```python
contamination=0.05  # Expected % of anomalies (default 5%)
```

Features được sử dụng:
- Traffic metrics: bytes, packets, duration
- Derived features: bytes_per_packet, packets_per_second
- Protocol features: TCP/UDP, ICS protocols
- Time features: hour, day_of_week, night/weekend
- Connection diversity: unique_destinations

## 📊 Performance Tuning

### Contamination Rate
- **0.01-0.03**: Conservative (ít false positives)
- **0.05**: Balanced (recommended)
- **0.10-0.15**: Aggressive (catch more anomalies)

### Feature Selection
Thêm custom features trong `src/network_loader.py`:

```python
df['custom_feature'] = ...  # Your feature engineering
```

## 🐳 Docker (Optional)

```bash
cd docker
docker-compose up
```

## 🧪 Testing

```bash
# Generate test data
python scripts/generate_network_data.py

# Run detection
python detect.py --data data/network_traffic.csv --detailed
```

## 📝 Notes

- **Training data**: Chỉ dùng **normal traffic** (không anomalies)
- **Test data**: Có thể chứa cả normal và anomalous traffic
- **Contamination**: Điều chỉnh dựa trên expected anomaly rate
- **Thresholds**: Lateral/Exfil detection dùng 95th percentile

## 🚨 Security Best Practices

1. **Baseline**: Train trên clean normal traffic
2. **Retrain**: Cập nhật model định kỳ (monthly)
3. **Validation**: Human review top anomalies
4. **Integration**: Kết hợp với SIEM/SOC
5. **Alerts**: Set up notifications cho high-score anomalies

## 📚 Data Sources

Hệ thống đọc data từ các tools:
- **Wireshark** (Export as CSV)
- **Zeek/Bro** (conn.log)
- **nfdump** (NetFlow)
- **Suricata** (eve.json)
- **Custom network monitoring tools**

## 🔗 Integration

### With SIEM

```python
from src.anomaly_detector import ICSAnomalyDetector

detector = ICSAnomalyDetector()
detector.load_model('output/model.pkl')
results = detector.predict(your_netflow_data)

# Send to SIEM
high_risk = results[results['anomaly_score'] < -0.5]
send_to_siem(high_risk)
```

---

**🔐 Protecting ICS/SCADA Networks with AI 🚀**
