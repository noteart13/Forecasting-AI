# 🔒 ICS/SCADA Network Anomaly Detection

Hệ thống AI phát hiện tấn công mạng trong môi trường công nghiệp (ICS/SCADA) - Lateral Movement, Data Exfiltration, ICS Anomalies.

## 🚀 Quick Start

```bash
# 1. Cài đặt dependencies
pip install -r requirements.txt

# 2. Chạy demo tự động
python demo.py

# 3. Phân tích PCAP từ Wireshark
python demo_pcap.py --pcap capture.pcap --detailed
```

## 📊 Input Format

**Hỗ trợ:** CSV, Excel, JSON, PCAP/PCAPNG (Wireshark)

**Required columns:**
```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration
1696789123,10.0.1.100,10.0.1.10,54321,502,TCP,2048,15,1.2
```

## 🔧 Sử dụng

### Demo tự động (Recommended)
```bash
python demo.py
```
→ Tự động generate data → train → detect → báo cáo

### PCAP Analysis (Wireshark)
```bash
python demo_pcap.py --pcap your_file.pcap --detailed
```
→ Phân tích trực tiếp file .pcap/.pcapng từ Wireshark

**Tham số:**
- `--pcap`: Đường dẫn file .pcap/.pcapng
- `--detailed`: Phân tích chi tiết (Lateral Movement, Data Exfil, ICS)
- `--model`: Model đã train (optional)
- `--output`: Thư mục kết quả (default: output/pcap_analysis)

**Lưu ý:** Cần cài đặt thêm:
```bash
pip install scapy pyshark
```

### Manual Workflow
```bash
# 1. Generate sample data
python scripts/generate_network_data.py

# 2. Train model
python train.py --data data/network_traffic.csv

# 3. Detect anomalies
python detect.py --data data/network_traffic.csv --detailed
```

## 📈 Output Files

```
output/
├── anomaly_model.pkl          # Trained model
├── anomalies_detected.csv     # Tất cả anomalies
├── lateral_movement.csv       # Di chuyển ngang
├── data_exfiltration.csv      # Đánh cắp dữ liệu
├── ics_anomalies.csv          # ICS anomalies
└── attack_summary.txt         # Báo cáo tổng hợp
```

**Anomaly Score:** < -0.5 (🔴 High) | -0.5 to -0.3 (🟡 Medium) | > -0.3 (🟢 Low)

## 🔌 ICS Protocols Supported

| Port  | Protocol     | Mô tả |
|-------|--------------|-------|
| 102   | Siemens S7   | PLC communication |
| 502   | Modbus TCP   | Industrial automation |
| 2404  | IEC 61850    | Substation automation |
| 20000 | DNP3         | SCADA systems |
| 44818 | EtherNet/IP  | Industrial Ethernet |
| 4840  | OPC UA       | Industrial IoT |

## 🎯 Detection Methods

**Machine Learning:** Isolation Forest (unsupervised) - học baseline, phát hiện deviation tự động

**Rule-based Detection:**

### 1. Lateral Movement
- Port scanning (scan nhiều ports)
- Host scanning (scan nhiều hosts)
- Multiple destinations trong thời gian ngắn
- Output: `lateral_score`, `is_port_scan`, `is_host_scan`, `is_high_risk`

### 2. Data Exfiltration
- Upload traffic lớn bất thường
- Connections ra external IPs
- Transfers vào giờ đêm/cuối tuần
- Output: `exfil_score`, `mb_transferred`, `is_large_transfer`, `is_unusual_time`

### 3. ICS Anomalies
- ICS devices → external IPs (🚨 CRITICAL)
- Non-ICS devices → ICS ports (🚨 CRITICAL)
- ICS traffic vào giờ bất thường
- Sudden traffic volume changes
- Output: `type`, `severity` (low/medium/high/critical), `count`, `description`

## ⚙️ Configuration

### Training
```bash
python train.py --data data/normal_traffic.csv --contamination 0.05
```
- `0.01-0.03`: Conservative (ít false positive)
- `0.05`: Balanced ✅
- `0.10-0.15`: Aggressive (phát hiện nhiều)

### Detection
```bash
python detect.py --data data/test.csv --model output/model.pkl --detailed
```

## 📁 Cấu trúc Project

```
forecasting-ai/
├── demo.py, demo_pcap.py      # Demo scripts
├── train.py, detect.py         # Training & Detection
├── requirements.txt            # Dependencies
├── src/
│   ├── network_loader.py       # Load data (CSV/PCAP)
│   └── anomaly_detector.py     # ML models + detection logic
├── scripts/
│   └── generate_network_data.py
├── data/                       # Input files
└── output/                     # Results
```

## 🛠️ Troubleshooting

**Không phát hiện anomaly:**
```bash
python train.py --contamination 0.10  # Tăng lên 10%
```

**Quá nhiều false positive:**
```bash
python train.py --contamination 0.01  # Giảm xuống 1%
```

**Import errors:**
```bash
pip install -r requirements.txt
```

**PCAP errors:**
```bash
# Lỗi "No module named 'scapy'"
pip install scapy pyshark

# File .pcap không đọc được
# → Kiểm tra format .pcap/.pcapng
# → Thử file nhỏ hơn (< 100MB)
# → Kiểm tra quyền đọc file
```

## 🚨 Example Output

```
🔍 GENERAL ANOMALIES: 47 detected (0.47%)

🎯 DETAILED THREAT ANALYSIS
────────────────────────────────────────
🚨 Lateral Movement: 3 suspicious activities
🚨 Data Exfiltration: 2 suspicious transfers
🚨 ICS Anomalies: 5 anomaly types

🔴 TOP ANOMALIES:
10.0.1.100 → 203.45.67.89 | 5MB | score: -0.95
```

## 💡 Best Practices

✅ **Training:** Dùng clean normal traffic only, ít nhất 1000+ flows, retrain hàng tháng
✅ **Detection:** Review top anomalies manually, tune contamination theo false positive rate
✅ **Production:** Integrate với SIEM, setup alerts cho high-risk events

## 🏆 Key Features

✅ Zero-day detection (behavior-based)
✅ ICS protocol-aware (Modbus, DNP3, S7, OPC UA)
✅ No signatures needed
✅ Low false positive rate
✅ PCAP/Wireshark support
✅ Auto-generated professional reports

---

**🔐 Bảo vệ mạng ICS/SCADA của bạn với AI!**

👉 Chạy ngay: `python demo.py`
