# ⚡ Quick Start - ICS/SCADA Anomaly Detection

## 🎯 3 Bước để bắt đầu

### 1️⃣ Cài đặt (30 giây)

```bash
pip install -r requirements.txt
```

### 2️⃣ Tạo dữ liệu mẫu (1 phút)

```bash
python scripts/generate_network_data.py
```

Tạo 10,000 network flows với ~5% anomalies.

### 3️⃣ Train và Detect (2 phút)

```bash
# Train model trên normal traffic
python train.py --data data/network_traffic.csv

# Phát hiện anomalies
python detect.py --data data/network_traffic.csv --detailed
```

## 📊 Kết quả

```
output/
├── anomaly_model.pkl           # Trained model
├── anomalies_detected.csv      # All anomalies
├── lateral_movement.csv        # Lateral movement events
├── data_exfiltration.csv       # Data exfil attempts
└── ics_anomalies.csv          # ICS-specific issues
```

## 🔧 Với dữ liệu thực

### Bước 1: Xuất NetFlow data

Từ công cụ network monitoring (Wireshark, Zeek, nfdump):

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration
1696789123,10.0.1.100,10.0.1.10,54321,502,TCP,2048,15,1.2
```

### Bước 2: Train trên normal traffic

```bash
python train.py --data your_normal_traffic.csv
```

### Bước 3: Detect trên test data

```bash
python detect.py --data your_test_traffic.csv --detailed
```

## 🚨 Hiểu kết quả

### Anomaly Score
- **< -0.5**: High risk (cần investigate ngay)
- **-0.5 to -0.3**: Medium risk
- **> -0.3**: Low risk

### Threat Types

**Lateral Movement**
- Source IP kết nối nhiều destinations
- Port scanning
- Failed connections

**Data Exfiltration**
- Large outbound transfers
- Connections ra external IPs
- Unusual upload patterns

**ICS Anomalies**
- ICS devices → unexpected hosts
- Traffic vào giờ bất thường
- Protocol violations

## 💡 Tips

1. **Training data**: Chỉ dùng clean normal traffic
2. **Contamination**: Adjust `--contamination 0.05` (5% expected anomalies)
3. **Thresholds**: Top 5% được flag là anomalies
4. **Retraining**: Update model hàng tháng

## 📚 Đọc thêm

- `README.md` - Full documentation
- `src/network_loader.py` - Data loading
- `src/anomaly_detector.py` - Detection algorithms

---

**Done! Bắt đầu bảo vệ mạng ICS/SCADA của bạn 🔒**
