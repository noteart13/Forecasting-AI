# 🔒 Hướng dẫn sử dụng hệ thống phân tích PCAP từ Wireshark

## 📋 Tổng quan

Hệ thống AI này có thể đọc và phân tích trực tiếp file .pcap từ Wireshark để phát hiện các hành vi bất thường trong mạng ICS/SCADA:

- **Lateral Movement**: Kẻ tấn công di chuyển ngang trong hệ thống
- **Data Exfiltration**: Hành vi đánh cắp và chuyển dữ liệu ra bên ngoài  
- **ICS-specific anomalies**: Các hành vi bất thường trong mạng Hệ thống Điều khiển Công nghiệp

## 🚀 Cài đặt

### 1. Cài đặt dependencies

```bash
pip install -r requirements.txt
```

**Lưu ý**: Để đọc file .pcap, bạn cần cài đặt thêm:
```bash
pip install scapy pyshark
```

### 2. Kiểm tra cài đặt

```bash
python -c "import scapy; print('Scapy OK')"
python -c "import pyshark; print('PyShark OK')"
```

## 📊 Sử dụng với file .pcap

### Phân tích file .pcap từ Wireshark

```bash
python demo_pcap.py --pcap your_capture.pcap --detailed
```

**Tham số:**
- `--pcap`: Đường dẫn đến file .pcap/.pcapng
- `--detailed`: Chạy phân tích chi tiết (Lateral Movement, Data Exfiltration, ICS Anomalies)
- `--model`: Đường dẫn đến model đã train (tùy chọn)
- `--output`: Thư mục lưu kết quả (mặc định: output/pcap_analysis)

### Ví dụ thực tế

```bash
# Phân tích file capture từ Wireshark
python demo_pcap.py --pcap captures/network_traffic.pcap --detailed

# Sử dụng model đã train trước
python demo_pcap.py --pcap captures/suspicious_activity.pcap --model models/production_model.pkl --detailed
```

## 🔍 Các loại phân tích

### 1. Lateral Movement Detection

**Phát hiện:**
- Port scanning (scan nhiều ports)
- Host scanning (scan nhiều hosts)
- Connections đến nhiều destinations trong thời gian ngắn
- Traffic patterns bất thường

**Output:** `lateral_movement.csv`
- `lateral_score`: Điểm số lateral movement
- `is_port_scan`: Có phải port scanning không
- `is_host_scan`: Có phải host scanning không
- `is_high_risk`: Pattern nguy hiểm cao

### 2. Data Exfiltration Detection

**Phát hiện:**
- Upload traffic lớn bất thường
- Connections ra external IPs
- Transfers vào giờ bất thường (đêm, cuối tuần)
- Sử dụng protocols đáng ngờ (FTP, HTTP POST, etc.)

**Output:** `data_exfiltration.csv`
- `exfil_score`: Điểm số exfiltration
- `mb_transferred`: Dữ liệu chuyển (MB)
- `is_large_transfer`: Transfer lớn (>10MB)
- `is_unusual_time`: Thời gian bất thường
- `is_high_risk`: Pattern nguy hiểm cao

### 3. ICS Anomalies Detection

**Phát hiện:**
- ICS devices kết nối với external IPs (CRITICAL)
- Non-ICS devices truy cập ICS ports (CRITICAL)
- ICS traffic vào giờ bất thường (night/weekend)
- Sudden traffic volume changes
- Unusual ICS protocol usage patterns

**Output:** `ics_anomalies.csv`
- `type`: Loại anomaly
- `severity`: Mức độ nghiêm trọng (low/medium/high/critical)
- `count`: Số lượng events
- `description`: Mô tả chi tiết

## 📈 Kết quả phân tích

### File output

```
output/pcap_analysis/
├── general_anomalies.csv      # Tất cả anomalies
├── lateral_movement.csv      # Lateral movement events
├── data_exfiltration.csv     # Data exfiltration attempts
└── ics_anomalies.csv         # ICS-specific anomalies
```

### Điểm số và mức độ nguy hiểm

**Anomaly Score:**
- `< -0.5`: 🔴 High risk (investigate ngay)
- `-0.5 to -0.3`: 🟡 Medium risk
- `> -0.3`: 🟢 Low risk

**Severity Levels:**
- `critical`: 🚨 Nguy hiểm cao nhất (ICS external comm, unauthorized access)
- `high`: ⚠️ Nguy hiểm cao (traffic spikes, large transfers)
- `medium`: ⚡ Nguy hiểm trung bình (unusual timing, protocol usage)
- `low`: ℹ️ Nguy hiểm thấp

## 🎯 ICS Protocols được hỗ trợ

| Port  | Protocol     | Mô tả |
|-------|--------------|-------|
| 102   | Siemens S7   | PLC communication |
| 502   | Modbus TCP   | Industrial automation |
| 2404  | IEC 61850    | Substation automation |
| 20000 | DNP3         | SCADA |
| 44818 | EtherNet/IP  | Industrial Ethernet |
| 47808 | BACnet       | Building automation |
| 4840  | OPC UA       | Industrial IoT |

## 🔧 Troubleshooting

### Lỗi "No module named 'scapy'"

```bash
pip install scapy
```

### Lỗi "No module named 'pyshark'"

```bash
pip install pyshark
```

**Lưu ý**: PyShark cần Wireshark được cài đặt trên hệ thống.

### File .pcap không đọc được

- Kiểm tra file có phải định dạng .pcap/.pcapng không
- Thử với file .pcap nhỏ hơn (< 100MB)
- Kiểm tra quyền đọc file

### Không phát hiện anomalies

```bash
# Tăng sensitivity
python demo_pcap.py --pcap file.pcap --detailed --model output/anomaly_model.pkl
```

## 📝 Ví dụ kết quả

### Lateral Movement Detection

```
🚨 Lateral Movement: 84 suspicious activities detected
🚨 High Risk Patterns: 0 detected (port/host scanning)

TOP SUSPICIOUS SOURCES:
src_ip        unique_dsts  unique_ports  lateral_score  is_port_scan  is_host_scan
192.168.1.99           8            15          12.50             1             1
10.0.0.13              3             4           7.00             0             0
```

### Data Exfiltration Detection

```
🚨 Data Exfiltration: 6 suspicious transfers detected
🚨 High Risk Patterns: 4 detected (large transfers/unusual timing)

TOP SUSPICIOUS TRANSFERS:
src_ip        mb_transferred  unique_external_dsts  exfil_score  is_large_transfer
192.168.1.15       21.63                     3    74.90                  1
192.168.1.15       14.24                     2    50.72                  1
```

### ICS Anomalies Detection

```
🚨 ICS Anomalies: 3 anomaly types detected
- unusual_time (medium): 66 ICS connections during night hours
- external_communication (critical): 10 ICS connections to external IPs
- unusual_protocol_usage (medium): 1 ICS protocols showing unusual usage patterns

CRITICAL ICS ANOMALIES:
- external_communication: 10 ICS connections to external IPs
```

## 🚀 Best Practices

### 1. Chuẩn bị dữ liệu

- Capture đủ thời gian (ít nhất 1 giờ)
- Bao gồm cả normal traffic và suspicious activity
- Đảm bảo có ICS protocols trong capture

### 2. Phân tích

- Luôn sử dụng `--detailed` để có phân tích đầy đủ
- Review các critical anomalies trước
- Cross-reference với SIEM/IDS logs

### 3. Response

- Investigate critical anomalies ngay lập tức
- Block suspicious IPs nếu cần
- Document findings cho incident response

## 📞 Hỗ trợ

Nếu gặp vấn đề:

1. Kiểm tra logs trong console output
2. Verify file .pcap format
3. Test với sample data: `python scripts/generate_pcap_data.py`
4. Check dependencies: `pip list | grep -E "(scapy|pyshark)"`

---

**🔐 Bảo vệ mạng ICS/SCADA của bạn với AI! 🚀**
