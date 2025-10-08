"""
Script để tạo dữ liệu mẫu PCAP cho testing
Tạo các patterns bất thường: Lateral Movement, Data Exfiltration, ICS Anomalies
"""
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_sample_pcap_data():
    """Generate sample network traffic data with anomalies"""
    
    # Base time range
    start_time = datetime.now() - timedelta(hours=24)
    end_time = datetime.now()
    
    # Generate normal traffic
    normal_flows = []
    
    # Internal IPs (simulate corporate network)
    internal_ips = [
        '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13',
        '192.168.1.20', '192.168.1.21', '192.168.1.22', '192.168.1.23',
        '10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13'
    ]
    
    # External IPs
    external_ips = [
        '8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9',
        '203.0.113.1', '203.0.113.2', '203.0.113.3'
    ]
    
    # ICS devices
    ics_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
    
    # ICS ports
    ics_ports = [102, 502, 2404, 20000, 44818, 47808, 4840]
    
    # Generate normal traffic (80% of data)
    for _ in range(800):
        timestamp = start_time + timedelta(
            seconds=random.randint(0, int((end_time - start_time).total_seconds()))
        )
        
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(internal_ips + external_ips)
        
        # Normal port distribution
        if random.random() < 0.7:  # 70% internal traffic
            dst_ip = random.choice(internal_ips)
            dst_port = random.choice([80, 443, 22, 21, 25, 53, 110, 143])
        else:  # 30% external traffic
            dst_port = random.choice([80, 443, 22, 21, 25, 53])
        
        protocol = random.choice(['TCP', 'UDP'])
        bytes_count = random.randint(100, 10000)
        packets = random.randint(1, 50)
        duration = random.uniform(0.1, 60.0)
        
        normal_flows.append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': dst_port,
            'protocol': protocol,
            'bytes': bytes_count,
            'packets': packets,
            'duration': duration
        })
    
    # Generate ICS traffic (10% of data)
    for _ in range(100):
        timestamp = start_time + timedelta(
            seconds=random.randint(0, int((end_time - start_time).total_seconds()))
        )
        
        src_ip = random.choice(ics_ips)
        dst_ip = random.choice(ics_ips + internal_ips)
        dst_port = random.choice(ics_ports)
        
        protocol = 'TCP'  # Most ICS protocols use TCP
        bytes_count = random.randint(50, 1000)  # ICS packets are usually small
        packets = random.randint(1, 10)
        duration = random.uniform(0.1, 5.0)  # ICS connections are usually short
        
        normal_flows.append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': dst_port,
            'protocol': protocol,
            'bytes': bytes_count,
            'packets': packets,
            'duration': duration
        })
    
    # Generate Lateral Movement patterns (5% of data)
    lateral_flows = []
    attacker_ip = '192.168.1.99'  # Compromised internal IP
    
    # Port scanning pattern
    for port in range(22, 32):  # Scan SSH ports
        timestamp = start_time + timedelta(minutes=random.randint(0, 1440))
        
        lateral_flows.append({
            'timestamp': timestamp,
            'src_ip': attacker_ip,
            'dst_ip': random.choice(internal_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': port,
            'protocol': 'TCP',
            'bytes': random.randint(50, 200),
            'packets': random.randint(1, 3),
            'duration': random.uniform(0.1, 2.0)
        })
    
    # Host scanning pattern
    for target_ip in internal_ips[:8]:  # Scan multiple hosts
        timestamp = start_time + timedelta(minutes=random.randint(0, 1440))
        
        lateral_flows.append({
            'timestamp': timestamp,
            'src_ip': attacker_ip,
            'dst_ip': target_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 21]),
            'protocol': 'TCP',
            'bytes': random.randint(100, 500),
            'packets': random.randint(2, 10),
            'duration': random.uniform(0.5, 5.0)
        })
    
    # Generate Data Exfiltration patterns (3% of data)
    exfil_flows = []
    compromised_ip = '192.168.1.15'
    
    # Large data transfers to external IPs
    for _ in range(20):
        timestamp = start_time + timedelta(
            minutes=random.randint(1200, 1440)  # Late night transfers
        )
        
        exfil_flows.append({
            'timestamp': timestamp,
            'src_ip': compromised_ip,
            'dst_ip': random.choice(external_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 21, 22]),  # HTTP, HTTPS, FTP, SSH
            'protocol': random.choice(['TCP', 'UDP']),
            'bytes': random.randint(1000000, 10000000),  # Large transfers (1-10MB)
            'packets': random.randint(100, 1000),
            'duration': random.uniform(10.0, 300.0)  # Long duration
        })
    
    # Generate ICS Anomalies (2% of data)
    ics_anomaly_flows = []
    
    # ICS device communicating with external IP (critical anomaly)
    for _ in range(10):
        timestamp = start_time + timedelta(
            minutes=random.randint(0, 1440)
        )
        
        ics_anomaly_flows.append({
            'timestamp': timestamp,
            'src_ip': random.choice(ics_ips),
            'dst_ip': random.choice(external_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(ics_ports),
            'protocol': 'TCP',
            'bytes': random.randint(100, 2000),
            'packets': random.randint(1, 20),
            'duration': random.uniform(0.1, 10.0)
        })
    
    # Non-ICS device accessing ICS ports (unauthorized access)
    for _ in range(15):
        timestamp = start_time + timedelta(
            minutes=random.randint(0, 1440)
        )
        
        ics_anomaly_flows.append({
            'timestamp': timestamp,
            'src_ip': random.choice([ip for ip in internal_ips if ip not in ics_ips]),
            'dst_ip': random.choice(ics_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(ics_ports),
            'protocol': 'TCP',
            'bytes': random.randint(50, 1000),
            'packets': random.randint(1, 10),
            'duration': random.uniform(0.1, 5.0)
        })
    
    # ICS traffic at unusual times (night/weekend)
    for _ in range(20):
        # Night time (22:00 - 06:00)
        hour = random.choice([22, 23, 0, 1, 2, 3, 4, 5])
        timestamp = start_time.replace(hour=hour, minute=random.randint(0, 59))
        
        ics_anomaly_flows.append({
            'timestamp': timestamp,
            'src_ip': random.choice(ics_ips),
            'dst_ip': random.choice(ics_ips + internal_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(ics_ports),
            'protocol': 'TCP',
            'bytes': random.randint(50, 1000),
            'packets': random.randint(1, 10),
            'duration': random.uniform(0.1, 5.0)
        })
    
    # Combine all flows
    all_flows = normal_flows + lateral_flows + exfil_flows + ics_anomaly_flows
    
    # Convert to DataFrame and sort by timestamp
    df = pd.DataFrame(all_flows)
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    logger.info(f"✅ Generated {len(df)} network flows:")
    logger.info(f"  - Normal flows: {len(normal_flows)}")
    logger.info(f"  - Lateral Movement: {len(lateral_flows)}")
    logger.info(f"  - Data Exfiltration: {len(exfil_flows)}")
    logger.info(f"  - ICS Anomalies: {len(ics_anomaly_flows)}")
    
    return df


def main():
    """Generate sample data and save to CSV"""
    logger.info("🔧 Generating sample PCAP data...")
    
    # Generate data
    data = generate_sample_pcap_data()
    
    # Save to CSV
    output_file = 'data/sample_pcap_data.csv'
    data.to_csv(output_file, index=False)
    
    logger.info(f"💾 Sample data saved to {output_file}")
    logger.info(f"📊 Data shape: {data.shape}")
    logger.info(f"📅 Time range: {data['timestamp'].min()} to {data['timestamp'].max()}")
    
    # Show some statistics
    logger.info("\n📈 Data Statistics:")
    logger.info(f"  Unique sources: {data['src_ip'].nunique()}")
    logger.info(f"  Unique destinations: {data['dst_ip'].nunique()}")
    logger.info(f"  Total bytes: {data['bytes'].sum():,}")
    logger.info(f"  ICS protocol flows: {data['dst_port'].isin([102, 502, 2404, 20000, 44818, 47808, 4840]).sum()}")
    
    # Show anomaly patterns
    logger.info("\n🔍 Anomaly Patterns:")
    logger.info(f"  Lateral Movement (attacker IP): {data[data['src_ip'] == '192.168.1.99'].shape[0]} flows")
    logger.info(f"  Data Exfiltration (compromised IP): {data[data['src_ip'] == '192.168.1.15'].shape[0]} flows")
    logger.info(f"  ICS External Comm: {data[data['src_ip'].isin(['192.168.1.100', '192.168.1.101', '192.168.1.102']) & ~data['dst_ip'].str.startswith(('192.168', '10.0'))].shape[0]} flows")


if __name__ == '__main__':
    main()
