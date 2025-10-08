"""
Generate Sample Network Traffic Data cho ICS/SCADA Security Testing
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_network_data(
    num_flows: int = 10000,
    anomaly_rate: float = 0.05,
    output_file: str = 'data/network_traffic.csv'
):
    """
    Generate synthetic network flow data với normal và anomalous traffic
    """
    
    print("🌐 Generating network traffic data...")
    
    # ICS devices và servers
    ics_devices = [f'10.0.1.{i}' for i in range(10, 30)]  # PLCs, RTUs
    scada_servers = ['10.0.1.5', '10.0.1.6']
    engineering_stations = ['10.0.1.100', '10.0.1.101']
    office_network = [f'10.0.2.{i}' for i in range(10, 100)]
    external_ips = [f'203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}' for _ in range(50)]
    
    # ICS protocols và ports
    ics_ports = {
        102: 'S7',
        502: 'Modbus',
        2404: 'IEC61850',
        20000: 'DNP3',
        44818: 'EtherNet/IP',
        4840: 'OPC-UA'
    }
    
    normal_ports = [80, 443, 22, 3389, 445]
    
    flows = []
    start_time = datetime.now() - timedelta(days=1)
    
    num_normal = int(num_flows * (1 - anomaly_rate))
    num_anomaly = num_flows - num_normal
    
    # Generate NORMAL traffic
    for i in range(num_normal):
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
        
        # Normal ICS communication
        if random.random() < 0.6:
            src_ip = random.choice(scada_servers + engineering_stations)
            dst_ip = random.choice(ics_devices)
            dst_port = random.choice(list(ics_ports.keys()))
            protocol = 'TCP'
            bytes_val = random.randint(100, 5000)
            packets = random.randint(5, 50)
            duration = random.uniform(0.1, 5.0)
        
        # Normal office traffic
        else:
            src_ip = random.choice(office_network)
            dst_ip = random.choice(office_network + external_ips)
            dst_port = random.choice(normal_ports)
            protocol = random.choice(['TCP', 'UDP'])
            bytes_val = random.randint(500, 50000)
            packets = random.randint(10, 200)
            duration = random.uniform(0.5, 30.0)
        
        flows.append({
            'timestamp': timestamp.timestamp(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': dst_port,
            'protocol': protocol,
            'bytes': bytes_val,
            'packets': packets,
            'duration': duration
        })
    
    # Generate ANOMALOUS traffic
    print(f"   Injecting {num_anomaly} anomalies...")
    
    for i in range(num_anomaly):
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
        anomaly_type = random.choice(['lateral', 'exfil', 'ics_anomaly', 'scan'])
        
        if anomaly_type == 'lateral':
            # Lateral movement: một source kết nối nhiều destinations
            src_ip = random.choice(office_network)
            for _ in range(random.randint(5, 15)):
                flows.append({
                    'timestamp': timestamp.timestamp(),
                    'src_ip': src_ip,
                    'dst_ip': random.choice(ics_devices + office_network),
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([22, 445, 3389] + list(ics_ports.keys())),
                    'protocol': 'TCP',
                    'bytes': random.randint(100, 1000),
                    'packets': random.randint(2, 10),
                    'duration': random.uniform(0.1, 1.0)
                })
        
        elif anomaly_type == 'exfil':
            # Data exfiltration: large upload to external
            src_ip = random.choice(ics_devices + engineering_stations)
            dst_ip = random.choice(external_ips)
            flows.append({
                'timestamp': timestamp.timestamp(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 8080]),
                'protocol': 'TCP',
                'bytes': random.randint(10000000, 100000000),  # 10-100 MB
                'packets': random.randint(5000, 50000),
                'duration': random.uniform(60.0, 600.0)
            })
        
        elif anomaly_type == 'ics_anomaly':
            # ICS device talking to unexpected host
            src_ip = random.choice(ics_devices)
            dst_ip = random.choice(external_ips + office_network)
            flows.append({
                'timestamp': timestamp.timestamp(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice(list(ics_ports.keys())),
                'protocol': 'TCP',
                'bytes': random.randint(500, 5000),
                'packets': random.randint(10, 100),
                'duration': random.uniform(1.0, 10.0)
            })
        
        elif anomaly_type == 'scan':
            # Port scan
            src_ip = random.choice(office_network + external_ips)
            dst_ip = random.choice(ics_devices)
            for port in range(1, 1025, random.randint(1, 50)):
                flows.append({
                    'timestamp': timestamp.timestamp(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': random.randint(1024, 65535),
                    'dst_port': port,
                    'protocol': 'TCP',
                    'bytes': 60,
                    'packets': 1,
                    'duration': 0.01
                })
    
    # Create DataFrame
    df = pd.DataFrame(flows)
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    
    # Save
    df.to_csv(output_file, index=False)
    
    print(f"✅ Generated {len(df)} network flows")
    print(f"   Normal traffic: ~{num_normal} flows")
    print(f"   Anomalies: ~{num_anomaly} flows ({anomaly_rate*100:.1f}%)")
    print(f"   Saved to {output_file}")
    
    # Statistics
    print(f"\n📊 Statistics:")
    print(f"   Unique sources: {df['src_ip'].nunique()}")
    print(f"   Unique destinations: {df['dst_ip'].nunique()}")
    print(f"   Total bytes: {df['bytes'].sum():,.0f}")
    print(f"   Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    
    return df


if __name__ == '__main__':
    df = generate_network_data(
        num_flows=10000,
        anomaly_rate=0.05,
        output_file='data/network_traffic.csv'
    )
    
    print("\n" + "="*60)
    print("✅ Sample network data generation completed!")
    print("="*60)
    print("\nNext steps:")
    print("  1. Train model: python train.py")
    print("  2. Detect anomalies: python detect.py --data data/network_traffic.csv --detailed")
