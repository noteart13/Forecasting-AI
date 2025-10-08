"""
Convert Wireshark export CSV to format cho ICS/SCADA Anomaly Detection
"""
import pandas as pd
import sys
from pathlib import Path

def convert_wireshark_csv(input_file, output_file='data/converted_traffic.csv'):
    """
    Convert Wireshark CSV export to system format
    
    Wireshark columns:
    - No, Time, Source, Destination, Protocol, Length, Info
    
    System format:
    - timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, duration
    """
    
    print(f"📥 Loading Wireshark data from {input_file}...")
    
    try:
        # Read Wireshark CSV
        df = pd.read_csv(input_file)
        
        print(f"✅ Loaded {len(df)} packets")
        print(f"Columns: {df.columns.tolist()}")
        
        # Map columns
        converted = pd.DataFrame()
        
        # Basic mapping
        if 'Time' in df.columns:
            converted['timestamp'] = df['Time']
        elif 'time' in df.columns:
            converted['timestamp'] = df['time']
        else:
            print("⚠️  No Time column found, using sequential time")
            converted['timestamp'] = range(len(df))
        
        # IP addresses
        if 'Source' in df.columns:
            converted['src_ip'] = df['Source']
        elif 'source' in df.columns or 'src' in df.columns:
            converted['src_ip'] = df.get('source', df.get('src'))
        else:
            print("❌ Source IP column not found")
            return None
        
        if 'Destination' in df.columns:
            converted['dst_ip'] = df['Destination']
        elif 'destination' in df.columns or 'dst' in df.columns:
            converted['dst_ip'] = df.get('destination', df.get('dst'))
        else:
            print("❌ Destination IP column not found")
            return None
        
        # Protocol
        if 'Protocol' in df.columns:
            converted['protocol'] = df['Protocol']
        elif 'protocol' in df.columns:
            converted['protocol'] = df['protocol']
        else:
            print("⚠️  Protocol column not found, defaulting to TCP")
            converted['protocol'] = 'TCP'
        
        # Length/Bytes
        if 'Length' in df.columns:
            converted['bytes'] = df['Length']
        elif 'length' in df.columns:
            converted['bytes'] = df['length']
        else:
            print("⚠️  Length column not found, using default 1000")
            converted['bytes'] = 1000
        
        # Extract ports from Info column if available
        if 'Info' in df.columns or 'info' in df.columns:
            info_col = df.get('Info', df.get('info', ''))
            
            # Try to extract ports (e.g., "56443 → 443" or "Port=443")
            converted['src_port'] = 0
            converted['dst_port'] = 0
            
            # Simple heuristic: look for numbers in info
            for idx, info in enumerate(info_col):
                if pd.notna(info):
                    import re
                    ports = re.findall(r'\b(\d{1,5})\b', str(info))
                    if len(ports) >= 2:
                        converted.at[idx, 'src_port'] = int(ports[0]) if int(ports[0]) < 65536 else 0
                        converted.at[idx, 'dst_port'] = int(ports[1]) if int(ports[1]) < 65536 else 0
                    elif len(ports) == 1:
                        converted.at[idx, 'dst_port'] = int(ports[0]) if int(ports[0]) < 65536 else 0
        else:
            converted['src_port'] = 0
            converted['dst_port'] = 0
        
        # Packets (1 per row in Wireshark)
        converted['packets'] = 1
        
        # Duration (aggregate later)
        converted['duration'] = 0.1
        
        # Save
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        converted.to_csv(output_file, index=False)
        
        print(f"\n✅ Converted {len(converted)} packets")
        print(f"💾 Saved to {output_file}")
        print(f"\n📊 Summary:")
        print(f"   Unique sources: {converted['src_ip'].nunique()}")
        print(f"   Unique destinations: {converted['dst_ip'].nunique()}")
        print(f"   Protocols: {converted['protocol'].unique()}")
        print(f"   Total bytes: {converted['bytes'].sum():,.0f}")
        
        print(f"\n🚀 Next steps:")
        print(f"   1. Train: python train.py --data {output_file}")
        print(f"   2. Detect: python detect.py --data {output_file} --detailed")
        
        return converted
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python convert_wireshark.py <wireshark_export.csv> [output.csv]")
        print("\nExample:")
        print("  python scripts/convert_wireshark.py capture.csv")
        print("  python scripts/convert_wireshark.py capture.csv data/my_traffic.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'data/converted_traffic.csv'
    
    convert_wireshark_csv(input_file, output_file)
