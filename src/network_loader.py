"""
Network Data Loader for ICS/SCADA Anomaly Detection
Đọc NetFlow và packet metadata từ tools như Wireshark, Zeek, nfdump, etc.
"""
import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkLoader:
    """Load NetFlow/packet data từ CSV, JSON, Excel"""
    
    # ICS/SCADA ports
    ICS_PORTS = {
        102: 'S7',
        502: 'Modbus',
        2404: 'IEC 61850',
        20000: 'DNP3',
        44818: 'EtherNet/IP',
        47808: 'BACnet',
        4840: 'OPC UA'
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = None
        
    def load(self) -> pd.DataFrame:
        """
        Load network flow data
        Hỗ trợ CSV, Excel, JSON
        
        Expected columns:
        - timestamp: Unix timestamp or datetime
        - src_ip, dst_ip: IP addresses
        - src_port, dst_port: Port numbers
        - protocol: TCP/UDP/ICMP
        - bytes: Total bytes
        - packets: Packet count
        - duration: Flow duration (seconds)
        """
        try:
            if self.file_path.endswith('.csv'):
                self.data = pd.read_csv(self.file_path)
            elif self.file_path.endswith(('.xlsx', '.xls')):
                self.data = pd.read_excel(self.file_path)
            elif self.file_path.endswith('.json'):
                self.data = pd.read_json(self.file_path)
            else:
                raise ValueError("Unsupported format. Use CSV, Excel, or JSON")
            
            logger.info(f"✅ Loaded {len(self.data)} flows from {self.file_path}")
            logger.info(f"Columns: {list(self.data.columns)}")
            return self.data
            
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            raise
    
    def preprocess(self) -> pd.DataFrame:
        """Preprocess và extract features"""
        if self.data is None:
            raise ValueError("No data loaded")
        
        df = self.data.copy()
        
        # Convert timestamp
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
            df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Fill missing
        df = df.fillna(0)
        
        # Extract features
        df = self._extract_features(df)
        
        logger.info(f"✅ Preprocessed {len(df)} flows with {len(df.columns)} features")
        self.data = df
        return df
    
    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract security features"""
        
        # 1. ICS Protocol Detection
        df['is_ics_protocol'] = df['dst_port'].isin(self.ICS_PORTS.keys()).astype(int)
        df['ics_protocol'] = df['dst_port'].map(self.ICS_PORTS).fillna('Unknown')
        
        # 2. Traffic Metrics
        df['bytes_per_packet'] = df['bytes'] / (df['packets'] + 1)
        df['packets_per_second'] = df['packets'] / (df['duration'] + 1)
        df['bytes_per_second'] = df['bytes'] / (df['duration'] + 1)
        
        # 3. Time Features
        if 'timestamp' in df.columns:
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
            df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        
        # 4. Port Categories
        df['is_high_port'] = (df['dst_port'] > 10000).astype(int)
        df['is_well_known'] = (df['dst_port'] < 1024).astype(int)
        
        # 5. Protocol
        df['is_tcp'] = (df['protocol'].str.upper() == 'TCP').astype(int)
        df['is_udp'] = (df['protocol'].str.upper() == 'UDP').astype(int)
        
        # 6. Connection Diversity
        src_dst_count = df.groupby('src_ip')['dst_ip'].nunique()
        df['unique_destinations'] = df['src_ip'].map(src_dst_count)
        
        return df
    
    def get_statistics(self) -> dict:
        """Get data statistics"""
        if self.data is None:
            return {}
        
        stats = {
            'total_flows': len(self.data),
            'unique_sources': self.data['src_ip'].nunique() if 'src_ip' in self.data.columns else 0,
            'unique_destinations': self.data['dst_ip'].nunique() if 'dst_ip' in self.data.columns else 0,
            'ics_flows': int(self.data['is_ics_protocol'].sum()) if 'is_ics_protocol' in self.data.columns else 0,
            'total_bytes': int(self.data['bytes'].sum()) if 'bytes' in self.data.columns else 0,
            'avg_bytes_per_flow': float(self.data['bytes'].mean()) if 'bytes' in self.data.columns else 0
        }
        
        if 'timestamp' in self.data.columns:
            stats['time_range'] = {
                'start': str(self.data['timestamp'].min()),
                'end': str(self.data['timestamp'].max())
            }
        
        return stats
