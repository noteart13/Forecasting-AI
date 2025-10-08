"""
Network Data Loader for ICS/SCADA Anomaly Detection
Đọc NetFlow và packet metadata từ tools như Wireshark, Zeek, nfdump, etc.
Hỗ trợ file .pcap từ Wireshark
"""
import pandas as pd
import numpy as np
import logging
import os
from datetime import datetime
from typing import Optional, Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Install with: pip install scapy")

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logger.warning("PyShark not available. Install with: pip install pyshark")


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
        Hỗ trợ CSV, Excel, JSON, PCAP
        
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
            if self.file_path.endswith('.pcap') or self.file_path.endswith('.pcapng'):
                self.data = self._load_pcap()
            elif self.file_path.endswith('.csv'):
                self.data = pd.read_csv(self.file_path)
            elif self.file_path.endswith(('.xlsx', '.xls')):
                self.data = pd.read_excel(self.file_path)
            elif self.file_path.endswith('.json'):
                self.data = pd.read_json(self.file_path)
            else:
                raise ValueError("Unsupported format. Use CSV, Excel, JSON, or PCAP")
            
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
        
        # Convert timestamp - try multiple formats
        if 'timestamp' in df.columns:
            # Try Unix timestamp first
            try:
                # Convert to float first to handle large numbers
                df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
                # Check if timestamp is reasonable (not too large)
                if df['timestamp'].max() > 2e9:  # Year 2033+, likely microseconds or nanoseconds
                    logger.warning("Timestamp appears to be in future, adjusting...")
                    df['timestamp'] = df['timestamp'] / 1000  # Convert from milliseconds
                df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            except Exception as e:
                # Try parsing as datetime string
                try:
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                except:
                    # If all fail, create dummy datetime
                    logger.warning("Cannot parse timestamp, using sequential datetime")
                    df['timestamp'] = pd.date_range(start='2024-01-01', periods=len(df), freq='1min')
            
            df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Fill missing (but not timestamp)
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)
        
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
        if 'timestamp' in df.columns and pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
            df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        else:
            # Default values if timestamp not available
            df['hour'] = 12
            df['day_of_week'] = 2
            df['is_night'] = 0
            df['is_weekend'] = 0
        
        # 4. Port Categories
        df['is_high_port'] = (df['dst_port'] > 10000).astype(int)
        df['is_well_known'] = (df['dst_port'] < 1024).astype(int)
        
        # 5. Protocol
        # Check if protocol column exists, if not create default
        if 'protocol' not in df.columns:
            logger.warning("⚠️  'protocol' column not found, creating default 'TCP' protocol")
            df['protocol'] = 'TCP'
        
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
    
    def _load_pcap(self) -> pd.DataFrame:
        """
        Load và parse file .pcap/.pcapng từ Wireshark
        Chuyển đổi packets thành flow records
        """
        if not SCAPY_AVAILABLE and not PYSHARK_AVAILABLE:
            raise ImportError("Neither Scapy nor PyShark available. Install at least one: pip install scapy or pip install pyshark")
        
        logger.info(f"📦 Loading PCAP file: {self.file_path}")
        
        # Try PyShark first (better for complex protocols)
        if PYSHARK_AVAILABLE:
            try:
                return self._load_pcap_pyshark()
            except Exception as e:
                logger.warning(f"PyShark failed: {e}, trying Scapy...")
        
        # Fallback to Scapy
        if SCAPY_AVAILABLE:
            return self._load_pcap_scapy()
        else:
            raise ImportError("No PCAP parsing library available")
    
    def _load_pcap_pyshark(self) -> pd.DataFrame:
        """Load PCAP using PyShark"""
        flows = []
        
        try:
            cap = pyshark.FileCapture(self.file_path)
            
            for packet in cap:
                try:
                    # Extract basic packet info
                    timestamp = float(packet.sniff_timestamp)
                    length = int(packet.length)
                    
                    # Check if packet has IP layer
                    if hasattr(packet, 'ip'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        protocol = packet.ip.proto
                        
                        # Extract ports if available
                        src_port = None
                        dst_port = None
                        
                        if hasattr(packet, 'tcp'):
                            src_port = int(packet.tcp.srcport)
                            dst_port = int(packet.tcp.dstport)
                            protocol_name = 'TCP'
                        elif hasattr(packet, 'udp'):
                            src_port = int(packet.udp.srcport)
                            dst_port = int(packet.udp.dstport)
                            protocol_name = 'UDP'
                        elif hasattr(packet, 'icmp'):
                            protocol_name = 'ICMP'
                        else:
                            protocol_name = f'IP_{protocol}'
                        
                        flows.append({
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port or 0,
                            'dst_port': dst_port or 0,
                            'protocol': protocol_name,
                            'bytes': length,
                            'packets': 1,
                            'duration': 0  # Will be calculated later
                        })
                        
                except Exception as e:
                    logger.debug(f"Skipping packet: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error reading PCAP with PyShark: {e}")
            raise
        
        if not flows:
            logger.warning("No valid packets found in PCAP file")
            return pd.DataFrame()
        
        df = pd.DataFrame(flows)
        
        # Convert timestamp to datetime - handle various formats
        try:
            df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
            # Check if reasonable timestamp (after year 2033 means likely wrong scale)
            if df['timestamp'].max() > 2e9:
                logger.warning("Timestamp appears to be in microseconds/milliseconds, adjusting...")
                df['timestamp'] = df['timestamp'] / 1000
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
        except Exception as e:
            logger.warning(f"Timestamp conversion failed: {e}, using sequential time")
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Aggregate flows (group by 5-tuple)
        df = self._aggregate_flows(df)
        
        logger.info(f"✅ Parsed {len(df)} flows from PCAP")
        return df
    
    def _load_pcap_scapy(self) -> pd.DataFrame:
        """Load PCAP using Scapy"""
        flows = []
        
        try:
            packets = rdpcap(self.file_path)
            
            for packet in packets:
                try:
                    # Extract basic packet info
                    timestamp = packet.time
                    length = len(packet)
                    
                    # Check if packet has IP layer
                    if packet.haslayer(IP):
                        ip_layer = packet[IP]
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        protocol = ip_layer.proto
                        
                        # Extract ports if available
                        src_port = None
                        dst_port = None
                        
                        if packet.haslayer(TCP):
                            tcp_layer = packet[TCP]
                            src_port = tcp_layer.sport
                            dst_port = tcp_layer.dport
                            protocol_name = 'TCP'
                        elif packet.haslayer(UDP):
                            udp_layer = packet[UDP]
                            src_port = udp_layer.sport
                            dst_port = udp_layer.dport
                            protocol_name = 'UDP'
                        elif packet.haslayer(ICMP):
                            protocol_name = 'ICMP'
                        else:
                            protocol_name = f'IP_{protocol}'
                        
                        flows.append({
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port or 0,
                            'dst_port': dst_port or 0,
                            'protocol': protocol_name,
                            'bytes': length,
                            'packets': 1,
                            'duration': 0  # Will be calculated later
                        })
                        
                except Exception as e:
                    logger.debug(f"Skipping packet: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error reading PCAP with Scapy: {e}")
            raise
        
        if not flows:
            logger.warning("No valid packets found in PCAP file")
            return pd.DataFrame()
        
        df = pd.DataFrame(flows)
        
        # Convert timestamp to datetime - handle various formats
        try:
            df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
            # Check if reasonable timestamp (after year 2033 means likely wrong scale)
            if df['timestamp'].max() > 2e9:
                logger.warning("Timestamp appears to be in microseconds/milliseconds, adjusting...")
                df['timestamp'] = df['timestamp'] / 1000
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
        except Exception as e:
            logger.warning(f"Timestamp conversion failed: {e}, using sequential time")
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Aggregate flows (group by 5-tuple)
        df = self._aggregate_flows(df)
        
        logger.info(f"✅ Parsed {len(df)} flows from PCAP")
        return df
    
    def _aggregate_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregate packets into flows based on 5-tuple
        (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        logger.info("🔄 Aggregating packets into flows...")
        
        # Group by 5-tuple
        flow_groups = df.groupby(['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'])
        
        aggregated_flows = []
        
        for (src_ip, dst_ip, src_port, dst_port, protocol), group in flow_groups:
            # Calculate flow metrics
            start_time = group['timestamp'].min()
            end_time = group['timestamp'].max()
            duration = (end_time - start_time).total_seconds()
            
            # If duration is 0 (single packet), set to 1 second
            if duration == 0:
                duration = 1.0
            
            aggregated_flows.append({
                'timestamp': start_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'bytes': group['bytes'].sum(),
                'packets': group['packets'].sum(),
                'duration': duration
            })
        
        result_df = pd.DataFrame(aggregated_flows)
        logger.info(f"✅ Aggregated into {len(result_df)} flows")
        
        return result_df
