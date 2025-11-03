"""
Real-time Network Anomaly Detection
Chạy liên tục, phân tích traffic theo thời gian thực
"""
import time
import logging
from collections import deque
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from src.anomaly_detector import ICSAnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RealtimeDetector:
    """
    Real-time network monitoring với sliding window
    """
    
    def __init__(self, model_path: str, window_size: int = 300):
        """
        Args:
            model_path: Path to trained model
            window_size: Analysis window (seconds)
        """
        self.detector = ICSAnomalyDetector()
        self.detector.load_model(model_path)
        
        self.window_size = window_size
        self.packet_buffer = deque(maxlen=10000)  # Keep last 10k packets
        
        self.alert_callback = None
        self.stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'alerts_sent': 0
        }
        
    def start_monitoring(self, interface: str = None, 
                        bpf_filter: str = None):
        """
        Start real-time packet capture
        
        Args:
            interface: Network interface (e.g., 'eth0', 'Wi-Fi')
            bpf_filter: BPF filter (e.g., 'tcp port 502 or tcp port 102')
        """
        logger.info("🚀 Starting real-time monitoring...")
        logger.info(f"   Interface: {interface or 'default'}")
        logger.info(f"   Filter: {bpf_filter or 'all traffic'}")
        logger.info(f"   Window size: {self.window_size}s")
        
        try:
            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=self._process_packet,
                store=False
            )
        except KeyboardInterrupt:
            logger.info("\n⏹️  Monitoring stopped by user")
            self._print_stats()
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            
    def _process_packet(self, packet):
        """Process individual packet"""
        try:
            if not packet.haslayer(IP):
                return
            
            # Extract packet info
            ip_layer = packet[IP]
            timestamp = time.time()
            
            packet_data = {
                'timestamp': timestamp,
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': 'ICMP',
                'bytes': len(packet),
                'src_port': 0,
                'dst_port': 0
            }
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_data['protocol'] = 'TCP'
                packet_data['src_port'] = tcp_layer.sport
                packet_data['dst_port'] = tcp_layer.dport
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_data['protocol'] = 'UDP'
                packet_data['src_port'] = udp_layer.sport
                packet_data['dst_port'] = udp_layer.dport
            
            # Add to buffer
            self.packet_buffer.append(packet_data)
            self.stats['packets_processed'] += 1
            
            # Analyze every N packets or every M seconds
            if self.stats['packets_processed'] % 100 == 0:
                self._analyze_buffer()
                
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
    
    def _analyze_buffer(self):
        """Analyze buffered packets"""
        if len(self.packet_buffer) < 10:
            return
        
        try:
            # Convert to DataFrame
            df = pd.DataFrame(list(self.packet_buffer))
            
            # Filter to analysis window
            current_time = time.time()
            cutoff_time = current_time - self.window_size
            df = df[df['timestamp'] >= cutoff_time]
            
            if len(df) < 5:
                return
            
            # Convert timestamp to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            
            # Extract features
            df = self._extract_realtime_features(df)
            
            # Detect anomalies
            results = self.detector.predict(df)
            
            n_anomalies = results['is_anomaly'].sum()
            
            if n_anomalies > 0:
                self.stats['anomalies_detected'] += n_anomalies
                self._handle_anomalies(results[results['is_anomaly'] == 1])
                
                # Print live stats
                if self.stats['packets_processed'] % 1000 == 0:
                    logger.info(
                        f"📊 Processed: {self.stats['packets_processed']} | "
                        f"Anomalies: {self.stats['anomalies_detected']} | "
                        f"Buffer: {len(self.packet_buffer)}"
                    )
                    
        except Exception as e:
            logger.debug(f"Error analyzing buffer: {e}")
    
    def _extract_realtime_features(self, df):
        """Extract features for real-time analysis"""
        # Add required features
        df['packets'] = 1
        df['duration'] = 1.0
        
        # ICS protocol detection
        ICS_PORTS = {102, 502, 2404, 20000, 44818, 47808, 4840}
        df['is_ics_protocol'] = df['dst_port'].isin(ICS_PORTS).astype(int)
        
        # Traffic metrics
        df['bytes_per_packet'] = df['bytes']
        df['packets_per_second'] = 1
        df['bytes_per_second'] = df['bytes']
        
        # Time features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        
        # Port categories
        df['is_high_port'] = (df['dst_port'] > 10000).astype(int)
        df['is_well_known'] = (df['dst_port'] < 1024).astype(int)
        
        # Protocol
        df['is_tcp'] = (df['protocol'] == 'TCP').astype(int)
        df['is_udp'] = (df['protocol'] == 'UDP').astype(int)
        
        # Connection diversity
        src_dst_count = df.groupby('src_ip')['dst_ip'].nunique()
        df['unique_destinations'] = df['src_ip'].map(src_dst_count)
        
        return df
    
    def _handle_anomalies(self, anomalies_df):
        """Handle detected anomalies"""
        for _, row in anomalies_df.iterrows():
            alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'dst_port': row['dst_port'],
                'anomaly_score': row['anomaly_score'],
                'severity': self._classify_severity(row['anomaly_score'])
            }
            
            # Log alert
            logger.warning(
                f"🚨 ANOMALY: {alert['src_ip']} → {alert['dst_ip']}:{alert['dst_port']} "
                f"| Score: {alert['anomaly_score']:.3f} | Severity: {alert['severity']}"
            )
            
            self.stats['alerts_sent'] += 1
            
            # Call callback if set
            if self.alert_callback:
                self.alert_callback(alert)
    
    def _classify_severity(self, score):
        """Classify anomaly severity"""
        if score < -0.7:
            return 'CRITICAL'
        elif score < -0.5:
            return 'HIGH'
        elif score < -0.3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback
    
    def _print_stats(self):
        """Print monitoring statistics"""
        logger.info("\n" + "="*60)
        logger.info("📊 MONITORING STATISTICS")
        logger.info("="*60)
        logger.info(f"Packets processed: {self.stats['packets_processed']:,}")
        logger.info(f"Anomalies detected: {self.stats['anomalies_detected']}")
        logger.info(f"Alerts sent: {self.stats['alerts_sent']}")
        
        if self.stats['packets_processed'] > 0:
            anomaly_rate = (self.stats['anomalies_detected'] / 
                          self.stats['packets_processed'] * 100)
            logger.info(f"Anomaly rate: {anomaly_rate:.2f}%")


# Example usage
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time Network Monitoring')
    parser.add_argument('--model', type=str, required=True,
                       help='Path to trained model')
    parser.add_argument('--interface', type=str, default=None,
                       help='Network interface to monitor')
    parser.add_argument('--filter', type=str, default=None,
                       help='BPF filter (e.g., "tcp port 502")')
    parser.add_argument('--window', type=int, default=300,
                       help='Analysis window size (seconds)')
    args = parser.parse_args()
    
    # Initialize detector
    detector = RealtimeDetector(
        model_path=args.model,
        window_size=args.window
    )
    
    # Start monitoring
    detector.start_monitoring(
        interface=args.interface,
        bpf_filter=args.filter
    )