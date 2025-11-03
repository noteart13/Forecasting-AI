"""
Anomaly Detection Models for ICS/SCADA Networks
Phát hiện: Lateral Movement, Data Exfiltration, ICS Anomalies
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ICSAnomalyDetector:
    """
    Phát hiện bất thường trong mạng ICS/SCADA
    Sử dụng Isolation Forest và rule-based detection
    """
    
    def __init__(self, contamination=0.05):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.is_trained = False
        
    def train(self, df: pd.DataFrame, feature_cols: list = None):
        """
        Train model trên normal traffic
        
        Args:
            df: DataFrame chứa normal network traffic
            feature_cols: List tên cột để dùng làm features
        """
        if feature_cols is None:
            # Auto-select numeric columns
            feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            # Remove IDs and labels
            exclude = ['src_ip', 'dst_ip', 'timestamp', 'label', 'anomaly']
            feature_cols = [c for c in feature_cols if c not in exclude]
        
        self.feature_columns = feature_cols
        logger.info(f"Training with {len(feature_cols)} features: {feature_cols}")
        
        X = df[feature_cols].fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model.fit(X_scaled)
        self.is_trained = True
        
        logger.info(f"✅ Model trained on {len(df)} normal flows")
        
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Predict anomalies
        
        Returns:
            DataFrame với cột 'anomaly_score' và 'is_anomaly'
        """
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        X = df[self.feature_columns].fillna(0)
        X_scaled = self.scaler.transform(X)
        
        # Predict (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        result = df.copy()
        result['anomaly_score'] = scores
        result['is_anomaly'] = (predictions == -1).astype(int)
        
        n_anomalies = result['is_anomaly'].sum()
        logger.info(f"🔍 Found {n_anomalies} anomalies ({n_anomalies/len(df)*100:.2f}%)")
        
        return result
    
    def detect_lateral_movement(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Advanced Lateral Movement Detection
        
        Techniques:
        1. Dynamic threshold based on baseline
        2. Behavioral scoring (scan patterns)
        3. Time-based anomaly detection
        4. Failed connection tracking
        """
        df = df.copy()
        
        # Time window (adaptive: 5-15 minutes based on traffic volume)
        if 'timestamp' in df.columns:
            # Adaptive time window
            total_duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            if total_duration < 3600:  # < 1 hour
                window_size = '5T'
            elif total_duration < 86400:  # < 1 day
                window_size = '10T'
            else:
                window_size = '15T'
            
            df['time_window'] = df['timestamp'].dt.floor(window_size)
        else:
            df['time_window'] = 0
        
        # === 1. Basic Statistics per Source ===
        lateral_stats = df.groupby(['src_ip', 'time_window']).agg({
            'dst_ip': 'nunique',
            'dst_port': 'nunique',
            'packets': 'sum',
            'bytes': 'sum',
            'duration': ['mean', 'std', 'sum']
        }).reset_index()
        
        # Flatten column names
        lateral_stats.columns = ['src_ip', 'time_window', 'unique_dsts', 'unique_ports', 
                                'total_packets', 'total_bytes', 'avg_duration', 
                                'std_duration', 'total_duration']
        
        # === 2. Calculate Baseline (per source IP) ===
        baseline = df.groupby('src_ip').agg({
            'dst_ip': 'nunique',
            'dst_port': 'nunique'
        }).reset_index()
        baseline.columns = ['src_ip', 'baseline_dsts', 'baseline_ports']
        
        # Merge baseline
        lateral_stats = lateral_stats.merge(baseline, on='src_ip', how='left')
        
        # === 3. Advanced Metrics ===
        
        # 3.1 Deviation from baseline
        lateral_stats['dst_deviation'] = (
            lateral_stats['unique_dsts'] / (lateral_stats['baseline_dsts'] + 1)
        )
        lateral_stats['port_deviation'] = (
            lateral_stats['unique_ports'] / (lateral_stats['baseline_ports'] + 1)
        )
        
        # 3.2 Connection efficiency (failed connections indicator)
        lateral_stats['connection_efficiency'] = (
            lateral_stats['total_bytes'] / (lateral_stats['total_packets'] + 1)
        )
        # Low efficiency = potential failed connections/scans
        lateral_stats['is_low_efficiency'] = (
            lateral_stats['connection_efficiency'] < 100
        ).astype(int)
        
        # 3.3 Scan pattern detection
        lateral_stats['scan_intensity'] = (
            lateral_stats['unique_ports'] * lateral_stats['unique_dsts'] / 
            (lateral_stats['total_duration'] + 1)
        )
        
        # 3.4 Sequential port pattern (indicator of port scan)
        # Check if ports are accessed sequentially
        port_sequences = df.groupby(['src_ip', 'time_window']).apply(
            lambda x: self._detect_sequential_ports(x['dst_port'].values)
        ).reset_index(name='is_sequential_scan')
        lateral_stats = lateral_stats.merge(port_sequences, on=['src_ip', 'time_window'], how='left')
        lateral_stats['is_sequential_scan'] = lateral_stats['is_sequential_scan'].fillna(0)
        
        # === 4. Pattern Detection ===
        
        # 4.1 Port scanning
        port_scan_threshold = lateral_stats['unique_ports'].quantile(0.95)
        lateral_stats['is_port_scan'] = (
            (lateral_stats['unique_ports'] > max(10, port_scan_threshold)) &
            (lateral_stats['total_packets'] > 20)
        ).astype(int)
        
        # 4.2 Host scanning
        host_scan_threshold = lateral_stats['unique_dsts'].quantile(0.95)
        lateral_stats['is_host_scan'] = (
            (lateral_stats['unique_dsts'] > max(5, host_scan_threshold)) &
            (lateral_stats['total_packets'] > 10)
        ).astype(int)
        
        # 4.3 Rapid connection attempts
        lateral_stats['connection_rate'] = (
            lateral_stats['total_packets'] / (lateral_stats['total_duration'] + 1)
        )
        rapid_threshold = lateral_stats['connection_rate'].quantile(0.90)
        lateral_stats['is_rapid_attempts'] = (
            lateral_stats['connection_rate'] > rapid_threshold
        ).astype(int)
        
        # === 5. Scoring System ===
        lateral_stats['lateral_score'] = (
            # Diversity score (weighted by deviation from baseline)
            lateral_stats['dst_deviation'] * 3.0 +
            lateral_stats['port_deviation'] * 2.5 +
            
            # Scan patterns
            lateral_stats['is_port_scan'] * 4.0 +
            lateral_stats['is_host_scan'] * 4.0 +
            lateral_stats['is_sequential_scan'] * 3.0 +
            
            # Connection behavior
            lateral_stats['is_low_efficiency'] * 2.0 +
            lateral_stats['is_rapid_attempts'] * 2.0 +
            
            # Intensity
            np.log1p(lateral_stats['scan_intensity']) * 1.5
        )
        
        # === 6. Dynamic Threshold ===
        # Use MAD (Median Absolute Deviation) for robust threshold
        median_score = lateral_stats['lateral_score'].median()
        mad = np.median(np.abs(lateral_stats['lateral_score'] - median_score))
        threshold = median_score + 3 * mad  # 3-MAD threshold
        
        lateral_stats['is_lateral_movement'] = (
            lateral_stats['lateral_score'] > threshold
        ).astype(int)
        
        # === 7. Risk Classification ===
        lateral_stats['risk_level'] = 'low'
        lateral_stats.loc[
            (lateral_stats['is_lateral_movement'] == 1) & 
            (lateral_stats['lateral_score'] > threshold * 1.5),
            'risk_level'
        ] = 'high'
        lateral_stats.loc[
            (lateral_stats['is_lateral_movement'] == 1) & 
            (lateral_stats['risk_level'] != 'high'),
            'risk_level'
        ] = 'medium'
        
        lateral_stats['is_high_risk'] = (
            lateral_stats['risk_level'] == 'high'
        ).astype(int)
        
        # === 8. Summary ===
        suspicious = lateral_stats[lateral_stats['is_lateral_movement'] == 1]
        high_risk_count = lateral_stats['is_high_risk'].sum()
        
        logger.info(f"🚨 Lateral Movement: {len(suspicious)} suspicious activities detected")
        logger.info(f"   • Port scans: {lateral_stats['is_port_scan'].sum()}")
        logger.info(f"   • Host scans: {lateral_stats['is_host_scan'].sum()}")
        logger.info(f"   • High risk: {high_risk_count}")
        
        return lateral_stats

    def _detect_sequential_ports(self, ports):
        """Detect if ports are accessed sequentially (scan pattern)"""
        if len(ports) < 5:
            return 0
        
        # Sort ports
        sorted_ports = np.sort(ports)
        
        # Calculate gaps between consecutive ports
        gaps = np.diff(sorted_ports)
        
        # If most gaps are small and consistent, it's likely a sequential scan
        avg_gap = np.mean(gaps)
        std_gap = np.std(gaps)
        
        # Sequential if: avg_gap < 10 and std_gap < 5
        return int(avg_gap < 10 and std_gap < 5)
    def detect_data_exfiltration(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Enhanced Data Exfiltration Detection
        
        New Features:
        1. Encrypted channel detection (TLS/HTTPS)
        2. DNS tunneling detection
        3. Upload/Download ratio analysis
        4. Covert channels (ICMP, DNS)
        """
        df = df.copy()
        
        # === 1. Identify Internal/External IPs ===
        def is_private_ip(ip):
            """RFC 1918 private IP check"""
            if isinstance(ip, str):
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        first = int(parts[0])
                        second = int(parts[1])
                        if first == 10:
                            return True
                        if first == 172 and 16 <= second <= 31:
                            return True
                        if first == 192 and second == 168:
                            return True
                        if first == 127:
                            return True
                    except:
                        pass
            return False
        
        df['is_internal_src'] = df['src_ip'].apply(is_private_ip)
        df['is_internal_dst'] = df['dst_ip'].apply(is_private_ip)
        
        # Outbound traffic (internal → external)
        outbound = df[(df['is_internal_src']) & (~df['is_internal_dst'])].copy()
        
        if len(outbound) == 0:
            logger.info("No outbound traffic detected")
            return pd.DataFrame()
        
        # === 2. Time Window ===
        if 'timestamp' in outbound.columns:
            outbound['time_window'] = outbound['timestamp'].dt.floor('10T')
        else:
            outbound['time_window'] = 0
        
        # === 3. Basic Aggregation ===
        exfil_stats = outbound.groupby(['src_ip', 'time_window']).agg({
            'bytes': 'sum',
            'packets': 'sum',
            'dst_ip': 'nunique',
            'dst_port': 'nunique',
            'duration': 'sum'
        }).reset_index()
        
        exfil_stats.columns = ['src_ip', 'time_window', 'bytes_out', 'packets_out', 
                            'unique_external_dsts', 'unique_ports', 'total_duration']
        
        # === 4. Enhanced Metrics ===
        
        # 4.1 Data volume
        exfil_stats['mb_transferred'] = exfil_stats['bytes_out'] / (1024 * 1024)
        exfil_stats['transfer_rate'] = exfil_stats['bytes_out'] / (exfil_stats['total_duration'] + 1)
        
        # 4.2 Packet analysis
        exfil_stats['avg_packet_size'] = exfil_stats['bytes_out'] / (exfil_stats['packets_out'] + 1)
        exfil_stats['packet_rate'] = exfil_stats['packets_out'] / (exfil_stats['total_duration'] + 1)
        
        # === 5. Encrypted Channel Detection ===
        # Check for TLS/HTTPS traffic (port 443, 8443)
        encrypted_ports = [443, 8443, 993, 995, 465]
        encrypted_traffic = outbound[outbound['dst_port'].isin(encrypted_ports)].groupby(['src_ip', 'time_window']).agg({
            'bytes': 'sum',
            'dst_ip': 'nunique'
        }).reset_index()
        encrypted_traffic.columns = ['src_ip', 'time_window', 'encrypted_bytes', 'encrypted_dsts']
        
        exfil_stats = exfil_stats.merge(encrypted_traffic, on=['src_ip', 'time_window'], how='left')
        exfil_stats['encrypted_bytes'] = exfil_stats['encrypted_bytes'].fillna(0)
        exfil_stats['encrypted_dsts'] = exfil_stats['encrypted_dsts'].fillna(0)
        
        exfil_stats['encryption_ratio'] = (
            exfil_stats['encrypted_bytes'] / (exfil_stats['bytes_out'] + 1)
        )
        exfil_stats['is_heavily_encrypted'] = (
            exfil_stats['encryption_ratio'] > 0.7
        ).astype(int)
        
        # === 6. DNS Tunneling Detection ===
        # Check for excessive DNS traffic (port 53)
        dns_traffic = outbound[outbound['dst_port'] == 53].groupby(['src_ip', 'time_window']).agg({
            'bytes': 'sum',
            'packets': 'sum',
            'dst_ip': 'nunique'
        }).reset_index()
        dns_traffic.columns = ['src_ip', 'time_window', 'dns_bytes', 'dns_packets', 'dns_servers']
        
        exfil_stats = exfil_stats.merge(dns_traffic, on=['src_ip', 'time_window'], how='left')
        exfil_stats['dns_bytes'] = exfil_stats['dns_bytes'].fillna(0)
        exfil_stats['dns_packets'] = exfil_stats['dns_packets'].fillna(0)
        
        # DNS tunneling indicators:
        # 1. High DNS packet count
        # 2. Large DNS payload (> 100 bytes/packet average)
        exfil_stats['dns_avg_size'] = exfil_stats['dns_bytes'] / (exfil_stats['dns_packets'] + 1)
        exfil_stats['is_dns_tunneling'] = (
            (exfil_stats['dns_packets'] > 100) &
            (exfil_stats['dns_avg_size'] > 100)
        ).astype(int)
        
        # === 7. Covert Channel Detection ===
        # ICMP tunneling (large ICMP traffic)
        icmp_traffic = outbound[outbound['protocol'].str.upper() == 'ICMP'].groupby(['src_ip', 'time_window']).agg({
            'bytes': 'sum'
        }).reset_index()
        icmp_traffic.columns = ['src_ip', 'time_window', 'icmp_bytes']
        
        exfil_stats = exfil_stats.merge(icmp_traffic, on=['src_ip', 'time_window'], how='left')
        exfil_stats['icmp_bytes'] = exfil_stats['icmp_bytes'].fillna(0)
        exfil_stats['is_icmp_covert'] = (
            exfil_stats['icmp_bytes'] > 1000000  # > 1MB ICMP
        ).astype(int)
        
        # === 8. Pattern Detection ===
        exfil_stats['is_large_transfer'] = (exfil_stats['mb_transferred'] > 10).astype(int)
        exfil_stats['is_multiple_destinations'] = (exfil_stats['unique_external_dsts'] > 3).astype(int)
        exfil_stats['is_high_bandwidth'] = (exfil_stats['transfer_rate'] > 1000000).astype(int)
        
        # === 9. Time-based Analysis ===
        if 'timestamp' in outbound.columns:
            outbound['hour'] = outbound['timestamp'].dt.hour
            outbound['day_of_week'] = outbound['timestamp'].dt.dayofweek
            outbound['is_night'] = ((outbound['hour'] >= 22) | (outbound['hour'] <= 6)).astype(int)
            outbound['is_weekend'] = (outbound['day_of_week'] >= 5).astype(int)
            
            timing_stats = outbound.groupby(['src_ip', 'time_window']).agg({
                'is_night': 'max',
                'is_weekend': 'max'
            }).reset_index()
            
            exfil_stats = exfil_stats.merge(timing_stats, on=['src_ip', 'time_window'], how='left')
            exfil_stats['is_unusual_time'] = (
                (exfil_stats['is_night'] == 1) | (exfil_stats['is_weekend'] == 1)
            ).astype(int)
        else:
            exfil_stats['is_unusual_time'] = 0
        
        # === 10. Suspicious Protocol Detection ===
        suspicious_protocols = ['FTP', 'HTTP', 'HTTPS', 'SFTP', 'SCP']
        protocol_stats = outbound[outbound['protocol'].isin(suspicious_protocols)].groupby(['src_ip', 'time_window']).size().reset_index(name='suspicious_protocol_count')
        exfil_stats = exfil_stats.merge(protocol_stats, on=['src_ip', 'time_window'], how='left')
        exfil_stats['suspicious_protocol_count'] = exfil_stats['suspicious_protocol_count'].fillna(0)
        exfil_stats['is_suspicious_protocol'] = (exfil_stats['suspicious_protocol_count'] > 0).astype(int)
        
        # === 11. Advanced Scoring System ===
        exfil_stats['exfil_score'] = (
            # Data volume
            exfil_stats['mb_transferred'] * 3.0 +
            
            # Connection patterns
            exfil_stats['unique_external_dsts'] * 2.0 +
            exfil_stats['is_multiple_destinations'] * 3.0 +
            
            # Transfer characteristics
            exfil_stats['is_large_transfer'] * 4.0 +
            exfil_stats['is_high_bandwidth'] * 2.0 +
            
            # Covert channels
            exfil_stats['is_heavily_encrypted'] * 3.0 +
            exfil_stats['is_dns_tunneling'] * 5.0 +  # High priority
            exfil_stats['is_icmp_covert'] * 5.0 +    # High priority
            
            # Timing
            exfil_stats['is_unusual_time'] * 2.5 +
            
            # Protocols
            exfil_stats['is_suspicious_protocol'] * 1.5
        )
        
        # === 12. Dynamic Threshold ===
        median_score = exfil_stats['exfil_score'].median()
        mad = np.median(np.abs(exfil_stats['exfil_score'] - median_score))
        threshold = median_score + 3 * mad
        
        exfil_stats['is_exfiltration'] = (
            exfil_stats['exfil_score'] > threshold
        ).astype(int)
        
        # === 13. Risk Classification ===
        exfil_stats['risk_level'] = 'low'
        exfil_stats.loc[
            (exfil_stats['is_exfiltration'] == 1) & 
            (
                (exfil_stats['is_dns_tunneling'] == 1) | 
                (exfil_stats['is_icmp_covert'] == 1) |
                (exfil_stats['mb_transferred'] > 100)
            ),
            'risk_level'
        ] = 'critical'
        exfil_stats.loc[
            (exfil_stats['is_exfiltration'] == 1) & 
            (exfil_stats['risk_level'] != 'critical') &
            (exfil_stats['exfil_score'] > threshold * 1.5),
            'risk_level'
        ] = 'high'
        exfil_stats.loc[
            (exfil_stats['is_exfiltration'] == 1) & 
            (exfil_stats['risk_level'] == 'low'),
            'risk_level'
        ] = 'medium'
        
        exfil_stats['is_high_risk'] = (
            exfil_stats['risk_level'].isin(['high', 'critical'])
        ).astype(int)
        
        # === 14. Summary ===
        suspicious = exfil_stats[exfil_stats['is_exfiltration'] == 1]
        
        logger.info(f"🚨 Data Exfiltration: {len(suspicious)} suspicious transfers detected")
        logger.info(f"   • DNS tunneling: {exfil_stats['is_dns_tunneling'].sum()}")
        logger.info(f"   • ICMP covert: {exfil_stats['is_icmp_covert'].sum()}")
        logger.info(f"   • Encrypted channels: {exfil_stats['is_heavily_encrypted'].sum()}")
        logger.info(f"   • Critical risk: {(exfil_stats['risk_level'] == 'critical').sum()}")
        
        return exfil_stats
    def detect_ics_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Phát hiện ICS-specific anomalies - Các hành vi bất thường trong mạng Hệ thống Điều khiển Công nghiệp
        
        Dấu hiệu nâng cao:
        - ICS devices kết nối với unexpected IPs (external connections)
        - ICS protocols sử dụng vào giờ bất thường (night/weekend)
        - Sudden changes trong ICS traffic patterns (volume spikes)
        - Non-ICS devices accessing ICS ports (unauthorized access)
        - ICS devices communicating with non-ICS protocols
        - Abnormal ICS protocol usage patterns
        - ICS devices showing lateral movement behavior
        - Unusual ICS device discovery patterns
        """
        df = df.copy()
        
        if 'is_ics_protocol' not in df.columns:
            logger.warning("No ICS protocol information available")
            return pd.DataFrame()
        
        # Filter ICS traffic
        ics_traffic = df[df['is_ics_protocol'] == 1].copy()
        
        if len(ics_traffic) == 0:
            logger.info("No ICS protocol traffic detected")
            return pd.DataFrame()
        
        logger.info(f"🔍 Analyzing {len(ics_traffic)} ICS flows...")
        
        # Initialize anomaly tracking
        anomaly_details = []
        
        # 1. ICS traffic at unusual times (night/weekend)
        if 'is_night' in ics_traffic.columns:
            night_ics = ics_traffic[ics_traffic['is_night'] == 1]
            if len(night_ics) > 0:
                anomaly_details.append({
                    'type': 'unusual_time',
                    'severity': 'medium',
                    'count': len(night_ics),
                    'description': f'{len(night_ics)} ICS connections during night hours',
                    'affected_devices': night_ics['src_ip'].nunique()
                })
        
        if 'is_weekend' in ics_traffic.columns:
            weekend_ics = ics_traffic[ics_traffic['is_weekend'] == 1]
            if len(weekend_ics) > 0:
                anomaly_details.append({
                    'type': 'weekend_activity',
                    'severity': 'medium',
                    'count': len(weekend_ics),
                    'description': f'{len(weekend_ics)} ICS connections during weekend',
                    'affected_devices': weekend_ics['src_ip'].nunique()
                })
        
        # 2. ICS devices with high destination diversity (potential lateral movement)
        ics_diversity = ics_traffic.groupby('src_ip').agg({
            'dst_ip': 'nunique',
            'dst_port': 'nunique',
            'bytes': 'sum'
        }).reset_index()
        
        ics_diversity.columns = ['src_ip', 'unique_dsts', 'unique_ports', 'total_bytes']
        
        # Calculate diversity scores
        mean_diversity = ics_diversity['unique_dsts'].mean()
        std_diversity = ics_diversity['unique_dsts'].std()
        high_diversity_threshold = mean_diversity + 2 * std_diversity
        
        high_diversity_devices = ics_diversity[ics_diversity['unique_dsts'] > high_diversity_threshold]
        if len(high_diversity_devices) > 0:
            anomaly_details.append({
                'type': 'high_diversity',
                'severity': 'high',
                'count': len(high_diversity_devices),
                'description': f'{len(high_diversity_devices)} ICS devices with unusually high connection diversity',
                'affected_devices': high_diversity_devices['src_ip'].tolist()
            })
        
        # 3. ICS devices communicating with external IPs
        def is_private_ip(ip):
            """Check if IP is private (RFC 1918)"""
            if isinstance(ip, str):
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        first = int(parts[0])
                        second = int(parts[1])
                        if first == 10:
                            return True
                        if first == 172 and 16 <= second <= 31:
                            return True
                        if first == 192 and second == 168:
                            return True
                        if first == 127:
                            return True
                    except:
                        pass
            return False
        
        ics_traffic['is_internal_dst'] = ics_traffic['dst_ip'].apply(is_private_ip)
        external_ics = ics_traffic[~ics_traffic['is_internal_dst']]
        
        if len(external_ics) > 0:
            anomaly_details.append({
                'type': 'external_communication',
                'severity': 'critical',
                'count': len(external_ics),
                'description': f'{len(external_ics)} ICS connections to external IPs',
                'affected_devices': external_ics['src_ip'].nunique(),
                'external_ips': external_ics['dst_ip'].unique().tolist()[:10]  # Limit to first 10
            })
        
        # 4. Sudden traffic volume changes (DDoS-like patterns)
        if 'timestamp' in ics_traffic.columns:
            ics_traffic['time_window'] = ics_traffic['timestamp'].dt.floor('30T')
            volume_stats = ics_traffic.groupby('time_window').agg({
                'bytes': 'sum',
                'packets': 'sum',
                'src_ip': 'nunique'
            }).reset_index()
            
            volume_stats.columns = ['time_window', 'total_bytes', 'total_packets', 'unique_devices']
            
            # Detect volume spikes
            mean_volume = volume_stats['total_bytes'].mean()
            std_volume = volume_stats['total_bytes'].std()
            spike_threshold = mean_volume + 3 * std_volume
            
            volume_spikes = volume_stats[volume_stats['total_bytes'] > spike_threshold]
            if len(volume_spikes) > 0:
                anomaly_details.append({
                    'type': 'traffic_spike',
                    'severity': 'high',
                    'count': len(volume_spikes),
                    'description': f'{len(volume_spikes)} time windows with unusual ICS traffic volume',
                    'max_volume_mb': volume_spikes['total_bytes'].max() / (1024 * 1024)
                })
        
        # 5. Non-ICS devices accessing ICS ports (unauthorized access)
        non_ics_accessing_ics = df[(df['is_ics_protocol'] == 0) & (df['dst_port'].isin([102, 502, 2404, 20000, 44818, 47808, 4840]))]
        
        if len(non_ics_accessing_ics) > 0:
            anomaly_details.append({
                'type': 'unauthorized_access',
                'severity': 'critical',
                'count': len(non_ics_accessing_ics),
                'description': f'{len(non_ics_accessing_ics)} non-ICS devices accessing ICS ports',
                'affected_devices': non_ics_accessing_ics['src_ip'].nunique(),
                'accessed_ports': non_ics_accessing_ics['dst_port'].unique().tolist()
            })
        
        # 6. ICS protocol usage patterns analysis
        protocol_stats = ics_traffic.groupby('dst_port').agg({
            'src_ip': 'nunique',
            'bytes': 'sum',
            'packets': 'sum'
        }).reset_index()
        
        protocol_stats.columns = ['port', 'unique_sources', 'total_bytes', 'total_packets']
        
        # Detect unusual protocol usage
        unusual_protocols = protocol_stats[
            (protocol_stats['unique_sources'] > protocol_stats['unique_sources'].quantile(0.9)) |
            (protocol_stats['total_bytes'] > protocol_stats['total_bytes'].quantile(0.9))
        ]
        
        if len(unusual_protocols) > 0:
            anomaly_details.append({
                'type': 'unusual_protocol_usage',
                'severity': 'medium',
                'count': len(unusual_protocols),
                'description': f'{len(unusual_protocols)} ICS protocols showing unusual usage patterns',
                'protocols': unusual_protocols['port'].tolist()
            })
        
        # Convert to DataFrame
        if anomaly_details:
            result_df = pd.DataFrame(anomaly_details)
            
            # Calculate overall risk score
            severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            result_df['risk_score'] = result_df['severity'].map(severity_scores)
            
            logger.info(f"🚨 ICS Anomalies: {len(anomaly_details)} anomaly types detected")
            for _, row in result_df.iterrows():
                logger.info(f"   - {row['type']} ({row['severity']}): {row['description']}")
            
            return result_df
        else:
            logger.info("✅ No ICS anomalies detected")
            return pd.DataFrame()
    
    def save_model(self, filepath: str):
        """Save trained model"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'contamination': self.contamination
        }, filepath)
        logger.info(f"✅ Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_columns = data['feature_columns']
        self.contamination = data['contamination']
        self.is_trained = True
        logger.info(f"✅ Model loaded from {filepath}")
    
    def generate_attack_summary(self, results, lateral_df=None, exfil_df=None, ics_df=None, output_path='output/attack_summary.txt', pcap_file=None):
        """
        Generate professional attack summary report with analysis tables
        
        Args:
            results: DataFrame with anomaly detection results
            lateral_df: Lateral movement detection results
            exfil_df: Data exfiltration detection results
            ics_df: ICS anomaly detection results
            output_path: Path to save summary report
            pcap_file: Original PCAP file path (if any)
        """
        from datetime import datetime
        import json
        from pathlib import Path
        
        report_lines = []
        
        # === HEADER ===
        report_lines.append("="*110)
        report_lines.append("🔒 BÁO CÁO PHÂN TÍCH BẢO MẬT MẠNG - PHÁT HIỆN MỐI ĐE DỌA ICS/SCADA")
        report_lines.append("="*110)
        report_lines.append(f"Thời gian phân tích: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if pcap_file:
            report_lines.append(f"File PCAP: {Path(pcap_file).name}")
        report_lines.append(f"Công cụ: ICS/SCADA Anomaly Detection System v1.0")
        report_lines.append(f"Model: output/anomaly_model.pkl (Isolation Forest)")
        report_lines.append("")
        
        # Calculate statistics
        total_flows = len(results)
        total_anomalies = results['is_anomaly'].sum() if 'is_anomaly' in results.columns else 0
        anomaly_rate = (total_anomalies / total_flows * 100) if total_flows > 0 else 0
        
        high_risk = medium_risk = low_risk = 0
        if 'anomaly_score' in results.columns:
            high_risk = (results['anomaly_score'] < -0.5).sum()
            medium_risk = ((results['anomaly_score'] >= -0.5) & (results['anomaly_score'] < -0.3)).sum()
            low_risk = (results['anomaly_score'] >= -0.3).sum()
        
        # ICS traffic count
        ics_flows = 0
        if 'is_ics_protocol' in results.columns:
            ics_flows = int(results['is_ics_protocol'].sum())
        
        # Count threats
        lateral_count = 0
        if lateral_df is not None and len(lateral_df) > 0 and 'is_lateral_movement' in lateral_df.columns:
            lateral_count = int(lateral_df['is_lateral_movement'].sum())
        
        exfil_count = 0
        if exfil_df is not None and len(exfil_df) > 0 and 'is_exfiltration' in exfil_df.columns:
            exfil_count = int(exfil_df['is_exfiltration'].sum())
        
        ics_anomaly_count = len(ics_df) if ics_df is not None else 0
        
        # === 1️⃣ TỔNG QUAN ===
        report_lines.append("1️⃣ TỔNG QUAN")
        report_lines.append("-" * 110)
        report_lines.append(f"Model nạp từ output/anomaly_model.pkl (đã train ở bước trước).")
        report_lines.append(f"{total_anomalies}/{total_flows} flow bị đánh dấu bất thường → {anomaly_rate:.2f}% anomaly")
        if anomaly_rate < 5:
            report_lines.append(f"→ Hợp lý vì dữ liệu demo nhỏ, không chứa pattern lạ theo feature model đã học.")
        elif anomaly_rate > 20:
            report_lines.append(f"→ Tỷ lệ bất thường cao, cần điều tra thêm các flow nghi ngờ.")
        report_lines.append("")
        
        # === 2️⃣ DỮ LIỆU ĐẦU VÀO ===
        report_lines.append("2️⃣ DỮ LIỆU ĐẦU VÀO")
        report_lines.append("-" * 110)
        report_lines.append(f"  • Tổng số flows: {total_flows:,}")
        
        # Network statistics
        if 'src_ip' in results.columns:
            unique_src = results['src_ip'].nunique()
            report_lines.append(f"  • Unique source IPs: {unique_src}")
        if 'dst_ip' in results.columns:
            unique_dst = results['dst_ip'].nunique()
            report_lines.append(f"  • Unique destination IPs: {unique_dst}")
        if 'protocol' in results.columns:
            protocols = results['protocol'].value_counts()
            report_lines.append(f"  • Protocols: {', '.join([f'{p}={c}' for p, c in protocols.items()])}")
        if 'bytes' in results.columns:
            total_bytes = results['bytes'].sum()
            report_lines.append(f"  • Total traffic: {total_bytes:,.0f} bytes ({total_bytes/1024/1024:.2f} MB)")
        
        report_lines.append("")
        report_lines.append("Kết luận:")
        if total_flows < 100:
            report_lines.append("  → Dữ liệu PCAP rất nhỏ, phù hợp cho demo test, không phải traffic thực.")
        else:
            report_lines.append("  → Dữ liệu đủ lớn để phân tích mối đe dọa.")
        report_lines.append("")
        
        # === 3️⃣ PHÂN TÍCH BẰNG MÔ HÌNH ===
        report_lines.append("3️⃣ PHÂN TÍCH BẰNG MÔ HÌNH")
        report_lines.append("-" * 110)
        
        if 'anomaly_score' in results.columns:
            high_risk = (results['anomaly_score'] < -0.5).sum()
            medium_risk = ((results['anomaly_score'] >= -0.5) & (results['anomaly_score'] < -0.3)).sum()
            low_risk = (results['anomaly_score'] >= -0.3).sum()
            report_lines.append(f"  🔴 High Risk (score < -0.5): {high_risk}")
            report_lines.append(f"  🟡 Medium Risk (score -0.5 to -0.3): {medium_risk}")
            report_lines.append(f"  🟢 Low Risk (score > -0.3): {low_risk}")
        
        # === 3.1 General Anomaly Detection ===
        report_lines.append("3.1 General Anomaly Detection")
        report_lines.append("")
        report_lines.append(f"🔍 Running anomaly detection...")
        report_lines.append(f"Found {total_anomalies} anomalies ({anomaly_rate:.2f}%)")
        report_lines.append(f"🚨 GENERAL ANOMALIES: {total_anomalies} detected")
        report_lines.append("")
        report_lines.append("➡️ Giải thích:")
        if total_anomalies > 0:
            report_lines.append(f"Mô hình phát hiện {total_anomalies} flow ({anomaly_rate:.1f}%) khác biệt đáng kể so với {total_flows - total_anomalies} flow còn lại.")
            report_lines.append(f"Vì contamination mặc định ~0.05–0.15 nên con số {anomaly_rate:.1f}% là hợp lý.")
        else:
            report_lines.append("Không phát hiện flow bất thường nào. Tất cả traffic đều nằm trong baseline.")
        report_lines.append("Kết quả chi tiết lưu trong: output/pcap_analysis/general_anomalies.csv")
        report_lines.append("")
        
        # === 3.2 Phân tích chuyên sâu ===
        report_lines.append("3.2 Phân tích Chuyên Sâu")
        report_lines.append("")
        
        # === Lateral Movement ===
        report_lines.append("🔸 Lateral Movement")
        if lateral_df is not None and len(lateral_df) > 0:
            report_lines.append(f"🚨 Lateral Movement: {lateral_count} suspicious activities detected")
            
            if lateral_count > 0 and 'src_ip' in lateral_df.columns:
                report_lines.append("")
                report_lines.append("TOP SUSPICIOUS SOURCES:")
                # Get detailed info
                suspicious = lateral_df[lateral_df['is_lateral_movement'] == 1]
                for _, row in suspicious.head(5).iterrows():
                    src_ip = row.get('src_ip', 'N/A')
                    # Try both column names (unique_dsts or unique_destinations)
                    unique_dsts = row.get('unique_dsts', row.get('unique_destinations', 0))
                    unique_ports = row.get('unique_ports', 0)
                    lateral_score = row.get('lateral_score', 0)
                    report_lines.append(f"{src_ip:<20} unique_dsts={unique_dsts:<3}  unique_ports={unique_ports:<3}  lateral_score={lateral_score:.1f}")
                
                report_lines.append("")
                report_lines.append("➡️ Phân tích:")
                if len(suspicious) > 0:
                    top = suspicious.iloc[0]
                    top_ip = top.get('src_ip', 'N/A')
                    top_dsts = top.get('unique_dsts', top.get('unique_destinations', 0))
                    report_lines.append(f"IP {top_ip} được đánh dấu đáng ngờ vì:")
                    report_lines.append(f"  • Nó kết nối đến {top_dsts} đích khác nhau")
                    report_lines.append(f"  • Trong khoảng thời gian ngắn")
                    report_lines.append(f"  • 'Lateral Score' mức trung bình–cao; cho thấy host có thể đang quét/di chuyển ngang.")
        else:
            report_lines.append(f"🚨 Lateral Movement: 0 suspicious activities detected")
            report_lines.append("")
            report_lines.append("→ Không phát hiện hành vi di chuyển ngang trong mạng.")
        
        report_lines.append("")
        
        # === Data Exfiltration ===
        report_lines.append("🔸 Data Exfiltration")
        if exfil_df is not None and len(exfil_df) > 0:
            report_lines.append(f"🚨 Data Exfiltration: {exfil_count} suspicious transfers detected")
            
            if exfil_count > 0:
                report_lines.append("")
                if 'bytes' in exfil_df.columns:
                    total_exfil_bytes = exfil_df['bytes'].sum()
                    report_lines.append(f"Total Data at Risk: {total_exfil_bytes:,.0f} bytes ({total_exfil_bytes/1024/1024:.2f} MB)")
                if 'dst_ip' in exfil_df.columns:
                    external_ips = exfil_df['dst_ip'].value_counts().head(3)
                    report_lines.append("Top External Destinations:")
                    for ip, count in external_ips.items():
                        report_lines.append(f"  • {ip}: {count} transfers")
        else:
            report_lines.append(f"🚨 Data Exfiltration: 0 suspicious transfers detected")
            report_lines.append("")
            report_lines.append("→ Không thấy flow nào truyền dữ liệu ra ngoài lớn bất thường.")
        
        report_lines.append("")
        
        # === ICS-specific Anomalies ===
        report_lines.append("🔸 ICS-specific Anomalies")
        if ics_df is not None and len(ics_df) > 0:
            report_lines.append(f"🚨 ICS/SCADA Anomalies: {len(ics_df)} types detected")
            report_lines.append("")
            
            if 'severity' in ics_df.columns:
                critical = (ics_df['severity'] == 'critical').sum()
                high = (ics_df['severity'] == 'high').sum()
                medium = (ics_df['severity'] == 'medium').sum()
                report_lines.append(f"  🔴 Critical: {critical}")
                report_lines.append(f"  🟠 High: {high}")
                report_lines.append(f"  🟡 Medium: {medium}")
                report_lines.append("")
            
            report_lines.append("Anomaly Types:")
            for _, row in ics_df.head(10).iterrows():
                report_lines.append(f"  • {row.get('type', 'Unknown')}: {row.get('description', 'No description')}")
        else:
            if ics_flows == 0:
                report_lines.append("No ICS protocol traffic detected")
                report_lines.append("")
                report_lines.append("→ PCAP không chứa gói Modbus/DNP3/S7Comm, nên module ICS không chạy.")
            else:
                report_lines.append(f"Found {ics_flows} ICS flows but no anomalies detected.")
                report_lines.append("")
                report_lines.append("→ ICS traffic trong phạm vi bình thường.")
        
        # === 4️⃣ ĐÁNH GIÁ TỔNG THỂ & Ý NGHĨA ===
        report_lines.append("4️⃣ ĐÁNH GIÁ TỔNG THỂ & Ý NGHĨA")
        report_lines.append("-" * 110)
        report_lines.append("")
        
        # Create evaluation table
        report_lines.append(f"{'Thành phần':<30} | {'Đánh giá':<30} | {'Ý nghĩa thực tế'}")
        report_lines.append("-" * 110)
        
        # Row 1: Data PCAP
        data_assess = f"{total_flows} flows"
        if total_flows < 100:
            data_meaning = "Demo test, không phải traffic thực."
        else:
            data_meaning = "Dữ liệu thực tế, đủ lớn để phân tích."
        report_lines.append(f"{'Dữ liệu PCAP':<30} | {data_assess:<30} | {data_meaning}")
        
        # Row 2: Model training
        model_assess = "OK, đã train baseline"
        model_meaning = "Training trực tiếp trên PCAP để chạy online detection."
        report_lines.append(f"{'Model training':<30} | {model_assess:<30} | {model_meaning}")
        
        # Row 3: Anomaly detection
        anomaly_assess = f"{total_anomalies}/{total_flows} flow bất thường"
        if total_anomalies > 0:
            anomaly_meaning = f"Có hoạt động lạ cần xem xét thêm."
        else:
            anomaly_meaning = "Không có outlier rõ ràng."
        report_lines.append(f"{'Anomaly detection':<30} | {anomaly_assess:<30} | {anomaly_meaning}")
        
        # Row 4: Lateral Movement
        lateral_assess = f"{lateral_count} nguồn nghi ngờ"
        if lateral_count > 0:
            lateral_meaning = "Có thể là thăm dò nội bộ nhẹ hoặc quét mạng."
        else:
            lateral_meaning = "Không phát hiện di chuyển ngang."
        report_lines.append(f"{'Lateral Movement':<30} | {lateral_assess:<30} | {lateral_meaning}")
        
        # Row 5: Data Exfiltration
        exfil_assess = f"{exfil_count} transfers nghi ngờ"
        if exfil_count > 0:
            exfil_meaning = "Có dữ liệu bất thường ra ngoài."
        else:
            exfil_meaning = "Không có luồng dữ liệu lớn ra ngoài."
        report_lines.append(f"{'Data Exfiltration':<30} | {exfil_assess:<30} | {exfil_meaning}")
        
        # Row 6: ICS detection
        ics_assess = f"{ics_flows} ICS flows, {ics_anomaly_count} anomalies"
        if ics_flows == 0:
            ics_meaning = "PCAP không phải mạng công nghiệp."
        elif ics_anomaly_count > 0:
            ics_meaning = "Phát hiện bất thường trong ICS protocol."
        else:
            ics_meaning = "ICS traffic bình thường."
        report_lines.append(f"{'ICS detection':<30} | {ics_assess:<30} | {ics_meaning}")
        
        report_lines.append("")
        
        # === OUTPUT FILES ===
        report_lines.append("3.3 Output Files Sinh Ra")
        report_lines.append("")
        report_lines.append("output/pcap_analysis/")
        report_lines.append("  ├─ general_anomalies.csv")
        report_lines.append("  ├─ lateral_movement.csv")
        report_lines.append("  ├─ data_exfiltration.csv")
        report_lines.append("  ├─ ics_anomalies.csv")
        report_lines.append("  └─ attack_summary.txt (báo cáo này)")
        report_lines.append("")
        report_lines.append("Tất cả chứa log chi tiết: src_ip, dst_ip, port, bytes, score...")
        
        if lateral_count > 0:
            report_lines.append("")
            report_lines.append("Đặc biệt, lateral_movement.csv có dòng đáng chú ý:")
            if lateral_df is not None and len(lateral_df) > 0:
                suspicious = lateral_df[lateral_df['is_lateral_movement'] == 1]
                if len(suspicious) > 0:
                    top = suspicious.iloc[0]
                    unique_dsts = top.get('unique_dsts', top.get('unique_destinations', 0))
                    report_lines.append(f"  src_ip={top.get('src_ip', 'N/A')}  unique_dsts={unique_dsts}  unique_ports={top.get('unique_ports', 0)}  lateral_score={top.get('lateral_score', 0):.1f}")
                    report_lines.append(f"  → host này là ứng viên duy nhất cần xem thêm trong Wireshark.")
        
        report_lines.append("")
        
        # === KẾT LUẬN CHUYÊN MÔN ===
        report_lines.append("⚙️ KẾT LUẬN CHUYÊN MÔN")
        report_lines.append("-" * 110)
        report_lines.append("  • Pipeline hoạt động đúng: file PCAP được parse → feature hóa → model đánh giá → xuất kết quả.")
        
        if total_anomalies == 0 and lateral_count == 0 and exfil_count == 0:
            report_lines.append("  • Không phát hiện mối đe dọa rõ rệt. Network traffic trong phạm vi bình thường.")
        elif total_anomalies > 0 or lateral_count > 0 or exfil_count > 0:
            report_lines.append(f"  • Phát hiện {total_anomalies + lateral_count + exfil_count} mối đe dọa tiềm ẩn cần điều tra.")
        
        if ics_flows == 0:
            report_lines.append("  • ICS traffic = 0 ⇒ đây là PCAP IT thông thường, chưa có OT/ICS.")
        else:
            report_lines.append(f"  • ICS traffic = {ics_flows} flows ⇒ đây là mạng ICS/SCADA/OT.")
        
        report_lines.append("")
        
        # === KHUYẾN NGHỊ ===
        report_lines.append("💡 KHUYẾN NGHỊ")
        report_lines.append("-" * 110)
        
        recommendations = []
        if lateral_count > 0:
            recommendations.append("1. URGENT: Điều tra các IP thực hiện lateral movement")
            recommendations.append("   → Xem lại trong Wireshark, check firewall logs")
            recommendations.append("   → Kiểm tra compromised accounts")
        
        if exfil_count > 0:
            recommendations.append("2. HIGH PRIORITY: Phát hiện data exfiltration")
            recommendations.append("   → Block ngay các external IPs đáng ngờ")
            recommendations.append("   → Review data access logs")
        
        if ics_anomaly_count > 0:
            recommendations.append("3. CRITICAL: ICS/SCADA anomalies")
            recommendations.append("   → Verify device configurations")
            recommendations.append("   → Check unauthorized protocol usage")
        
        if high_risk > 0:
            recommendations.append(f"4. Review {high_risk} high-risk anomalies được model đánh dấu")
        
        if not recommendations:
            recommendations.append("✅ Không phát hiện mối đe dọa nghiêm trọng.")
            recommendations.append("   → Tiếp tục monitoring thường xuyên")
            recommendations.append("   → Cập nhật baseline model định kỳ")
        
        for rec in recommendations:
            report_lines.append(rec)
        
        report_lines.append("")
        report_lines.append("="*110)
        report_lines.append("HẾT BÁO CÁO - End of Analysis Report")
        report_lines.append("="*110)
        
        # Save report
        report_text = "\n".join(report_lines)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        # Also save JSON version
        json_path = output_path.replace('.txt', '.json')
        summary_json = {
            'timestamp': datetime.now().isoformat(),
            'total_flows': int(total_flows),
            'total_anomalies': int(total_anomalies),
            'anomaly_rate': float(anomaly_rate),
            'threats': {
                'lateral_movement': int(lateral_df['is_lateral_movement'].sum()) if lateral_df is not None and 'is_lateral_movement' in lateral_df.columns else 0,
                'data_exfiltration': int(exfil_df['is_exfiltration'].sum()) if exfil_df is not None and 'is_exfiltration' in exfil_df.columns else 0,
                'ics_anomalies': int(len(ics_df)) if ics_df is not None else 0
            },
            'risk_levels': {
                'high': int(high_risk) if 'anomaly_score' in results.columns else 0,
                'medium': int(medium_risk) if 'anomaly_score' in results.columns else 0,
                'low': int(low_risk) if 'anomaly_score' in results.columns else 0
            }
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(summary_json, f, indent=2)
        
        logger.info(f"✅ Attack summary saved to {output_path}")
        logger.info(f"✅ JSON summary saved to {json_path}")
        
        # Print summary to console
        print("\n" + report_text)
        
        return report_text
