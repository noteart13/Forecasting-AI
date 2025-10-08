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
        Phát hiện Lateral Movement - Kẻ tấn công di chuyển ngang trong hệ thống
        
        Dấu hiệu nâng cao:
        - Source IP kết nối với nhiều destinations trong thời gian ngắn
        - Scan nhiều ports khác nhau (port scanning)
        - Connections đến các hosts không thông thường
        - Failed connections cao (connection attempts)
        - Traffic patterns bất thường (burst traffic)
        - Access từ các IP ranges không mong đợi
        """
        df = df.copy()
        
        # Time window (5 phút)
        if 'timestamp' in df.columns:
            df['time_window'] = df['timestamp'].dt.floor('5T')
        else:
            df['time_window'] = 0
        
        # Group by source IP và time window
        lateral_stats = df.groupby(['src_ip', 'time_window']).agg({
            'dst_ip': 'nunique',
            'dst_port': 'nunique',
            'packets': 'sum',
            'bytes': 'sum',
            'duration': 'mean'
        }).reset_index()
        
        lateral_stats.columns = ['src_ip', 'time_window', 'unique_dsts', 'unique_ports', 'packets', 'bytes', 'avg_duration']
        
        # Tính toán các metrics nâng cao
        lateral_stats['dst_diversity_score'] = lateral_stats['unique_dsts'] / lateral_stats['unique_dsts'].max()
        lateral_stats['port_scan_score'] = lateral_stats['unique_ports'] / lateral_stats['unique_ports'].max()
        lateral_stats['traffic_intensity'] = lateral_stats['bytes'] / (lateral_stats['avg_duration'] + 1)
        
        # Detect port scanning patterns
        lateral_stats['is_port_scan'] = (
            (lateral_stats['unique_ports'] > 10) &  # Scan nhiều ports
            (lateral_stats['packets'] > 50)          # Nhiều packets
        ).astype(int)
        
        # Detect host scanning patterns  
        lateral_stats['is_host_scan'] = (
            (lateral_stats['unique_dsts'] > 5) &     # Scan nhiều hosts
            (lateral_stats['packets'] > 20)          # Nhiều packets
        ).astype(int)
        
        # Lateral movement score (weighted combination)
        lateral_stats['lateral_score'] = (
            lateral_stats['dst_diversity_score'] * 4.0 +      # Nhiều destinations
            lateral_stats['port_scan_score'] * 3.0 +          # Scan ports
            lateral_stats['is_port_scan'] * 2.0 +             # Port scan pattern
            lateral_stats['is_host_scan'] * 2.0              # Host scan pattern
        )
        
        # Dynamic threshold based on traffic patterns
        mean_score = lateral_stats['lateral_score'].mean()
        std_score = lateral_stats['lateral_score'].std()
        threshold = mean_score + 2 * std_score  # 2-sigma threshold
        
        lateral_stats['is_lateral_movement'] = (lateral_stats['lateral_score'] > threshold).astype(int)
        
        # Additional checks for high-risk patterns
        high_risk = lateral_stats[
            (lateral_stats['is_lateral_movement'] == 1) &
            ((lateral_stats['is_port_scan'] == 1) | (lateral_stats['is_host_scan'] == 1))
        ]
        lateral_stats['is_high_risk'] = lateral_stats.index.isin(high_risk.index).astype(int)
        
        suspicious = lateral_stats[lateral_stats['is_lateral_movement'] == 1]
        high_risk_count = lateral_stats['is_high_risk'].sum()
        
        logger.info(f"🚨 Lateral Movement: {len(suspicious)} suspicious activities detected")
        logger.info(f"🚨 High Risk Patterns: {high_risk_count} detected (port/host scanning)")
        
        return lateral_stats
    
    def detect_data_exfiltration(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Phát hiện Data Exfiltration - Hành vi đánh cắp và chuyển dữ liệu ra bên ngoài
        
        Dấu hiệu nâng cao:
        - Upload traffic bất thường lớn (outbound bytes)
        - Connections ra external IPs không thông thường
        - Transfers vào giờ bất thường (đêm, cuối tuần)
        - Sử dụng protocols không thông thường (FTP, HTTP POST, etc.)
        - Traffic patterns bất thường (burst uploads)
        - Connections đến các domains/IPs đáng ngờ
        - Sử dụng encrypted channels để che giấu
        """
        df = df.copy()
        
        # Identify internal/external IPs
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
                        # Loopback
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
        
        # Time window (10 phút)
        if 'timestamp' in outbound.columns:
            outbound['time_window'] = outbound['timestamp'].dt.floor('10T')
        else:
            outbound['time_window'] = 0
        
        # Aggregate by source và time window
        exfil_stats = outbound.groupby(['src_ip', 'time_window']).agg({
            'bytes': 'sum',
            'packets': 'sum',
            'dst_ip': 'nunique',
            'dst_port': 'nunique',
            'duration': 'sum'
        }).reset_index()
        
        exfil_stats.columns = ['src_ip', 'time_window', 'bytes_out', 'packets_out', 'unique_external_dsts', 'unique_ports', 'total_duration']
        
        # Tính toán các metrics nâng cao
        exfil_stats['mb_transferred'] = exfil_stats['bytes_out'] / (1024 * 1024)
        exfil_stats['transfer_rate'] = exfil_stats['bytes_out'] / (exfil_stats['total_duration'] + 1)
        exfil_stats['packet_rate'] = exfil_stats['packets_out'] / (exfil_stats['total_duration'] + 1)
        
        # Detect suspicious patterns
        exfil_stats['is_large_transfer'] = (exfil_stats['mb_transferred'] > 10).astype(int)  # > 10MB
        exfil_stats['is_multiple_destinations'] = (exfil_stats['unique_external_dsts'] > 3).astype(int)
        exfil_stats['is_high_bandwidth'] = (exfil_stats['transfer_rate'] > 1000000).astype(int)  # > 1MB/s
        
        # Detect unusual timing (night/weekend transfers)
        if 'timestamp' in outbound.columns:
            outbound['hour'] = outbound['timestamp'].dt.hour
            outbound['day_of_week'] = outbound['timestamp'].dt.dayofweek
            outbound['is_night'] = ((outbound['hour'] >= 22) | (outbound['hour'] <= 6)).astype(int)
            outbound['is_weekend'] = (outbound['day_of_week'] >= 5).astype(int)
            
            # Aggregate timing info
            timing_stats = outbound.groupby(['src_ip', 'time_window']).agg({
                'is_night': 'max',
                'is_weekend': 'max'
            }).reset_index()
            
            exfil_stats = exfil_stats.merge(timing_stats, on=['src_ip', 'time_window'], how='left')
            exfil_stats['is_unusual_time'] = ((exfil_stats['is_night'] == 1) | (exfil_stats['is_weekend'] == 1)).astype(int)
        else:
            exfil_stats['is_unusual_time'] = 0
        
        # Detect suspicious protocols (FTP, HTTP POST, etc.)
        suspicious_protocols = ['FTP', 'HTTP', 'HTTPS', 'SFTP', 'SCP']
        protocol_stats = outbound[outbound['protocol'].isin(suspicious_protocols)].groupby(['src_ip', 'time_window']).size().reset_index(name='suspicious_protocol_count')
        exfil_stats = exfil_stats.merge(protocol_stats, on=['src_ip', 'time_window'], how='left')
        exfil_stats['suspicious_protocol_count'] = exfil_stats['suspicious_protocol_count'].fillna(0)
        exfil_stats['is_suspicious_protocol'] = (exfil_stats['suspicious_protocol_count'] > 0).astype(int)
        
        # Exfiltration score (weighted combination)
        exfil_stats['exfil_score'] = (
            exfil_stats['mb_transferred'] * 3.0 +                    # Data volume
            exfil_stats['unique_external_dsts'] * 2.0 +              # Multiple destinations
            exfil_stats['is_large_transfer'] * 4.0 +                # Large transfers
            exfil_stats['is_multiple_destinations'] * 3.0 +          # Multiple destinations
            exfil_stats['is_high_bandwidth'] * 2.0 +                # High bandwidth
            exfil_stats['is_unusual_time'] * 2.0 +                   # Unusual timing
            exfil_stats['is_suspicious_protocol'] * 1.5              # Suspicious protocols
        )
        
        # Dynamic threshold based on traffic patterns
        mean_score = exfil_stats['exfil_score'].mean()
        std_score = exfil_stats['exfil_score'].std()
        threshold = mean_score + 2 * std_score  # 2-sigma threshold
        
        exfil_stats['is_exfiltration'] = (exfil_stats['exfil_score'] > threshold).astype(int)
        
        # Additional checks for high-risk patterns
        high_risk = exfil_stats[
            (exfil_stats['is_exfiltration'] == 1) &
            ((exfil_stats['is_large_transfer'] == 1) | (exfil_stats['is_unusual_time'] == 1))
        ]
        exfil_stats['is_high_risk'] = exfil_stats.index.isin(high_risk.index).astype(int)
        
        suspicious = exfil_stats[exfil_stats['is_exfiltration'] == 1]
        high_risk_count = exfil_stats['is_high_risk'].sum()
        
        logger.info(f"🚨 Data Exfiltration: {len(suspicious)} suspicious transfers detected")
        logger.info(f"🚨 High Risk Patterns: {high_risk_count} detected (large transfers/unusual timing)")
        
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
