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
        Phát hiện Lateral Movement
        
        Dấu hiệu:
        - Source IP kết nối với nhiều destinations trong thời gian ngắn
        - Scan nhiều ports khác nhau
        - Failed connections cao
        """
        df = df.copy()
        
        # Time window (5 phút)
        if 'timestamp' in df.columns:
            df['time_window'] = df['timestamp'].dt.floor('5T')
        else:
            df['time_window'] = 0
        
        # Group by source IP
        lateral_stats = df.groupby(['src_ip', 'time_window']).agg({
            'dst_ip': 'nunique',
            'dst_port': 'nunique',
            'packets': 'sum',
            'bytes': 'sum'
        }).reset_index()
        
        lateral_stats.columns = ['src_ip', 'time_window', 'unique_dsts', 'unique_ports', 'packets', 'bytes']
        
        # Lateral movement score
        lateral_stats['lateral_score'] = (
            lateral_stats['unique_dsts'] * 3.0 +  # Nhiều destinations
            lateral_stats['unique_ports'] * 2.0    # Scan ports
        )
        
        # Threshold (top 5%)
        threshold = lateral_stats['lateral_score'].quantile(0.95)
        lateral_stats['is_lateral_movement'] = (lateral_stats['lateral_score'] > threshold).astype(int)
        
        suspicious = lateral_stats[lateral_stats['is_lateral_movement'] == 1]
        logger.info(f"🚨 Lateral Movement: {len(suspicious)} suspicious activities detected")
        
        return lateral_stats
    
    def detect_data_exfiltration(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Phát hiện Data Exfiltration
        
        Dấu hiệu:
        - Upload traffic bất thường lớn (outbound bytes)
        - Connections ra external IPs
        - Transfers vào giờ bất thường (đêm, cuối tuần)
        - Sử dụng protocols không thông thường
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
        
        # Aggregate by source
        exfil_stats = outbound.groupby(['src_ip', 'time_window']).agg({
            'bytes': 'sum',
            'packets': 'sum',
            'dst_ip': 'nunique'
        }).reset_index()
        
        exfil_stats.columns = ['src_ip', 'time_window', 'bytes_out', 'packets_out', 'unique_external_dsts']
        
        # Exfiltration score
        exfil_stats['exfil_score'] = (
            exfil_stats['bytes_out'] / 1000000 * 2.0 +  # MB transferred
            exfil_stats['unique_external_dsts'] * 5.0     # Multiple destinations
        )
        
        # Threshold (top 5%)
        threshold = exfil_stats['exfil_score'].quantile(0.95)
        exfil_stats['is_exfiltration'] = (exfil_stats['exfil_score'] > threshold).astype(int)
        
        suspicious = exfil_stats[exfil_stats['is_exfiltration'] == 1]
        logger.info(f"🚨 Data Exfiltration: {len(suspicious)} suspicious transfers detected")
        
        return exfil_stats
    
    def detect_ics_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Phát hiện ICS-specific anomalies
        
        Dấu hiệu:
        - ICS devices kết nối với unexpected IPs
        - ICS protocols sử dụng vào giờ bất thường
        - Sudden changes trong ICS traffic patterns
        - Non-ICS devices accessing ICS ports
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
        
        # Anomaly checks
        anomalies = []
        
        # 1. ICS traffic at unusual times (night/weekend)
        if 'is_night' in ics_traffic.columns:
            night_ics = ics_traffic[ics_traffic['is_night'] == 1]
            if len(night_ics) > 0:
                anomalies.append({
                    'type': 'unusual_time',
                    'count': len(night_ics),
                    'description': f'{len(night_ics)} ICS connections during night hours'
                })
        
        # 2. ICS devices with high destination diversity
        ics_diversity = ics_traffic.groupby('src_ip')['dst_ip'].nunique()
        high_diversity = ics_diversity[ics_diversity > ics_diversity.quantile(0.95)]
        if len(high_diversity) > 0:
            anomalies.append({
                'type': 'high_diversity',
                'count': len(high_diversity),
                'description': f'{len(high_diversity)} ICS devices with unusually high connection diversity'
            })
        
        # 3. Sudden traffic volume changes
        if 'timestamp' in ics_traffic.columns:
            ics_traffic['time_window'] = ics_traffic['timestamp'].dt.floor('30T')
            volume_stats = ics_traffic.groupby('time_window')['bytes'].sum()
            mean_volume = volume_stats.mean()
            std_volume = volume_stats.std()
            spike_threshold = mean_volume + 3 * std_volume
            spikes = volume_stats[volume_stats > spike_threshold]
            if len(spikes) > 0:
                anomalies.append({
                    'type': 'traffic_spike',
                    'count': len(spikes),
                    'description': f'{len(spikes)} time windows with unusual ICS traffic volume'
                })
        
        logger.info(f"🚨 ICS Anomalies: {len(anomalies)} types detected")
        
        return pd.DataFrame(anomalies)
    
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
