"""
Train Anomaly Detection Model cho ICS/SCADA Network
"""
import argparse
import yaml
import json
from pathlib import Path
import logging

from src.network_loader import NetworkLoader
from src.anomaly_detector import ICSAnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description='Train ICS/SCADA Anomaly Detection Model')
    parser.add_argument('--data', type=str, default='data/network_traffic.csv',
                       help='Path to normal network traffic data')
    parser.add_argument('--output', type=str, default='output/anomaly_model.pkl',
                       help='Path to save trained model')
    parser.add_argument('--contamination', type=float, default=0.05,
                       help='Expected proportion of anomalies (default: 0.05)')
    args = parser.parse_args()
    
    logger.info("="*60)
    logger.info("🔒 ICS/SCADA ANOMALY DETECTION - TRAINING")
    logger.info("="*60)
    
    # Load data
    logger.info(f"\n📊 Loading training data from {args.data}...")
    loader = NetworkLoader(args.data)
    data = loader.load()
    data = loader.preprocess()
    
    # Statistics
    stats = loader.get_statistics()
    logger.info("\n📈 Data Statistics:")
    for key, value in stats.items():
        logger.info(f"  {key}: {value}")
    
    # Train model
    logger.info(f"\n🧠 Training Isolation Forest model...")
    logger.info(f"   Contamination: {args.contamination}")
    
    detector = ICSAnomalyDetector(contamination=args.contamination)
    
    # Select features for training
    feature_cols = [
        'bytes', 'packets', 'duration',
        'bytes_per_packet', 'packets_per_second', 'bytes_per_second',
        'is_ics_protocol', 'is_high_port', 'is_tcp', 'is_udp',
        'unique_destinations', 'hour', 'is_night', 'is_weekend'
    ]
    
    # Filter available features
    available_features = [f for f in feature_cols if f in data.columns]
    logger.info(f"   Using {len(available_features)} features: {available_features}")
    
    detector.train(data, feature_cols=available_features)
    
    # Save model
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    detector.save_model(str(output_path))
    
    # Save training metadata
    metadata = {
        'training_samples': len(data),
        'features': available_features,
        'contamination': args.contamination,
        'data_statistics': stats
    }
    
    metadata_path = output_path.parent / 'training_metadata.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"\n✅ Model saved to {output_path}")
    logger.info(f"✅ Metadata saved to {metadata_path}")
    
    logger.info("\n" + "="*60)
    logger.info("🎉 TRAINING COMPLETED SUCCESSFULLY!")
    logger.info("="*60)
    logger.info("\nNext step: Run detection with 'python detect.py --data <test_data.csv>'")


if __name__ == '__main__':
    main()
