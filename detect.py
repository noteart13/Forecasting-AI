"""
Detect Anomalies trong ICS/SCADA Network Traffic
"""
import argparse
import yaml
import json
from pathlib import Path
import logging
import pandas as pd

from src.network_loader import NetworkLoader
from src.anomaly_detector import ICSAnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description='Detect Anomalies in ICS/SCADA Network')
    parser.add_argument('--data', type=str, required=True,
                       help='Path to network traffic data to analyze')
    parser.add_argument('--model', type=str, default='output/anomaly_model.pkl',
                       help='Path to trained model')
    parser.add_argument('--output', type=str, default='output/anomalies_detected.csv',
                       help='Path to save detection results')
    parser.add_argument('--detailed', action='store_true',
                       help='Run detailed threat analysis (Lateral Movement, Exfil, ICS)')
    args = parser.parse_args()
    
    logger.info("="*60)
    logger.info("🔍 ICS/SCADA ANOMALY DETECTION - ANALYSIS")
    logger.info("="*60)
    
    # Load data
    logger.info(f"\n📊 Loading data from {args.data}...")
    loader = NetworkLoader(args.data)
    data = loader.load()
    data = loader.preprocess()
    
    stats = loader.get_statistics()
    logger.info("\n📈 Data Statistics:")
    for key, value in stats.items():
        logger.info(f"  {key}: {value}")
    
    # Load model
    logger.info(f"\n🔓 Loading model from {args.model}...")
    detector = ICSAnomalyDetector()
    detector.load_model(args.model)
    
    # Detect general anomalies
    logger.info("\n🔍 Running anomaly detection...")
    results = detector.predict(data)
    
    n_anomalies = results['is_anomaly'].sum()
    logger.info(f"\n🚨 GENERAL ANOMALIES: {n_anomalies} detected ({n_anomalies/len(results)*100:.2f}%)")
    
    # Detailed threat analysis
    if args.detailed:
        logger.info("\n" + "="*60)
        logger.info("🎯 DETAILED THREAT ANALYSIS")
        logger.info("="*60)
        
        # 1. Lateral Movement
        logger.info("\n🔍 Analyzing Lateral Movement...")
        lateral = detector.detect_lateral_movement(data)
        if len(lateral) > 0:
            suspicious_lateral = lateral[lateral['is_lateral_movement'] == 1]
            logger.info(f"   Found {len(suspicious_lateral)} suspicious activities")
            lateral_path = Path(args.output).parent / 'lateral_movement.csv'
            suspicious_lateral.to_csv(lateral_path, index=False)
            logger.info(f"   Saved to {lateral_path}")
        
        # 2. Data Exfiltration
        logger.info("\n🔍 Analyzing Data Exfiltration...")
        exfil = detector.detect_data_exfiltration(data)
        if len(exfil) > 0:
            suspicious_exfil = exfil[exfil['is_exfiltration'] == 1]
            logger.info(f"   Found {len(suspicious_exfil)} suspicious transfers")
            exfil_path = Path(args.output).parent / 'data_exfiltration.csv'
            suspicious_exfil.to_csv(exfil_path, index=False)
            logger.info(f"   Saved to {exfil_path}")
        
        # 3. ICS-specific Anomalies
        logger.info("\n🔍 Analyzing ICS-specific Anomalies...")
        ics_anomalies = detector.detect_ics_anomalies(data)
        if len(ics_anomalies) > 0:
            logger.info(f"   Found {len(ics_anomalies)} anomaly types:")
            for _, row in ics_anomalies.iterrows():
                logger.info(f"   - {row['type']}: {row['description']}")
            ics_path = Path(args.output).parent / 'ics_anomalies.csv'
            ics_anomalies.to_csv(ics_path, index=False)
            logger.info(f"   Saved to {ics_path}")
    
    # Save main results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save anomalies only
    anomalies_only = results[results['is_anomaly'] == 1].copy()
    anomalies_only.to_csv(output_path, index=False)
    
    logger.info(f"\n💾 Results saved to {output_path}")
    
    # Top anomalies
    if len(anomalies_only) > 0:
        logger.info("\n🔴 TOP 10 ANOMALIES (by anomaly score):")
        top_anomalies = anomalies_only.nsmallest(10, 'anomaly_score')[
            ['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'bytes', 'anomaly_score']
        ]
        print(top_anomalies.to_string(index=False))
    
    # Summary report
    logger.info("\n" + "="*60)
    logger.info("📊 DETECTION SUMMARY")
    logger.info("="*60)
    logger.info(f"Total flows analyzed: {len(results)}")
    logger.info(f"Anomalies detected: {n_anomalies} ({n_anomalies/len(results)*100:.2f}%)")
    logger.info(f"ICS protocol flows: {stats.get('ics_flows', 0)}")
    
    if args.detailed:
        logger.info(f"\nThreat Analysis:")
        logger.info(f"  - Lateral Movement: Check lateral_movement.csv")
        logger.info(f"  - Data Exfiltration: Check data_exfiltration.csv")
        logger.info(f"  - ICS Anomalies: Check ics_anomalies.csv")
    
    logger.info("\n" + "="*60)
    logger.info("✅ DETECTION COMPLETED!")
    logger.info("="*60)


if __name__ == '__main__':
    main()
