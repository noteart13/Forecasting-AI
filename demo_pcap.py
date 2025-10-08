"""
Demo script để test phân tích file .pcap từ Wireshark
Hỗ trợ phát hiện Lateral Movement, Data Exfiltration và ICS Anomalies
"""
import argparse
import logging
import sys
import shutil
from pathlib import Path

from src.network_loader import NetworkLoader
from src.anomaly_detector import ICSAnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def clean_output_directory(output_dir):
    """Clean old output files before creating new analysis"""
    output_path = Path(output_dir)
    if output_path.exists():
        logger.info(f"🧹 Cleaning old output files in {output_dir}...")
        # Remove all files in directory but keep the directory
        for item in output_path.iterdir():
            if item.is_file():
                item.unlink()
                logger.info(f"   Deleted: {item.name}")
            elif item.is_dir():
                shutil.rmtree(item)
                logger.info(f"   Deleted folder: {item.name}")
        logger.info("✅ Output directory cleaned")
    else:
        logger.info(f"📁 Creating new output directory: {output_dir}")


def main():
    parser = argparse.ArgumentParser(description='Demo PCAP Analysis for ICS/SCADA Networks')
    parser.add_argument('--pcap', type=str, required=True,
                       help='Path to PCAP file to analyze')
    parser.add_argument('--model', type=str, default='output/anomaly_model.pkl',
                       help='Path to trained model (optional)')
    parser.add_argument('--output', type=str, default='output/pcap_analysis',
                       help='Output directory for results')
    parser.add_argument('--detailed', action='store_true',
                       help='Run detailed threat analysis')
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("🔍 PCAP ANALYSIS DEMO - ICS/SCADA NETWORK SECURITY")
    logger.info("="*80)
    
    # Check if PCAP file exists
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        logger.error(f"❌ PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    # Clean old output files and create fresh directory
    output_dir = Path(args.output)
    clean_output_directory(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Load PCAP data
        logger.info(f"\n📦 Loading PCAP file: {args.pcap}")
        loader = NetworkLoader(str(pcap_path))
        data = loader.load()
        
        if len(data) == 0:
            logger.error("❌ No data loaded from PCAP file")
            sys.exit(1)
        
        # Preprocess data
        logger.info("\n🔄 Preprocessing network flows...")
        data = loader.preprocess()
        
        # Get statistics
        stats = loader.get_statistics()
        logger.info("\n📈 PCAP Analysis Statistics:")
        for key, value in stats.items():
            logger.info(f"  {key}: {value}")
        
        # Initialize detector
        detector = ICSAnomalyDetector()
        
        # Try to load existing model, otherwise train on current data
        model_path = Path(args.model)
        if model_path.exists():
            logger.info(f"\n🔓 Loading existing model from {args.model}")
            detector.load_model(str(model_path))
        else:
            logger.info(f"\n🎯 Training new model on PCAP data...")
            detector.train(data)
            detector.save_model(str(model_path))
        
        # Detect general anomalies
        logger.info("\n🔍 Running anomaly detection...")
        results = detector.predict(data)
        
        n_anomalies = results['is_anomaly'].sum()
        logger.info(f"\n🚨 GENERAL ANOMALIES: {n_anomalies} detected ({n_anomalies/len(results)*100:.2f}%)")
        
        # Save general results
        general_output = output_dir / 'general_anomalies.csv'
        anomalies_only = results[results['is_anomaly'] == 1].copy()
        anomalies_only.to_csv(general_output, index=False)
        logger.info(f"💾 General anomalies saved to {general_output}")
        
        # Detailed threat analysis
        if args.detailed:
            logger.info("\n" + "="*80)
            logger.info("🎯 DETAILED THREAT ANALYSIS")
            logger.info("="*80)
            
            # 1. Lateral Movement Analysis
            logger.info("\n🔍 Analyzing Lateral Movement...")
            lateral = detector.detect_lateral_movement(data)
            if len(lateral) > 0:
                suspicious_lateral = lateral[lateral['is_lateral_movement'] == 1]
                high_risk_lateral = lateral[lateral['is_high_risk'] == 1]
                
                logger.info(f"   Found {len(suspicious_lateral)} suspicious activities")
                logger.info(f"   High risk patterns: {len(high_risk_lateral)}")
                
                lateral_output = output_dir / 'lateral_movement.csv'
                suspicious_lateral.to_csv(lateral_output, index=False)
                logger.info(f"   Saved to {lateral_output}")
                
                # Show top suspicious sources
                if len(suspicious_lateral) > 0:
                    logger.info("\n🔴 TOP SUSPICIOUS SOURCES (Lateral Movement):")
                    top_sources = suspicious_lateral.nlargest(5, 'lateral_score')[
                        ['src_ip', 'unique_dsts', 'unique_ports', 'lateral_score', 'is_port_scan', 'is_host_scan']
                    ]
                    print(top_sources.to_string(index=False))
            
            # 2. Data Exfiltration Analysis
            logger.info("\n🔍 Analyzing Data Exfiltration...")
            exfil = detector.detect_data_exfiltration(data)
            if len(exfil) > 0:
                suspicious_exfil = exfil[exfil['is_exfiltration'] == 1]
                high_risk_exfil = exfil[exfil['is_high_risk'] == 1]
                
                logger.info(f"   Found {len(suspicious_exfil)} suspicious transfers")
                logger.info(f"   High risk patterns: {len(high_risk_exfil)}")
                
                exfil_output = output_dir / 'data_exfiltration.csv'
                suspicious_exfil.to_csv(exfil_output, index=False)
                logger.info(f"   Saved to {exfil_output}")
                
                # Show top suspicious transfers
                if len(suspicious_exfil) > 0:
                    logger.info("\n🔴 TOP SUSPICIOUS TRANSFERS (Data Exfiltration):")
                    top_transfers = suspicious_exfil.nlargest(5, 'exfil_score')[
                        ['src_ip', 'mb_transferred', 'unique_external_dsts', 'exfil_score', 'is_large_transfer', 'is_unusual_time']
                    ]
                    print(top_transfers.to_string(index=False))
            
            # 3. ICS-specific Anomalies Analysis
            logger.info("\n🔍 Analyzing ICS-specific Anomalies...")
            ics_anomalies = detector.detect_ics_anomalies(data)
            if len(ics_anomalies) > 0:
                logger.info(f"   Found {len(ics_anomalies)} anomaly types:")
                for _, row in ics_anomalies.iterrows():
                    logger.info(f"   - {row['type']} ({row['severity']}): {row['description']}")
                
                ics_output = output_dir / 'ics_anomalies.csv'
                ics_anomalies.to_csv(ics_output, index=False)
                logger.info(f"   Saved to {ics_output}")
                
                # Show critical anomalies
                critical_anomalies = ics_anomalies[ics_anomalies['severity'] == 'critical']
                if len(critical_anomalies) > 0:
                    logger.info("\n🔴 CRITICAL ICS ANOMALIES:")
                    for _, row in critical_anomalies.iterrows():
                        logger.info(f"   - {row['type']}: {row['description']}")
            
            # Generate comprehensive attack summary report
            logger.info("\n📝 Generating Attack Summary Report...")
            summary_path = output_dir / 'attack_summary.txt'
            detector.generate_attack_summary(
                results=results,
                lateral_df=lateral if len(lateral) > 0 else None,
                exfil_df=exfil if len(exfil) > 0 else None,
                ics_df=ics_anomalies if len(ics_anomalies) > 0 else None,
                output_path=str(summary_path),
                pcap_file=args.pcap
            )
        
        # Summary report
        logger.info("\n" + "="*80)
        logger.info("📊 PCAP ANALYSIS SUMMARY")
        logger.info("="*80)
        logger.info(f"PCAP file: {args.pcap}")
        logger.info(f"Total flows analyzed: {len(results)}")
        logger.info(f"General anomalies detected: {n_anomalies} ({n_anomalies/len(results)*100:.2f}%)")
        logger.info(f"ICS protocol flows: {stats.get('ics_flows', 0)}")
        logger.info(f"Unique sources: {stats.get('unique_sources', 0)}")
        logger.info(f"Unique destinations: {stats.get('unique_destinations', 0)}")
        logger.info(f"Total bytes: {stats.get('total_bytes', 0):,}")
        
        if args.detailed:
            logger.info(f"\nDetailed Analysis Results:")
            logger.info(f"  - General anomalies: {output_dir / 'general_anomalies.csv'}")
            logger.info(f"  - Lateral Movement: {output_dir / 'lateral_movement.csv'}")
            logger.info(f"  - Data Exfiltration: {output_dir / 'data_exfiltration.csv'}")
            logger.info(f"  - ICS Anomalies: {output_dir / 'ics_anomalies.csv'}")
            logger.info(f"  - 📋 ATTACK SUMMARY: {output_dir / 'attack_summary.txt'}")
            logger.info(f"  - 📋 JSON SUMMARY: {output_dir / 'attack_summary.json'}")
        
        logger.info("\n" + "="*80)
        logger.info("✅ PCAP ANALYSIS COMPLETED!")
        logger.info("="*80)
        
    except Exception as e:
        logger.error(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
