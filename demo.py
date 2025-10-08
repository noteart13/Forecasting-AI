"""
🚀 DEMO Script - ICS/SCADA Network Anomaly Detection
Chạy toàn bộ workflow: Generate Data -> Train -> Detect
"""
import subprocess
import sys
import os
import shutil
from pathlib import Path

def clean_output_directory(output_dir='output'):
    """Clean old output files before creating new analysis"""
    output_path = Path(output_dir)
    if output_path.exists():
        print(f"\n🧹 Cleaning old output files in {output_dir}...")
        # Remove all files in directory but keep the directory
        for item in output_path.iterdir():
            if item.is_file():
                print(f"   Deleted: {item.name}")
                item.unlink()
        print("✅ Output directory cleaned\n")

def run_command(cmd, description):
    """Run command và hiển thị output"""
    print(f"\n{'='*60}")
    print(f"▶️  {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            capture_output=False,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║  🔒 ICS/SCADA Network Anomaly Detection - DEMO  🔒       ║
    ║  AI-powered threat detection for Industrial Networks      ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Clean old output files
    clean_output_directory('output')
    
    # Check directories
    Path("data").mkdir(exist_ok=True)
    Path("output").mkdir(exist_ok=True)
    
    # Step 1: Generate Network Data
    print("\n📊 STEP 1: Generate Sample Network Traffic Data")
    print("   - Creating 10,000 network flows")
    print("   - Injecting ~5% anomalies (Lateral Movement, Data Exfil, ICS anomalies)")
    
    if not run_command(
        f"{sys.executable} scripts/generate_network_data.py",
        "🌐 Generating sample network traffic..."
    ):
        print("\n❌ Failed to generate data. Exiting.")
        return
    
    # Step 2: Train Model
    print("\n\n🧠 STEP 2: Train Anomaly Detection Model")
    print("   - Using Isolation Forest algorithm")
    print("   - Learning normal traffic baseline")
    print("   - Contamination: 5%")
    
    if not run_command(
        f"{sys.executable} train.py --data data/network_traffic.csv --output output/anomaly_model.pkl",
        "🎓 Training model on normal traffic..."
    ):
        print("\n❌ Training failed. Exiting.")
        return
    
    # Step 3: Detect Anomalies
    print("\n\n🔍 STEP 3: Detect Anomalies & Threats")
    print("   - Running anomaly detection")
    print("   - Analyzing Lateral Movement")
    print("   - Analyzing Data Exfiltration")
    print("   - Analyzing ICS-specific anomalies")
    
    if not run_command(
        f"{sys.executable} detect.py --data data/network_traffic.csv --model output/anomaly_model.pkl --detailed",
        "🚨 Detecting threats in network traffic..."
    ):
        print("\n❌ Detection failed.")
        return
    
    # Summary
    print("\n\n" + "="*60)
    print("✅ DEMO COMPLETED SUCCESSFULLY!")
    print("="*60)
    
    print("\n📁 Output Files:")
    output_dir = Path("output")
    if output_dir.exists():
        for file in output_dir.glob("*.csv"):
            size_kb = file.stat().st_size / 1024
            print(f"   ✓ {file.name:<30} ({size_kb:.1f} KB)")
        for file in output_dir.glob("*.pkl"):
            size_kb = file.stat().st_size / 1024
            print(f"   ✓ {file.name:<30} ({size_kb:.1f} KB)")
        for file in output_dir.glob("*.json"):
            size_kb = file.stat().st_size / 1024
            print(f"   ✓ {file.name:<30} ({size_kb:.1f} KB)")
    
    print("\n💡 Next Steps:")
    print("   1. Review anomalies: output/anomalies_detected.csv")
    print("   2. Check lateral movement: output/lateral_movement.csv")
    print("   3. Check data exfil: output/data_exfiltration.csv")
    print("   4. Check ICS anomalies: output/ics_anomalies.csv")
    
    print("\n🔧 Use with your own data:")
    print("   python train.py --data your_normal_traffic.csv")
    print("   python detect.py --data your_test_traffic.csv --detailed")
    
    print("\n🐳 Run with Docker:")
    print("   cd docker && docker-compose up demo")
    
    print("\n" + "="*60)
    print("🔐 ICS/SCADA Networks Protected with AI! 🚀")
    print("="*60 + "\n")

if __name__ == '__main__':
    main()
