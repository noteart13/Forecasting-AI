# Test script - Demo tự động clean output files
Write-Host "🧪 Testing Auto-Clean Demo Feature" -ForegroundColor Cyan
Write-Host "="*60

# Activate venv
& .venv/Scripts/Activate.ps1

Write-Host "`n1️⃣ Running PCAP Demo with Auto-Clean..." -ForegroundColor Yellow
python demo_pcap.py --pcap "$env:USERPROFILE\Downloads\DEMO_AI.pcapng" --detailed

Write-Host "`n✅ Check output/pcap_analysis/ for fresh results!" -ForegroundColor Green
Write-Host "   - Old files deleted automatically" -ForegroundColor White
Write-Host "   - New analysis created" -ForegroundColor White
