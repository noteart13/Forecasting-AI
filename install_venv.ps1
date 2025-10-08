# Install dependencies in virtual environment
Write-Host "🔧 Installing dependencies in virtual environment..." -ForegroundColor Cyan

# Activate venv
& .venv/Scripts/Activate.ps1

# Upgrade pip
Write-Host "`n📦 Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install requirements
Write-Host "`n📦 Installing requirements..." -ForegroundColor Yellow
pip install -r requirements.txt

Write-Host "`n✅ Installation completed!" -ForegroundColor Green
Write-Host "`n🚀 You can now run:" -ForegroundColor Cyan
Write-Host "   python demo.py" -ForegroundColor White
Write-Host "   python demo_pcap.py --pcap your_file.pcap --detailed" -ForegroundColor White
