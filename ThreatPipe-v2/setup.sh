#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# ThreatPipe v2 — One-Click Setup
# ═══════════════════════════════════════════════════════════════
# Run this ONCE on your SIFT Workstation (or any Debian/Ubuntu):
#   chmod +x setup.sh && ./setup.sh
# ═══════════════════════════════════════════════════════════════

set -e

echo "🔍 ThreatPipe v2 — Setup Starting..."
echo ""

# ── 1. Create virtual environment ──────────────────────────────
echo "📦 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# ── 2. Install Python dependencies ────────────────────────────
echo "📥 Installing Python packages..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# ── 3. Create forensic test files on disk ─────────────────────
echo "🔧 Creating forensic test evidence on disk (The Crime Scene)..."
python3 setup_test_evidence.py

# ── 4. Generate realistic attack logs ─────────────────────────
echo "📝 Generating realistic attack logs (The Camera Footage)..."
python3 generate_test_logs.py --size medium

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ SETUP COMPLETE!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "To run the dashboard:"
echo "  source venv/bin/activate"
echo "  export MISTRAL_API_KEY='your-key-here'"
echo "  streamlit run dashboard.py"
echo ""
echo "To run the CLI:"
echo "  source venv/bin/activate"
echo "  export MISTRAL_API_KEY='your-key-here'"
echo "  python stream_run.py realistic_attack.log"
echo ""
echo "To generate different log sizes (tests LLM sliding window):"
echo "  python generate_test_logs.py --size small"
echo "  python generate_test_logs.py --size large"
echo "════════════════════════════════════════════════════════════"
