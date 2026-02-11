#!/bin/bash
# Production Evaluation Quick Start Script

echo "======================================"
echo "SENTINEL-ADVERSARIAL PRODUCTION TEST"
echo "======================================"
echo ""

# Check environment
echo "1. Checking environment..."
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Run: python3 -m venv venv"
    exit 1
fi

if [ ! -f ".env" ]; then
    echo "❌ .env file not found. Create it with GROQ_API_KEY"
    exit 1
fi

echo "✓ Environment OK"
echo ""

# Activate venv
echo "2. Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Check dependencies
echo "3. Installing analysis dependencies..."
pip install pandas matplotlib seaborn --quiet
echo "✓ Dependencies installed"
echo ""

# Run production test
echo "4. Starting 200-round production evaluation..."
echo "   Expected duration: 45-60 minutes"
echo "   Monitor for errors - press Ctrl+C to abort if needed"
echo ""
read -p "Press Enter to start production run..."

python -m src.sentinel.orchestrator --config config/production.yaml --rounds 200

# Check if completed successfully
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Production test completed successfully!"
    echo ""
    
    # Get latest results file
    RESULTS_FILE=$(ls -t experiments/results/training_results_*.json | head -1)
    echo "Results saved: $RESULTS_FILE"
    echo ""
    
    # Run analysis
    echo "5. Generating analysis..."
    python results_to_csv.py "$RESULTS_FILE"
    python visualize_training.py "$RESULTS_FILE"
    
    echo ""
    echo "======================================"
    echo "ANALYSIS COMPLETE"
    echo "======================================"
    echo ""
    echo "View results:"
    echo "  1. Summary: experiments/results/visualizations/summary_statistics.csv"
    echo "  2. Plot: experiments/results/visualizations/training_progress.png"
    echo "  3. Per-vuln: experiments/results/visualizations/vulnerability_analysis.csv"
    echo ""
    echo "Open plot with: xdg-open experiments/results/visualizations/training_progress.png"
    echo ""
    echo "Read PRODUCTION_EVALUATION.md for success criteria and next steps."
    
else
    echo ""
    echo "⚠️ Production test encountered errors"
    echo "Check logs: logs/training.log"
    echo "Review PRODUCTION_EVALUATION.md for troubleshooting"
fi
