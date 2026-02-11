#!/usr/bin/env python3
"""
Convert training results JSON to CSV for easy analysis.

Usage:
    python results_to_csv.py experiments/results/training_results_*.json
"""

import json
import csv
import sys
from pathlib import Path


def convert_json_to_csv(json_path: Path):
    """Convert training results JSON to CSV."""
    
    # Load JSON
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # Create CSV path
    csv_path = json_path.with_suffix('.csv')
    
    # Write CSV
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow([
            'round', 'vulnerability_type', 'attack_success', 'patch_generated',
            'patch_blocks_attack', 'tests_pass', 'red_reward', 'blue_reward',
            'execution_time', 'code_sample_id'
        ])
        
        # Data rows
        for metric in data['metrics']:
            writer.writerow([
                metric['round_number'],
                metric['vulnerability_type'],
                int(metric['attack_success']),
                int(metric['patch_generated']),
                int(metric['patch_blocks_attack']),
                int(metric['tests_pass']),
                f"{metric['red_reward']:.2f}",
                f"{metric['blue_reward']:.2f}",
                f"{metric['execution_time']:.2f}",
                metric.get('code_sample_id', 'N/A')
            ])
    
    print(f"✓ Converted: {csv_path}")
    return csv_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python results_to_csv.py <results_json_file>")
        print("\nExample:")
        print("  python results_to_csv.py experiments/results/training_results_20260208_113808.json")
        print("\nOr convert all results:")
        print("  python results_to_csv.py experiments/results/training_results_*.json")
        sys.exit(1)
    
    for json_file in sys.argv[1:]:
        json_path = Path(json_file)
        
        if not json_path.exists():
            print(f"Warning: File not found: {json_path}")
            continue
        
        convert_json_to_csv(json_path)
    
    print("\nDone! CSV files can be opened in Excel, Google Sheets, or plotted with pandas.")


if __name__ == '__main__':
    main()
