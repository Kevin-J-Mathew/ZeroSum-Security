#!/usr/bin/env python3
"""
Quick analysis of partial training results
Validates that models are working properly before full production run
"""

import json
import sys
from pathlib import Path
from collections import Counter

def analyze_results(results_file: str):
    """Analyze training results and validate system performance"""
    
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    # Handle both 'rounds' and 'metrics' keys (different checkpoint formats)
    rounds = data.get('rounds') or data.get('metrics', [])
    total_rounds = len(rounds)
    
    # Check vulnerability coverage
    vuln_types = Counter(r['vulnerability_type'] for r in rounds)
    
    # Calculate basic metrics
    red_wins = sum(1 for r in rounds if r['attack_success'])
    blue_blocks = sum(1 for r in rounds if r['attack_success'] and r['patch_blocks_attack'])
    
    red_win_rate = red_wins / total_rounds if total_rounds > 0 else 0
    blue_block_rate = blue_blocks / red_wins if red_wins > 0 else 0
    
    # Calculate learning progression
    if total_rounds >= 20:
        first_20 = rounds[:20]
        last_20 = rounds[-20:]
        
        red_early = sum(1 for r in first_20 if r['attack_success']) / 20
        red_late = sum(1 for r in last_20 if r['attack_success']) / 20
        red_improvement = red_late - red_early
        
        blue_early_wins = sum(1 for r in first_20 if r['attack_success'])
        blue_early = sum(1 for r in first_20 if r['attack_success'] and r['patch_blocks_attack']) / blue_early_wins if blue_early_wins > 0 else 0
        
        blue_late_wins = sum(1 for r in last_20 if r['attack_success'])
        blue_late = sum(1 for r in last_20 if r['attack_success'] and r['patch_blocks_attack']) / blue_late_wins if blue_late_wins > 0 else 0
        blue_improvement = blue_late - blue_early
    else:
        red_improvement = 0
        blue_improvement = 0
    
    # Calculate average rewards
    avg_red_reward = sum(r['red_reward'] for r in rounds) / total_rounds
    avg_blue_reward = sum(r['blue_reward'] for r in rounds) / total_rounds
    
    # Balance score
    balance = 1 - abs(red_win_rate - blue_block_rate)
    
    print("=" * 60)
    print(f"QUICK ANALYSIS: {results_file}")
    print("=" * 60)
    print()
    
    print(f"📊 TOTAL ROUNDS: {total_rounds}")
    print()
    
    print("🎯 PERFORMANCE METRICS:")
    print(f"  Red Win Rate:   {red_win_rate:.1%} ({red_wins}/{total_rounds})")
    print(f"  Blue Block Rate: {blue_block_rate:.1%} ({blue_blocks}/{red_wins})")
    print(f"  Balance Score:   {balance:.2f}")
    print()
    
    print("💰 AVERAGE REWARDS:")
    print(f"  Red:  {avg_red_reward:.2f}")
    print(f"  Blue: {avg_blue_reward:.2f}")
    print()
    
    print("📈 LEARNING PROGRESSION (First 20 vs Last 20):")
    if total_rounds >= 20:
        print(f"  Red Improvement:  {red_improvement:+.1%}")
        print(f"  Blue Improvement: {blue_improvement:+.1%}")
    else:
        print(f"  Need at least 20 rounds for learning analysis")
    print()
    
    print("🔒 VULNERABILITY COVERAGE:")
    for vuln, count in vuln_types.most_common():
        pct = count / total_rounds * 100
        print(f"  {vuln:20s}: {count:3d} rounds ({pct:5.1f}%)")
    print()
    
    # Validation checks
    print("✅ VALIDATION CHECKS:")
    checks_passed = 0
    total_checks = 0
    
    # Check 1: All vulnerability types tested
    total_checks += 1
    if len(vuln_types) == 6:
        print(f"  ✅ All 6 vulnerability types tested")
        checks_passed += 1
    else:
        print(f"  ❌ Only {len(vuln_types)}/6 vulnerability types tested")
    
    # Check 2: Red win rate reasonable
    total_checks += 1
    if 0.20 <= red_win_rate <= 0.90:
        print(f"  ✅ Red win rate in acceptable range (20-90%)")
        checks_passed += 1
    else:
        print(f"  ⚠️  Red win rate {red_win_rate:.1%} outside range")
    
    # Check 3: Blue learning
    total_checks += 1
    if blue_blocks > 0:
        print(f"  ✅ Blue Agent successfully blocking attacks")
        checks_passed += 1
    else:
        print(f"  ⚠️  Blue Agent not blocking any attacks yet")
    
    # Check 4: Balance
    total_checks += 1
    if balance >= 0.50:
        print(f"  ✅ Competition balance acceptable (>0.50)")
        checks_passed += 1
    else:
        print(f"  ⚠️  Competition imbalanced (balance: {balance:.2f})")
    
    # Check 5: No domination
    total_checks += 1
    if red_win_rate < 0.95:
        print(f"  ✅ Red not dominating (<95% win rate)")
        checks_passed += 1
    else:
        print(f"  ⚠️  Red dominating too much")
    
    # Check 6: Rewards healthy
    total_checks += 1
    if -5 <= avg_red_reward <= 30 and -10 <= avg_blue_reward <= 30:
        print(f"  ✅ Reward values in healthy range")
        checks_passed += 1
    else:
        print(f"  ⚠️  Reward values outside expected range")
    
    print()
    print(f"RESULT: {checks_passed}/{total_checks} checks passed")
    print()
    
    # Final verdict
    if checks_passed >= 5:
        print("🎉 VERDICT: Models working properly! Ready for full production run.")
        return 0
    elif checks_passed >= 3:
        print("⚠️  VERDICT: Models mostly working, may need minor adjustments.")
        return 0
    else:
        print("❌ VERDICT: Issues detected, review before production run.")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python quick_analysis.py <results_json_file>")
        print()
        print("Example:")
        print("  python quick_analysis.py experiments/results/training_results_20260208_115003.json")
        sys.exit(1)
    
    results_file = sys.argv[1]
    
    if not Path(results_file).exists():
        print(f"Error: File not found: {results_file}")
        sys.exit(1)
    
    sys.exit(analyze_results(results_file))
