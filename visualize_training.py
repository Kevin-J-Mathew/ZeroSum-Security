#!/usr/bin/env python3
"""
Visualize and analyze adversarial training results.

Usage:
    python visualize_training.py experiments/results/training_results_*.json
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_training_results(results_path: str) -> Dict[str, Any]:
    """Load training results from JSON file."""
    with open(results_path, 'r') as f:
        return json.load(f)


def create_metrics_dataframe(results: Dict[str, Any]) -> pd.DataFrame:
    """Convert metrics to pandas DataFrame."""
    metrics = results['metrics']
    df = pd.DataFrame(metrics)
    
    # Add round numbers
    df['round'] = range(1, len(df) + 1)
    
    # Add cumulative win rates
    df['red_cumulative_wins'] = df['attack_success'].cumsum()
    df['blue_cumulative_wins'] = df['patch_blocks_attack'].cumsum()
    df['red_win_rate'] = df['red_cumulative_wins'] / df['round']
    df['blue_win_rate'] = df['blue_cumulative_wins'] / df['round']
    
    return df


def plot_training_progress(df: pd.DataFrame, output_dir: Path):
    """Plot comprehensive training progress."""
    sns.set_style("whitegrid")
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    # 1. Win Rates Over Time
    ax = axes[0, 0]
    ax.plot(df['round'], df['red_win_rate'] * 100, label='Red Agent', color='red', linewidth=2)
    ax.plot(df['round'], df['blue_win_rate'] * 100, label='Blue Agent', color='blue', linewidth=2)
    ax.set_xlabel('Round', fontsize=12)
    ax.set_ylabel('Win Rate (%)', fontsize=12)
    ax.set_title('Win Rates Over Time', fontsize=14, fontweight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    
    # 2. Rewards Over Time
    ax = axes[0, 1]
    # Use rolling average to smooth the plot
    window = min(10, len(df) // 5)
    if window > 1:
        red_rewards_smooth = df['red_reward'].rolling(window=window).mean()
        blue_rewards_smooth = df['blue_reward'].rolling(window=window).mean()
    else:
        red_rewards_smooth = df['red_reward']
        blue_rewards_smooth = df['blue_reward']
    
    ax.plot(df['round'], red_rewards_smooth, label='Red Agent', color='red', linewidth=2)
    ax.plot(df['round'], blue_rewards_smooth, label='Blue Agent', color='blue', linewidth=2)
    ax.set_xlabel('Round', fontsize=12)
    ax.set_ylabel('Average Reward', fontsize=12)
    ax.set_title(f'Rewards Over Time ({window}-round moving average)', fontsize=14, fontweight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    
    # 3. Vulnerability Type Distribution
    ax = axes[1, 0]
    vuln_counts = df['vulnerability_type'].value_counts()
    vuln_counts.plot(kind='bar', ax=ax, color='steelblue')
    ax.set_xlabel('Vulnerability Type', fontsize=12)
    ax.set_ylabel('Count', fontsize=12)
    ax.set_title('Vulnerability Type Distribution', fontsize=14, fontweight='bold')
    ax.tick_params(axis='x', rotation=45)
    ax.grid(True, alpha=0.3, axis='y')
    
    # 4. Attack Success vs Patch Effectiveness
    ax = axes[1, 1]
    metrics_summary = {
        'Red Wins': df['attack_success'].sum(),
        'Blue Blocks': df['patch_blocks_attack'].sum(),
        'No Attack': len(df) - df['attack_success'].sum() - df['patch_blocks_attack'].sum()
    }
    colors = ['red', 'blue', 'gray']
    ax.pie(metrics_summary.values(), labels=metrics_summary.keys(), autopct='%1.1f%%',
           colors=colors, startangle=90)
    ax.set_title('Overall Outcome Distribution', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    
    # Save plot
    output_path = output_dir / 'training_progress.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✓ Saved plot: {output_path}")
    plt.close()


def create_summary_table(df: pd.DataFrame, results: Dict[str, Any], output_dir: Path):
    """Create and save summary statistics table."""
    summary = {
        'Metric': [
            'Total Rounds',
            'Red Win Rate',
            'Blue Win Rate',
            'Avg Red Reward',
            'Avg Blue Reward',
            'Max Red Reward',
            'Max Blue Reward',
            'Min Red Reward',
            'Min Blue Reward',
        ],
        'Value': [
            f"{len(df)}",
            f"{df['attack_success'].mean():.2%}",
            f"{(df[df['attack_success'] == True]['patch_blocks_attack'].sum() / df['attack_success'].sum() if df['attack_success'].sum() > 0 else 0):.2%}",
            f"{df['red_reward'].mean():.2f}",
            f"{df['blue_reward'].mean():.2f}",
            f"{df['red_reward'].max():.2f}",
            f"{df['blue_reward'].max():.2f}",
            f"{df['red_reward'].min():.2f}",
            f"{df['blue_reward'].min():.2f}",
        ]
    }
    
    summary_df = pd.DataFrame(summary)
    
    # Print to console
    print("\n" + "="*50)
    print("TRAINING SUMMARY")
    print("="*50)
    print(summary_df.to_string(index=False))
    print("="*50 + "\n")
    
    # Save to CSV
    summary_path = output_dir / 'summary_statistics.csv'
    summary_df.to_csv(summary_path, index=False)
    print(f"✓ Saved summary: {summary_path}")


def create_per_round_csv(df: pd.DataFrame, output_dir: Path):
    """Save per-round metrics as CSV."""
    # Select key columns
    output_df = df[[
        'round', 'vulnerability_type', 'attack_success', 'patch_blocks_attack',
        'red_reward', 'blue_reward', 'red_win_rate', 'blue_win_rate'
    ]].copy()
    
    output_path = output_dir / 'per_round_metrics.csv'
    output_df.to_csv(output_path, index=False)
    print(f"✓ Saved per-round data: {output_path}")


def create_vulnerability_analysis(df: pd.DataFrame, output_dir: Path):
    """Analyze performance by vulnerability type."""
    vuln_analysis = df.groupby('vulnerability_type').agg({
        'attack_success': ['sum', 'mean', 'count'],
        'patch_blocks_attack': ['sum', 'mean'],
        'red_reward': 'mean',
        'blue_reward': 'mean'
    }).round(2)
    
    # Flatten column names
    vuln_analysis.columns = ['_'.join(col).strip() for col in vuln_analysis.columns.values]
    vuln_analysis = vuln_analysis.rename(columns={
        'attack_success_sum': 'red_wins',
        'attack_success_mean': 'red_win_rate',
        'attack_success_count': 'total_rounds',
        'patch_blocks_attack_sum': 'blue_wins',
        'patch_blocks_attack_mean': 'blue_win_rate',
        'red_reward_mean': 'avg_red_reward',
        'blue_reward_mean': 'avg_blue_reward'
    })
    
    print("\nPER-VULNERABILITY ANALYSIS")
    print("="*80)
    print(vuln_analysis.to_string())
    print("="*80 + "\n")
    
    output_path = output_dir / 'vulnerability_analysis.csv'
    vuln_analysis.to_csv(output_path)
    print(f"✓ Saved vulnerability analysis: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python visualize_training.py <results_json_file>")
        print("\nExample:")
        print("  python visualize_training.py experiments/results/training_results_20260208_113808.json")
        sys.exit(1)
    
    results_path = Path(sys.argv[1])
    
    if not results_path.exists():
        print(f"Error: File not found: {results_path}")
        sys.exit(1)
    
    print(f"\nLoading results from: {results_path}")
    results = load_training_results(results_path)
    
    # Create output directory
    output_dir = results_path.parent / 'visualizations'
    output_dir.mkdir(exist_ok=True)
    
    # Convert to DataFrame
    df = create_metrics_dataframe(results)
    
    # Generate visualizations and analysis
    print("\nGenerating visualizations and analysis...")
    plot_training_progress(df, output_dir)
    create_summary_table(df, results, output_dir)
    create_per_round_csv(df, output_dir)
    create_vulnerability_analysis(df, output_dir)
    
    print(f"\n✓ All outputs saved to: {output_dir}")
    print(f"\nTo view the plot, run:")
    print(f"  xdg-open {output_dir}/training_progress.png")


if __name__ == '__main__':
    main()
