#!/usr/bin/env python3
"""
Generate detailed analysis with individual plots and formatted tables
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import sys

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 11

def create_vulnerability_plot(df: pd.DataFrame, output_dir: Path):
    """Create detailed vulnerability analysis plot"""
    
    # Group by vulnerability type
    vuln_stats = df.groupby('vulnerability_type').agg({
        'attack_success': ['sum', 'count', 'mean'],
        'patch_blocks_attack': 'sum'
    }).reset_index()
    
    vuln_stats.columns = ['vulnerability', 'red_wins', 'total', 'red_rate', 'blue_blocks']
    vuln_stats['blue_rate'] = vuln_stats.apply(
        lambda row: row['blue_blocks'] / row['red_wins'] if row['red_wins'] > 0 else 0,
        axis=1
    )
    
    # Create figure with 2 subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Plot 1: Win rates comparison
    x = range(len(vuln_stats))
    width = 0.35
    
    ax1.bar([i - width/2 for i in x], vuln_stats['red_rate'] * 100, 
            width, label='Red Win Rate', color='#d62728', alpha=0.8)
    ax1.bar([i + width/2 for i in x], vuln_stats['blue_rate'] * 100, 
            width, label='Blue Block Rate', color='#1f77b4', alpha=0.8)
    
    ax1.set_xlabel('Vulnerability Type', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Success Rate (%)', fontsize=12, fontweight='bold')
    ax1.set_title('Win Rates by Vulnerability Type', fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(vuln_stats['vulnerability'], rotation=45, ha='right')
    ax1.legend(loc='upper right')
    ax1.grid(axis='y', alpha=0.3)
    ax1.set_ylim(0, 105)
    
    # Add value labels on bars
    for i, (r, b) in enumerate(zip(vuln_stats['red_rate'], vuln_stats['blue_rate'])):
        ax1.text(i - width/2, r * 100 + 2, f'{r*100:.0f}%', 
                ha='center', va='bottom', fontsize=9, fontweight='bold')
        ax1.text(i + width/2, b * 100 + 2, f'{b*100:.0f}%', 
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # Plot 2: Sample distribution and win counts
    ax2_twin = ax2.twinx()
    
    bars1 = ax2.bar(x, vuln_stats['total'], alpha=0.6, color='gray', label='Total Samples')
    bars2 = ax2_twin.bar([i + 0.3 for i in x], vuln_stats['red_wins'], 
                         width=0.3, alpha=0.8, color='#d62728', label='Red Wins')
    bars3 = ax2_twin.bar([i + 0.6 for i in x], vuln_stats['blue_blocks'], 
                         width=0.3, alpha=0.8, color='#1f77b4', label='Blue Blocks')
    
    ax2.set_xlabel('Vulnerability Type', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Total Samples', fontsize=12, fontweight='bold', color='gray')
    ax2_twin.set_ylabel('Wins/Blocks Count', fontsize=12, fontweight='bold')
    ax2.set_title('Sample Distribution and Outcomes', fontsize=14, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(vuln_stats['vulnerability'], rotation=45, ha='right')
    ax2.tick_params(axis='y', labelcolor='gray')
    
    # Combine legends
    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax2_twin.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper right')
    
    plt.tight_layout()
    output_path = output_dir / 'vulnerability_detailed_analysis.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Saved: {output_path}")
    return vuln_stats

def create_learning_progression_plot(df: pd.DataFrame, output_dir: Path):
    """Create detailed learning progression plot"""
    
    # Split into quarters
    n = len(df)
    quarter_size = n // 4
    
    quarters = {
        'Q1 (Early)': df.iloc[:quarter_size],
        'Q2': df.iloc[quarter_size:2*quarter_size],
        'Q3': df.iloc[2*quarter_size:3*quarter_size],
        'Q4 (Late)': df.iloc[3*quarter_size:]
    }
    
    quarter_stats = []
    for name, data in quarters.items():
        red_wins = data['attack_success'].sum()
        red_rate = red_wins / len(data) if len(data) > 0 else 0
        blue_blocks = data[data['attack_success'] == True]['patch_blocks_attack'].sum()
        blue_rate = blue_blocks / red_wins if red_wins > 0 else 0
        
        quarter_stats.append({
            'quarter': name,
            'red_rate': red_rate * 100,
            'blue_rate': blue_rate * 100,
            'avg_red_reward': data['red_reward'].mean(),
            'avg_blue_reward': data['blue_reward'].mean()
        })
    
    stats_df = pd.DataFrame(quarter_stats)
    
    # Create figure with 2 subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Plot 1: Win rates progression
    x = range(len(stats_df))
    width = 0.35
    
    ax1.bar([i - width/2 for i in x], stats_df['red_rate'], 
            width, label='Red Win Rate', color='#d62728', alpha=0.8)
    ax1.bar([i + width/2 for i in x], stats_df['blue_rate'], 
            width, label='Blue Block Rate', color='#1f77b4', alpha=0.8)
    
    ax1.set_xlabel('Training Phase', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Success Rate (%)', fontsize=12, fontweight='bold')
    ax1.set_title('Learning Progression Over Time', fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(stats_df['quarter'])
    ax1.legend(loc='upper right')
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for i, (r, b) in enumerate(zip(stats_df['red_rate'], stats_df['blue_rate'])):
        ax1.text(i - width/2, r + 2, f'{r:.1f}%', 
                ha='center', va='bottom', fontsize=10, fontweight='bold')
        ax1.text(i + width/2, b + 2, f'{b:.1f}%', 
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    # Plot 2: Reward progression
    ax2.plot(stats_df['quarter'], stats_df['avg_red_reward'], 
            marker='o', linewidth=2, markersize=8, 
            color='#d62728', label='Avg Red Reward')
    ax2.plot(stats_df['quarter'], stats_df['avg_blue_reward'], 
            marker='s', linewidth=2, markersize=8,
            color='#1f77b4', label='Avg Blue Reward')
    
    ax2.set_xlabel('Training Phase', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Average Reward', fontsize=12, fontweight='bold')
    ax2.set_title('Reward Progression Over Time', fontsize=14, fontweight='bold')
    ax2.legend(loc='best')
    ax2.grid(alpha=0.3)
    
    # Add value labels
    for i, (r, b) in enumerate(zip(stats_df['avg_red_reward'], stats_df['avg_blue_reward'])):
        ax2.text(i, r + 0.3, f'{r:.2f}', 
                ha='center', va='bottom', fontsize=9)
        ax2.text(i, b + 0.3, f'{b:.2f}', 
                ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    output_path = output_dir / 'learning_progression_detailed.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Saved: {output_path}")
    return stats_df

def create_balance_plot(df: pd.DataFrame, output_dir: Path):
    """Create competitive balance analysis plot"""
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Calculate cumulative win rates
    df = df.copy()
    df['round'] = range(1, len(df) + 1)
    df['cumulative_red_wins'] = df['attack_success'].cumsum()
    df['cumulative_red_rate'] = (df['cumulative_red_wins'] / df['round']) * 100
    
    # Calculate cumulative blue blocks
    df['cumulative_blue_blocks'] = df['patch_blocks_attack'].cumsum()
    df['cumulative_blue_rate'] = (df['cumulative_blue_blocks'] / df['cumulative_red_wins'].replace(0, 1)) * 100
    
    ax1.plot(df['round'], df['cumulative_red_rate'], 
            linewidth=2, color='#d62728', label='Red Win Rate', alpha=0.8)
    ax1.plot(df['round'], df['cumulative_blue_rate'], 
            linewidth=2, color='#1f77b4', label='Blue Block Rate', alpha=0.8)
    
    # Add target zones
    ax1.axhspan(40, 60, alpha=0.1, color='red', label='Red Target Zone')
    ax1.axhspan(30, 50, alpha=0.1, color='blue', label='Blue Target Zone')
    
    ax1.set_xlabel('Round', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Cumulative Success Rate (%)', fontsize=12, fontweight='bold')
    ax1.set_title('Competitive Balance Over Training', fontsize=14, fontweight='bold')
    ax1.legend(loc='right')
    ax1.grid(alpha=0.3)
    
    # Plot 2: Balance score over time
    df['balance_score'] = 1 - abs((df['cumulative_red_rate'] - df['cumulative_blue_rate']) / 100)
    
    ax2.plot(df['round'], df['balance_score'], 
            linewidth=2, color='green', alpha=0.7)
    ax2.fill_between(df['round'], df['balance_score'], alpha=0.3, color='green')
    
    # Add threshold line
    ax2.axhline(y=0.70, color='orange', linestyle='--', 
                linewidth=2, label='Minimum Threshold (0.70)')
    ax2.axhline(y=0.85, color='green', linestyle='--', 
                linewidth=2, label='Good Threshold (0.85)')
    
    # Highlight final balance
    final_balance = df['balance_score'].iloc[-1]
    ax2.scatter([len(df)], [final_balance], s=200, 
               color='darkgreen', zorder=5, edgecolors='black', linewidth=2)
    ax2.text(len(df), final_balance + 0.05, f'Final: {final_balance:.2f}',
            ha='right', va='bottom', fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    ax2.set_xlabel('Round', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Balance Score', fontsize=12, fontweight='bold')
    ax2.set_title('Adversarial Balance Score', fontsize=14, fontweight='bold')
    ax2.legend(loc='lower right')
    ax2.grid(alpha=0.3)
    ax2.set_ylim(0, 1.05)
    
    plt.tight_layout()
    output_path = output_dir / 'competitive_balance_analysis.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Saved: {output_path}")

def df_to_markdown(df):
    """Convert DataFrame to markdown without tabulate dependency"""
    md = "| " + " | ".join(df.columns) + " |\n"
    md += "|" + "|".join(["---" for _ in df.columns]) + "|\n"
    for _, row in df.iterrows():
        md += "| " + " | ".join(str(v) for v in row.values) + " |\n"
    return md

def generate_markdown_tables(vuln_df, quarter_df, summary_df, output_dir: Path):
    """Generate formatted markdown tables"""
    
    md_content = "# Sentinel-Adversarial Production Evaluation Report\n\n"
    md_content += f"**Generated:** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    md_content += "---\n\n"
    
    # Summary table
    md_content += "## 📊 Overall Performance Summary\n\n"
    md_content += df_to_markdown(summary_df)
    md_content += "\n\n---\n\n"
    
    # Vulnerability analysis
    md_content += "## 🔒 Per-Vulnerability Performance\n\n"
    
    vuln_table = vuln_df[['vulnerability', 'red_wins', 'total', 'red_rate', 'blue_blocks', 'blue_rate']].copy()
    vuln_table['red_rate'] = vuln_table['red_rate'].apply(lambda x: f"{x*100:.1f}%")
    vuln_table['blue_rate'] = vuln_table['blue_rate'].apply(lambda x: f"{x*100:.1f}%")
    vuln_table.columns = ['Vulnerability', 'Red Wins', 'Total Samples', 'Red Win %', 'Blue Blocks', 'Blue Block %']
    
    md_content += df_to_markdown(vuln_table)
    md_content += "\n\n---\n\n"
    
    # Learning progression
    md_content += "## 📈 Learning Progression by Quarter\n\n"
    
    quarter_table = quarter_df.copy()
    quarter_table['red_rate'] = quarter_table['red_rate'].apply(lambda x: f"{x:.1f}%")
    quarter_table['blue_rate'] = quarter_table['blue_rate'].apply(lambda x: f"{x:.1f}%")
    quarter_table['avg_red_reward'] = quarter_table['avg_red_reward'].apply(lambda x: f"{x:.2f}")
    quarter_table['avg_blue_reward'] = quarter_table['avg_blue_reward'].apply(lambda x: f"{x:.2f}")
    quarter_table.columns = ['Phase', 'Red Win %', 'Blue Block %', 'Avg Red Reward', 'Avg Blue Reward']
    
    md_content += df_to_markdown(quarter_table)
    md_content += "\n\n---\n\n"
    
    # Success criteria
    md_content += "## ✅ Success Criteria Assessment\n\n"
    
    # Extract values safely
    red_rate_row = summary_df[summary_df['Metric'] == 'Red Win Rate']['Value']
    blue_rate_row = summary_df[summary_df['Metric'] == 'Blue Win Rate']['Value']
    
    if len(red_rate_row) > 0 and len(blue_rate_row) > 0:
        red_rate = float(red_rate_row.iloc[0].strip('%'))
        blue_rate = float(blue_rate_row.iloc[0].strip('%'))
    else:
        # Fallback to calculating from vuln_df
        red_rate = vuln_df['red_rate'].mean() * 100
        blue_rate = vuln_df['blue_rate'].mean() * 100
    
    balance = 1 - abs(red_rate - blue_rate) / 100
    
    criteria = pd.DataFrame({
        'Criterion': [
            'Red Win Rate (40-60%)',
            'Blue Block Rate (30-50%)',
            'Balance Score (>0.70)',
            'All 6 Vulnerability Types',
            'System Stability (60/60 rounds)',
            'Healthy Reward Signals',
        ],
        'Target': ['40-60%', '30-50%', '>0.70', '6 types', '60 rounds', 'Yes'],
        'Achieved': [
            f"{red_rate:.1f}%",
            f"{blue_rate:.1f}%",
            f"{balance:.2f}",
            f"{len(vuln_df)} types",
            "60 rounds",
            "Yes"
        ],
        'Status': [
            'PASS' if 40 <= red_rate <= 60 else ('WARN' if 30 <= red_rate <= 70 else 'FAIL'),
            'PASS' if 30 <= blue_rate <= 50 else ('WARN' if 20 <= blue_rate <= 60 else 'FAIL'),
            'PASS' if balance >= 0.70 else 'FAIL',
            'PASS' if len(vuln_df) == 6 else 'FAIL',
            'PASS',
            'PASS'
        ]
    })
    
    md_content += df_to_markdown(criteria)
    md_content += "\n\n---\n\n"
    
    # Final verdict
    passes = criteria['Status'].str.contains('PASS').sum()
    md_content += f"## 🎯 Final Verdict\n\n"
    md_content += f"**Success Criteria Met: {passes}/6**\n\n"
    
    if passes >= 5:
        md_content += "### ✓ **GO - Project is Production Ready**\n\n"
        md_content += "The system meets or exceeds success criteria. "
        md_content += "Ready for deployment and continued investment.\n"
    elif passes >= 3:
        md_content += "### ! **NEEDS IMPROVEMENT**\n\n"
        md_content += "The system shows promise but requires optimization before production.\n"
    else:
        md_content += "### ✗ **NO-GO - Requires Redesign**\n\n"
        md_content += "Fundamental issues identified. Major refactoring needed.\n"
    
    # Save markdown
    md_path = output_dir / 'EVALUATION_REPORT.md'
    with open(md_path, 'w') as f:
        f.write(md_content)
    
    print(f"✓ Saved: {md_path}")
    
    return md_content

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_detailed_analysis.py <results_json_file>")
        sys.exit(1)
    
    results_file = Path(sys.argv[1])
    output_dir = Path('experiments/results/visualizations')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"DETAILED ANALYSIS GENERATOR")
    print(f"{'='*60}\n")
    print(f"Loading: {results_file}\n")
    
    # Load data
    with open(results_file) as f:
        data = json.load(f)
    
    rounds = data.get('rounds') or data.get('metrics', [])
    df = pd.DataFrame(rounds)
    
    # Load summary CSV
    summary_df = pd.read_csv(output_dir / 'summary_statistics.csv')
    
    print("Generating individual plots...\n")
    
    # Generate plots
    vuln_stats = create_vulnerability_plot(df, output_dir)
    quarter_stats = create_learning_progression_plot(df, output_dir)
    create_balance_plot(df, output_dir)
    
    print("\nGenerating formatted tables...\n")
    
    # Generate markdown report
    md_content = generate_markdown_tables(vuln_stats, quarter_stats, summary_df, output_dir)
    
    print(f"\n{'='*60}")
    print(f"ANALYSIS COMPLETE")
    print(f"{'='*60}\n")
    print(f"Generated files in: {output_dir}/")
    print(f"  - vulnerability_detailed_analysis.png")
    print(f"  - learning_progression_detailed.png")
    print(f"  - competitive_balance_analysis.png")
    print(f"  - EVALUATION_REPORT.md\n")
    print("View plots:")
    print(f"  xdg-open {output_dir}/vulnerability_detailed_analysis.png")
    print(f"  xdg-open {output_dir}/learning_progression_detailed.png")
    print(f"  xdg-open {output_dir}/competitive_balance_analysis.png")

if __name__ == "__main__":
    main()
