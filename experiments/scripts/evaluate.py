"""
experiments/scripts/evaluate.py

Comprehensive evaluation of the Sentinel-Adversarial system.
"""

import json
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
from scipy import stats
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SentinelEvaluator:
    """Evaluate Sentinel-Adversarial system performance."""
    
    def __init__(self, results_path: str):
        """
        Initialize evaluator.
        
        Args:
            results_path: Path to training results JSON
        """
        with open(results_path, 'r') as f:
            self.results = json.load(f)
        
        self.metrics = self.results['metrics']
        logger.info(f"Loaded {len(self.metrics)} rounds of metrics")
    
    def compute_statistics(self) -> Dict[str, Any]:
        """Compute comprehensive statistics."""
        
        red_wins = [m['attack_success'] for m in self.metrics]
        blue_wins = [m['patch_blocks_attack'] for m in self.metrics]
        red_rewards = [m['red_reward'] for m in self.metrics]
        blue_rewards = [m['blue_reward'] for m in self.metrics]
        
        stats_dict = {
            'overall': {
                'total_rounds': len(self.metrics),
                'red_win_rate': np.mean(red_wins),
                'blue_win_rate': np.mean(blue_wins),
                'avg_red_reward': np.mean(red_rewards),
                'avg_blue_reward': np.mean(blue_rewards),
                'red_reward_std': np.std(red_rewards),
                'blue_reward_std': np.std(blue_rewards),
            },
            'by_vulnerability_type': self._stats_by_vuln_type(),
            'convergence': self._convergence_analysis(),
            'patch_quality': self._patch_quality_analysis(),
        }
        
        return stats_dict
    
    def _stats_by_vuln_type(self) -> Dict[str, Dict[str, float]]:
        """Compute statistics grouped by vulnerability type."""
        
        vuln_types = set(m['vulnerability_type'] for m in self.metrics)
        stats = {}
        
        for vuln_type in vuln_types:
            relevant_metrics = [m for m in self.metrics if m['vulnerability_type'] == vuln_type]
            
            if relevant_metrics:
                stats[vuln_type] = {
                    'count': len(relevant_metrics),
                    'red_win_rate': np.mean([m['attack_success'] for m in relevant_metrics]),
                    'blue_win_rate': np.mean([m['patch_blocks_attack'] for m in relevant_metrics]),
                    'avg_red_reward': np.mean([m['red_reward'] for m in relevant_metrics]),
                    'avg_blue_reward': np.mean([m['blue_reward'] for m in relevant_metrics]),
                }
        
        return stats
    
    def _convergence_analysis(self) -> Dict[str, Any]:
        """Analyze convergence over time."""
        
        window_size = 50
        blue_win_rates = []
        
        for i in range(window_size, len(self.metrics), window_size):
            window = self.metrics[i-window_size:i]
            win_rate = np.mean([m['patch_blocks_attack'] for m in window])
            blue_win_rates.append(win_rate)
        
        # Find convergence point (when win rate stays above 90%)
        convergence_round = None
        for i, rate in enumerate(blue_win_rates):
            if rate >= 0.90:
                # Check if it stays above 90% for next 3 windows
                if i + 3 < len(blue_win_rates):
                    if all(r >= 0.90 for r in blue_win_rates[i:i+3]):
                        convergence_round = (i + 1) * window_size
                        break
        
        return {
            'converged': convergence_round is not None,
            'convergence_round': convergence_round,
            'final_win_rate': blue_win_rates[-1] if blue_win_rates else 0.0,
        }
    
    def _patch_quality_analysis(self) -> Dict[str, float]:
        """Analyze patch quality metrics."""
        
        patches = [m for m in self.metrics if m['patch_generated']]
        
        if not patches:
            return {}
        
        return {
            'patch_generation_rate': len(patches) / len(self.metrics),
            'patch_success_rate': np.mean([m['patch_blocks_attack'] for m in patches]),
            'test_pass_rate': np.mean([m['tests_pass'] for m in patches]),
        }
    
    def compare_baselines(self, baseline_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare against baseline systems.
        
        Args:
            baseline_results: Dictionary with baseline system results
                Format: {'bandit': {'detection_rate': 0.75, ...}, ...}
        
        Returns:
            Comparison results
        """
        sentinel_detection = np.mean([m['attack_success'] for m in self.metrics])
        
        comparisons = {}
        for system, results in baseline_results.items():
            baseline_detection = results.get('detection_rate', 0.0)
            improvement = ((sentinel_detection - baseline_detection) / baseline_detection) * 100
            
            # Statistical test
            # Simulate baseline results for statistical test
            sentinel_detections = [m['attack_success'] for m in self.metrics]
            baseline_detections = [baseline_detection] * len(sentinel_detections)
            
            statistic, p_value = stats.wilcoxon(sentinel_detections, baseline_detections)
            
            comparisons[system] = {
                'baseline_detection_rate': baseline_detection,
                'sentinel_detection_rate': sentinel_detection,
                'improvement_percent': improvement,
                'statistically_significant': p_value < 0.05,
                'p_value': p_value,
            }
        
        return comparisons
    
    def generate_plots(self, output_dir: str = 'experiments/results/plots') -> None:
        """Generate visualization plots."""
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set style
        sns.set_style('whitegrid')
        
        # 1. Win rates over time
        self._plot_win_rates(output_dir)
        
        # 2. Rewards over time
        self._plot_rewards(output_dir)
        
        # 3. Vulnerability type breakdown
        self._plot_vuln_breakdown(output_dir)
        
        # 4. Patch quality
        self._plot_patch_quality(output_dir)
        
        logger.info(f"Saved plots to {output_dir}")
    
    def _plot_win_rates(self, output_dir: Path) -> None:
        """Plot win rates over time."""
        
        window_size = 50
        rounds = list(range(window_size, len(self.metrics) + 1, window_size))
        
        red_rates = []
        blue_rates = []
        
        for i in range(window_size, len(self.metrics) + 1, window_size):
            window = self.metrics[i-window_size:i]
            red_rates.append(np.mean([m['attack_success'] for m in window]))
            blue_rates.append(np.mean([m['patch_blocks_attack'] for m in window]))
        
        plt.figure(figsize=(10, 6))
        plt.plot(rounds, red_rates, label='Red Agent Win Rate', color='red', linewidth=2)
        plt.plot(rounds, blue_rates, label='Blue Agent Win Rate', color='blue', linewidth=2)
        plt.axhline(y=0.5, color='gray', linestyle='--', label='50% Baseline')
        plt.xlabel('Training Round')
        plt.ylabel('Win Rate')
        plt.title('Agent Win Rates Over Training')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / 'win_rates.png', dpi=300)
        plt.close()
    
    def _plot_rewards(self, output_dir: Path) -> None:
        """Plot rewards over time."""
        
        rounds = [m['round_number'] for m in self.metrics]
        red_rewards = [m['red_reward'] for m in self.metrics]
        blue_rewards = [m['blue_reward'] for m in self.metrics]
        
        # Smooth with moving average
        window = 50
        red_smooth = np.convolve(red_rewards, np.ones(window)/window, mode='valid')
        blue_smooth = np.convolve(blue_rewards, np.ones(window)/window, mode='valid')
        rounds_smooth = rounds[window-1:]
        
        plt.figure(figsize=(10, 6))
        plt.plot(rounds_smooth, red_smooth, label='Red Agent', color='red', linewidth=2)
        plt.plot(rounds_smooth, blue_smooth, label='Blue Agent', color='blue', linewidth=2)
        plt.xlabel('Training Round')
        plt.ylabel('Average Reward')
        plt.title('Agent Rewards Over Training (50-round MA)')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / 'rewards.png', dpi=300)
        plt.close()
    
    def _plot_vuln_breakdown(self, output_dir: Path) -> None:
        """Plot vulnerability type breakdown."""
        
        vuln_types = {}
        for m in self.metrics:
            vtype = m['vulnerability_type']
            if vtype not in vuln_types:
                vuln_types[vtype] = {'total': 0, 'detected': 0}
            vuln_types[vtype]['total'] += 1
            if m['attack_success']:
                vuln_types[vtype]['detected'] += 1
        
        types = list(vuln_types.keys())
        detection_rates = [vuln_types[t]['detected'] / vuln_types[t]['total'] for t in types]
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(types, detection_rates, color='steelblue')
        plt.xlabel('Vulnerability Type')
        plt.ylabel('Detection Rate')
        plt.title('Detection Rate by Vulnerability Type')
        plt.xticks(rotation=45, ha='right')
        plt.ylim([0, 1.0])
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2%}',
                    ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(output_dir / 'vuln_breakdown.png', dpi=300)
        plt.close()
    
    def _plot_patch_quality(self, output_dir: Path) -> None:
        """Plot patch quality metrics."""
        
        patches = [m for m in self.metrics if m['patch_generated']]
        
        if not patches:
            return
        
        quality_metrics = {
            'Blocks Attack': np.mean([m['patch_blocks_attack'] for m in patches]),
            'Tests Pass': np.mean([m['tests_pass'] for m in patches]),
        }
        
        plt.figure(figsize=(8, 6))
        bars = plt.bar(quality_metrics.keys(), quality_metrics.values(), color=['green', 'orange'])
        plt.ylabel('Success Rate')
        plt.title('Patch Quality Metrics')
        plt.ylim([0, 1.0])
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2%}',
                    ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(output_dir / 'patch_quality.png', dpi=300)
        plt.close()
    
    def generate_report(self, output_path: str = 'experiments/results/evaluation_report.txt') -> None:
        """Generate text evaluation report."""
        
        stats = self.compute_statistics()
        
        report = f"""
========================================
SENTINEL-ADVERSARIAL EVALUATION REPORT
========================================

OVERALL STATISTICS
------------------
Total Training Rounds: {stats['overall']['total_rounds']}
Red Agent Win Rate: {stats['overall']['red_win_rate']:.2%}
Blue Agent Win Rate: {stats['overall']['blue_win_rate']:.2%}
Average Red Reward: {stats['overall']['avg_red_reward']:.2f} (±{stats['overall']['red_reward_std']:.2f})
Average Blue Reward: {stats['overall']['avg_blue_reward']:.2f} (±{stats['overall']['blue_reward_std']:.2f})

CONVERGENCE ANALYSIS
--------------------
Converged: {stats['convergence']['converged']}
Convergence Round: {stats['convergence']['convergence_round'] or 'N/A'}
Final Win Rate: {stats['convergence']['final_win_rate']:.2%}

PATCH QUALITY
-------------
Patch Generation Rate: {stats['patch_quality'].get('patch_generation_rate', 0):.2%}
Patch Success Rate: {stats['patch_quality'].get('patch_success_rate', 0):.2%}
Test Pass Rate: {stats['patch_quality'].get('test_pass_rate', 0):.2%}

PERFORMANCE BY VULNERABILITY TYPE
----------------------------------
"""
        
        for vuln_type, vuln_stats in stats['by_vulnerability_type'].items():
            report += f"\n{vuln_type.upper()}:\n"
            report += f"  Count: {vuln_stats['count']}\n"
            report += f"  Red Win Rate: {vuln_stats['red_win_rate']:.2%}\n"
            report += f"  Blue Win Rate: {vuln_stats['blue_win_rate']:.2%}\n"
        
        # Save report
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(report)
        
        logger.info(f"Saved evaluation report to {output_path}")
        print(report)


def main():
    parser = argparse.ArgumentParser(description='Evaluate Sentinel-Adversarial')
    parser.add_argument('--results', type=str, required=True,
                        help='Path to training results JSON')
    parser.add_argument('--plots', action='store_true',
                        help='Generate visualization plots')
    parser.add_argument('--report', action='store_true',
                        help='Generate text report')
    
    args = parser.parse_args()
    
    evaluator = SentinelEvaluator(args.results)
    
    # Compute and display statistics
    stats = evaluator.compute_statistics()
    print(json.dumps(stats, indent=2))
    
    # Generate plots
    if args.plots:
        evaluator.generate_plots()
    
    # Generate report
    if args.report:
        evaluator.generate_report()


if __name__ == "__main__":
    main()
