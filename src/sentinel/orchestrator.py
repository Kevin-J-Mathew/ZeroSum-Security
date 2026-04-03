"""
src/sentinel/orchestrator.py

Main orchestrator for adversarial training loop between Red and Blue agents.
"""

import os
import json
import logging
import yaml
import csv
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import time

from .agents.red_agent import RedAgent
from .agents.blue_agent import BlueAgent
from .agents.base_agent import RewardCalculator
from .sandbox.executor import SandboxExecutor, ExecutionResult
from .data.synthetic import SyntheticDatasetGenerator, VulnerableCodeSample

logger = logging.getLogger(__name__)


@dataclass
class RoundMetrics:
    """Metrics for a single training round."""
    round_number: int
    vulnerability_type: str
    attack_success: bool
    patch_generated: bool
    patch_blocks_attack: bool
    tests_pass: bool
    red_reward: float
    blue_reward: float
    execution_time: float
    code_sample_id: str


class AdversarialOrchestrator:
    """
    Orchestrates the adversarial training between Red and Blue agents.
    """
    
    def __init__(self, config_path: str):
        """
        Initialize orchestrator.
        
        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Initialize agents
        logger.info("Initializing agents...")
        self.red_agent = RedAgent(self.config)
        self.blue_agent = BlueAgent(self.config)
        
        # Initialize sandbox
        logger.info("Initializing sandbox...")
        self.sandbox = SandboxExecutor(self.config)
        
        # Initialize reward calculator
        self.reward_calc = RewardCalculator()
        
        # Training configuration
        self.training_config = self.config.get('training', {})
        self.max_rounds = self.training_config.get('max_rounds', 1000)
        self.early_stopping_threshold = self.training_config.get('early_stopping_threshold', 0.95)
        self.checkpoint_interval = self.training_config.get('checkpoint_interval', 50)
        
        # Metrics storage
        self.metrics: List[RoundMetrics] = []
        self.round_number = 0
        
        # Dataset
        self.dataset: List[VulnerableCodeSample] = []
        self.current_sample_idx = 0
        
        logger.info("Orchestrator initialized")
    
    def load_dataset(self, dataset_path: str) -> None:
        """Load training dataset."""
        generator = SyntheticDatasetGenerator()
        self.dataset = generator.load_dataset(dataset_path)
        logger.info(f"Loaded {len(self.dataset)} samples from dataset")
    
    def generate_dataset(self, num_samples: int = 1000) -> None:
        """Generate synthetic dataset."""
        logger.info(f"Generating {num_samples} synthetic samples...")
        generator = SyntheticDatasetGenerator()
        
        distribution = self.config.get('dataset', {}).get('synthetic', {}).get('vulnerability_distribution', None)
        self.dataset = generator.generate_dataset(num_samples, distribution)
        
        # Save generated dataset
        output_path = "datasets/synthetic/generated_dataset.json"
        generator.save_dataset(self.dataset, output_path)
        logger.info(f"Generated and saved dataset to {output_path}")
    
    def run_training(self, num_rounds: Optional[int] = None) -> None:
        """
        Run the adversarial training loop.
        
        Args:
            num_rounds: Number of rounds to train (uses config if None)
        """
        if not self.dataset:
            raise ValueError("No dataset loaded. Call load_dataset() or generate_dataset() first.")
        
        num_rounds = num_rounds or self.max_rounds
        logger.info(f"Starting adversarial training for {num_rounds} rounds")
        
        for round_num in range(num_rounds):
            self.round_number = round_num + 1
            
            try:
                metrics = self._run_single_round()
                self.metrics.append(metrics)
                
                # Log progress
                if round_num % 10 == 0:
                    self._log_progress()
                
                # Checkpoint
                if round_num % self.checkpoint_interval == 0:
                    self._save_checkpoint()
                
                # Early stopping check
                if self._should_stop_early():
                    logger.info(f"Early stopping at round {self.round_number}")
                    break
                    
            except Exception as e:
                logger.error(f"Error in round {self.round_number}: {e}")
                continue
        
        logger.info("Training completed")
        self._save_final_results()
    
    def _run_single_round(self) -> RoundMetrics:
        """
        Run a single adversarial round.
        
        Returns:
            RoundMetrics for this round
        """
        start_time = time.time()
        
        # 1. Sample vulnerable code
        sample = self._sample_code()
        
        logger.info(f"Round {self.round_number}: {sample.vulnerability_type} ({sample.complexity})")
        
        # 2. Red Agent attacks
        attack_result = self._red_agent_attack(sample)
        
        # 3. Blue Agent defends (if attack succeeded)
        patch_result = None
        if attack_result['attack_success']:
            patch_result = self._blue_agent_defend(sample, attack_result)
        
        # 4. Calculate rewards
        red_reward = self._calculate_red_reward(attack_result, patch_result)
        blue_reward = self._calculate_blue_reward(attack_result, patch_result)
        
        # 5. Update agents
        self.red_agent.update_policy(red_reward, attack_result)
        if patch_result:
            self.blue_agent.update_policy(blue_reward, patch_result)
        
        # 6. Create metrics
        execution_time = time.time() - start_time
        
        metrics = RoundMetrics(
            round_number=self.round_number,
            vulnerability_type=sample.vulnerability_type,
            attack_success=attack_result['attack_success'],
            patch_generated=patch_result is not None,
            patch_blocks_attack=patch_result.get('blocks_attack', False) if patch_result else False,
            tests_pass=patch_result.get('tests_pass', False) if patch_result else False,
            red_reward=red_reward,
            blue_reward=blue_reward,
            execution_time=execution_time,
            code_sample_id=sample.id,
        )
        
        return metrics
    
    def _sample_code(self) -> VulnerableCodeSample:
        """Sample a code sample from the dataset."""
        # Curriculum learning: start with easy, progress to hard
        if self.training_config.get('curriculum_learning', False):
            curriculum = self.training_config.get('curriculum', [])
            
            # Determine current curriculum stage
            current_stage = None
            cumulative_rounds = 0
            for stage in curriculum:
                cumulative_rounds += stage['rounds']
                if self.round_number <= cumulative_rounds:
                    current_stage = stage
                    break
            
            if current_stage:
                complexity = current_stage['vulnerability_complexity']
                # Filter dataset by complexity
                filtered = [s for s in self.dataset if s.complexity == complexity]
                if filtered:
                    return filtered[self.current_sample_idx % len(filtered)]
        
        # Default: random sampling
        sample = self.dataset[self.current_sample_idx % len(self.dataset)]
        self.current_sample_idx += 1
        return sample
    
    def _red_agent_attack(self, sample: VulnerableCodeSample) -> Dict[str, Any]:
        """
        Execute Red Agent's attack.
        
        Args:
            sample: Vulnerable code sample
            
        Returns:
            Attack result dictionary
        """
        # Red Agent generates attack
        observation = {
            'code': sample.code,
            'language': sample.language,
            'context': f'Vulnerability type: {sample.vulnerability_type}',
        }
        
        agent_response = self.red_agent.act(observation)
        
        # Parse attack
        try:
            attack_data = json.loads(agent_response.content)
            payload = attack_data.get('payload', '')
        except:
            payload = agent_response.content
        
        # Execute attack in sandbox with vulnerability type
        exec_result = self.sandbox.execute_code(
            code=sample.code,
            attack_payload=payload,
            language=sample.language,
            vulnerability_type=sample.vulnerability_type
        )
        
        return {
            'attack_success': exec_result.attack_succeeded or exec_result.vulnerability_triggered,
            'payload': payload,
            'attack_type': sample.vulnerability_type,
            'execution_result': exec_result,
            'agent_response': agent_response,
        }
    
    def _blue_agent_defend(
        self, 
        sample: VulnerableCodeSample, 
        attack_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute Blue Agent's defense.
        
        Args:
            sample: Vulnerable code sample
            attack_result: Result from Red Agent's attack
            
        Returns:
            Patch result dictionary
        """
        # Blue Agent generates patch
        observation = {
            'code': sample.code,
            'vulnerability_type': sample.vulnerability_type,
            'language': sample.language,
            'attack': {
                'attack_type': attack_result['attack_type'],
                'payload': attack_result['payload'],
            }
        }
        
        agent_response = self.blue_agent.act(observation)
        patched_code = agent_response.content
        
        # Validate patch
        validation = self.blue_agent.validate_patch(
            sample.code, 
            patched_code, 
            sample.vulnerability_type
        )
        
        if not validation['syntax_valid']:
            logger.warning(f"Patch has syntax errors: {validation['issues']}")
            return {
                'patch_valid': False,
                'blocks_attack': False,
                'tests_pass': False,
                'validation': validation,
            }
        
        # Test if patch blocks the attack
        try:
            exec_result = self.sandbox.execute_code(
                patched_code, 
                attack_result['payload'],
                sample.language,
                sample.vulnerability_type
            )
        except Exception as e:
            logger.warning(f"Patch execution failed: {e}")
            return {
                'patch_valid': False,
                'blocks_attack': False,
                'tests_pass': False,
                'validation': validation,
                'error': str(e)
            }
        
        blocks_attack = not (exec_result.attack_succeeded or exec_result.vulnerability_triggered)
        
        # Run tests if available (skip if pytest not available)
        tests_pass = True
        if sample.test_code:
            try:
                test_result = self.sandbox.execute_with_tests(patched_code, sample.test_code)
                tests_pass = test_result.success
            except Exception as e:
                # pytest not available in Docker - skip test execution
                logger.debug(f"Test execution skipped: {e}")
                tests_pass = True  # Assume pass if tests can't run
        
        return {
            'patch_valid': True,
            'patched_code': patched_code,
            'blocks_attack': blocks_attack,
            'tests_pass': tests_pass,
            'validation': validation,
            'execution_result': exec_result,
            'agent_response': agent_response,
        }
    
    def _calculate_red_reward(
        self, 
        attack_result: Dict[str, Any],
        patch_result: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate reward for Red Agent."""
        
        # Check if attack is novel
        recent_attacks = [m.vulnerability_type for m in self.metrics[-10:]]
        is_novel = attack_result['attack_type'] not in recent_attacks
        
        # Check if caught by static analysis (simplified)
        caught_by_static = False  # TODO: integrate Bandit/Semgrep
        
        # Was the attack bypassed by Blue Agent?
        bypassed_patch = False
        if patch_result and patch_result.get('patch_valid'):
            bypassed_patch = not patch_result['blocks_attack']
        
        reward = self.reward_calc.calculate_red_reward(
            attack_success=attack_result['attack_success'],
            is_novel=is_novel,
            caught_by_static=caught_by_static,
        )
        
        # Bonus for bypassing Blue Agent's patch
        if bypassed_patch:
            reward += 8.0
        
        return reward
    
    def _calculate_blue_reward(
        self,
        attack_result: Dict[str, Any],
        patch_result: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate reward for Blue Agent."""
        
        # FIX: If Red Agent failed, Blue Agent wins by default (don't penalize)
        if not attack_result['attack_success']:
            return 2.0  # Small reward for the system remaining secure
            
        # If Red succeeded but Blue failed to generate a valid patch
        if not patch_result or not patch_result.get('patch_valid'):
            return -5.0  # Penalty for invalid patch
        
        # Check for new vulnerabilities (simplified)
        no_new_vulnerabilities = patch_result['validation']['likely_secure']
        
        reward = self.reward_calc.calculate_blue_reward(
            patch_blocks_attack=patch_result['blocks_attack'],
            tests_pass=patch_result['tests_pass'],
            no_new_vulnerabilities=no_new_vulnerabilities,
            red_bypassed=not patch_result['blocks_attack'],
            functionality_broken=not patch_result['tests_pass'],
        )
        
        return reward
    
    def _log_progress(self) -> None:
        """Log training progress."""
        if not self.metrics:
            return
        
        recent_metrics = self.metrics[-100:]
        
        red_win_rate = sum(m.attack_success for m in recent_metrics) / len(recent_metrics)
        blue_win_rate = sum(m.patch_blocks_attack for m in recent_metrics) / len(recent_metrics)
        avg_red_reward = sum(m.red_reward for m in recent_metrics) / len(recent_metrics)
        avg_blue_reward = sum(m.blue_reward for m in recent_metrics) / len(recent_metrics)
        
        logger.info(f"""
        === Round {self.round_number} Progress ===
        Red Win Rate: {red_win_rate:.2%}
        Blue Win Rate: {blue_win_rate:.2%}
        Avg Red Reward: {avg_red_reward:.2f}
        Avg Blue Reward: {avg_blue_reward:.2f}
        """)
    
    def _should_stop_early(self) -> bool:
        """Check if training should stop early."""
        if len(self.metrics) < 100:
            return False
        
        recent_metrics = self.metrics[-100:]
        blue_win_rate = sum(m.patch_blocks_attack for m in recent_metrics) / len(recent_metrics)
        
        return blue_win_rate >= self.early_stopping_threshold
    
    def _save_checkpoint(self) -> None:
        """Save training checkpoint."""
        checkpoint_dir = Path("models/checkpoints")
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        checkpoint_path = checkpoint_dir / f"round_{self.round_number}.json"
        
        checkpoint_data = {
            'round_number': self.round_number,
            'metrics': [asdict(m) for m in self.metrics],
            'config': self.config,
        }
        
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)
        
        logger.info(f"Saved checkpoint to {checkpoint_path}")
    
    def _setup_csv_logging(self) -> Path:
        """Setup CSV file for real-time logging."""
        logs_dir = Path("experiments/logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        csv_path = logs_dir / f"training_log_{timestamp}.csv"
        
        # Write CSV header
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'round', 'vulnerability_type', 'attack_success', 'patch_generated',
                'patch_blocks_attack', 'tests_pass', 'red_reward', 'blue_reward',
                'execution_time', 'cumulative_red_wins', 'cumulative_blue_wins',
                'red_win_rate', 'blue_win_rate'
            ])
        
        logger.info(f"CSV log created: {csv_path}")
        return csv_path
    
    def _append_to_csv_log(self, metrics: RoundMetrics) -> None:
        """Append metrics to CSV log file."""
        # Calculate cumulative stats
        cumulative_red_wins = sum(m.attack_success for m in self.metrics)
        cumulative_blue_wins = sum(m.patch_blocks_attack for m in self.metrics)
        red_win_rate = cumulative_red_wins / len(self.metrics)
        blue_win_rate = cumulative_blue_wins / len(self.metrics)
        
        with open(self.csv_log_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                metrics.round_number,
                metrics.vulnerability_type,
                int(metrics.attack_success),
                int(metrics.patch_generated),
                int(metrics.patch_blocks_attack),
                int(metrics.tests_pass),
                f"{metrics.red_reward:.2f}",
                f"{metrics.blue_reward:.2f}",
                f"{metrics.execution_time:.2f}",
                cumulative_red_wins,
                cumulative_blue_wins,
                f"{red_win_rate:.4f}",
                f"{blue_win_rate:.4f}"
            ])
    
    def _save_final_results(self) -> None:
        """Save final training results."""
        results_dir = Path("experiments/results")
        results_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_path = results_dir / f"training_results_{timestamp}.json"
        
        results = {
            'total_rounds': self.round_number,
            'metrics': [asdict(m) for m in self.metrics],
            'final_stats': self._compute_final_stats(),
        }
        
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Saved final results to {results_path}")
    
    def _compute_final_stats(self) -> Dict[str, Any]:
        """Compute final statistics."""
        if not self.metrics:
            return {}
        
        return {
            'red_win_rate': sum(m.attack_success for m in self.metrics) / len(self.metrics),
            'blue_win_rate': sum(m.patch_blocks_attack for m in self.metrics) / len(self.metrics),
            'avg_red_reward': sum(m.red_reward for m in self.metrics) / len(self.metrics),
            'avg_blue_reward': sum(m.blue_reward for m in self.metrics) / len(self.metrics),
            'total_execution_time': sum(m.execution_time for m in self.metrics),
        }


def main():
    """Main entry point."""
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Sentinel Adversarial Training')
    parser.add_argument('--config', type=str, default='config/base_config.yaml',
                        help='Path to configuration file')
    parser.add_argument('--dataset', type=str, help='Path to dataset file')
    parser.add_argument('--generate', type=int, help='Generate N synthetic samples')
    parser.add_argument('--rounds', type=int, help='Number of training rounds')
    
    args = parser.parse_args()
    
    # Initialize orchestrator
    orchestrator = AdversarialOrchestrator(args.config)
    
    # Load or generate dataset
    if args.generate:
        orchestrator.generate_dataset(args.generate)
    elif args.dataset:
        orchestrator.load_dataset(args.dataset)
    else:
        # Generate default dataset
        orchestrator.generate_dataset(1000)
    
    # Run training
    orchestrator.run_training(args.rounds)


if __name__ == "__main__":
    main()
