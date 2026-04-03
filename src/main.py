"""
src/main.py

Entry point for running the ZeroSum-Security adversarial training loop.

Usage:
  python src/main.py                    # Run with synthetic dataset (10 samples, 10 rounds)
  python src/main.py --scrape           # Scrape real-world CVEs first, then train
  python src/main.py --dataset FILE     # Train using an existing dataset file
"""

import sys
import argparse
import logging
from sentinel.orchestrator import AdversarialOrchestrator

# Set up logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('main')


def scrape_cves():
    """Run the CVE scraper to build a real-world dataset."""
    from sentinel.data.cve_scraper import CVEDatasetBuilder

    logger.info("Starting CVE dataset scraping...")
    builder = CVEDatasetBuilder()
    samples = builder.build_dataset(
        samples_per_type=30,
        output_path="datasets/real_world/cve_dataset.json",
    )
    logger.info(f"Scraping complete: {len(samples)} samples saved.")
    return "datasets/real_world/cve_dataset.json"


def main():
    parser = argparse.ArgumentParser(description="ZeroSum-Security Adversarial Training")
    parser.add_argument('--scrape', action='store_true', help='Scrape real-world CVEs before training')
    parser.add_argument('--dataset', type=str, default=None, help='Path to an existing dataset JSON file')
    parser.add_argument('--rounds', type=int, default=10, help='Number of training rounds')
    parser.add_argument('--samples', type=int, default=10, help='Number of synthetic samples to generate')
    args = parser.parse_args()

    logger.info("Starting ZeroSum-Security Adversarial Training")

    config_path = "config/base_config.yaml"

    try:
        # Initialize orchestrator
        orchestrator = AdversarialOrchestrator(config_path)

        # Load or generate dataset
        if args.scrape:
            dataset_path = scrape_cves()
            orchestrator.load_dataset(dataset_path)
        elif args.dataset:
            orchestrator.load_dataset(args.dataset)
        else:
            logger.info(f"Generating {args.samples} synthetic samples...")
            orchestrator.generate_dataset(num_samples=args.samples)

        # Run training loop
        logger.info(f"Starting {args.rounds}-round training run...")
        orchestrator.run_training(num_rounds=args.rounds)

        logger.info("Training completed successfully!")

    except Exception as e:
        logger.error(f"Execution failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
