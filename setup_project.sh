#!/bin/bash
mkdir -p src/sentinel/{agents,sandbox,data,utils}
mkdir -p experiments/{configs,scripts,results/plots}
mkdir -p datasets/{synthetic,real_world}
mkdir -p models/checkpoints
mkdir -p logs docker docs config

# Create Python package markers
touch src/__init__.py src/sentinel/__init__.py
touch src/sentinel/agents/__init__.py src/sentinel/sandbox/__init__.py
touch src/sentinel/data/__init__.py src/sentinel/utils/__init__.py

# Create code placeholders
touch src/sentinel/agents/base_agent.py
touch src/sentinel/agents/red_agent.py
touch src/sentinel/agents/blue_agent.py
touch src/sentinel/sandbox/executor.py
touch src/sentinel/data/synthetic.py
touch src/sentinel/orchestrator.py
touch experiments/scripts/evaluate.py
touch config/base_config.yaml
touch requirements.txt
touch README.md
