#!/bin/bash

set -e

echo "Step 1: Building Tranco reputation data..."
python3 scripts/build_tranco_reputation.py

echo "Step 2: Preparing dataset..."
python3 scripts/prepare_dataset.py

echo "Step 3: Training Logistic Regression..."
python3 training/train_logistic_regression.py

echo "Step 4: Training Random Forest..."
python3 training/train_random_forest.py

echo "Step 5: Building weighted ensemble..."
python3 training/build_weighted_ensemble.py

echo "Step 6: Running tests..."
pytest tests/ -v

echo "Pipeline completed successfully."