#!/bin/bash

set -e
set -x
EXP_FILE="./experiment_mapping.csv"

tail -n+2 $EXP_FILE | while IFS=',' read ID DATASET PROJECT; do
	./deploy_experiment.sh "$ID" || true
done
