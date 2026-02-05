#!/bin/bash

set -e
set -x
EXP_FILE="./magma_experiment_mapping.csv"

cat $EXP_FILE | while IFS=',' read ID PROJECT HARNESS; do
	./deploy_magma_experiment.sh "$ID" || true
done
