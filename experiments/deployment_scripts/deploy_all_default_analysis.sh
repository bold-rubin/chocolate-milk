#!/bin/bash

set -x
EXP_FILE="./oss_fuzz_coverage_target_mapping.csv"

tail -n+2 $EXP_FILE | while IFS=',' read ID DATASET PROJECT; do
	./deploy_default_analysis.sh "$ID"
	if [ $? -eq 0 ]; then
		sleep 30s
	fi
done
