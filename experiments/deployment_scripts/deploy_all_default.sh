#!/bin/bash

set -x
EXP_FILE="./oss_fuzz_coverage_target_mapping.csv"

TRIAL=1
NO_CACHE=0

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --trial) TRIAL="$2"; shift ;;
        --no-cache) NO_CACHE="$2"; shift ;;
    esac
    shift
done

export TRIAL
export NO_CACHE

tail -n+2 $EXP_FILE | while IFS=',' read ID DATASET PROJECT; do
	./deploy_default_experiment.sh "$ID"
	if [ $? -eq 0 ]; then
		sleep 30s
	fi
done
