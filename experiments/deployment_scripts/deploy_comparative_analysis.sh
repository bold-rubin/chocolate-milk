#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <experiment_id>"
	exit 1
fi

NO_CACHE=${NO_CACHE:-1}
TRIAL=${TRIAL:-1}

EXP_ID=$1
IMAGE=ghcr.io/aijon:latest
EXP_FILE="./oss_fuzz_coverage_target_mapping.csv"

NUM_HARNESSES=$(grep "^$EXP_ID," $EXP_FILE | tr ',' '\n' | tail -n+3 | wc -l)
# NUM_HARNESSES=0
CPU_REQUEST="$((NUM_HARNESSES + 1))"
CPU_LIMIT="$((NUM_HARNESSES + 2))"

pod_create -i $IMAGE \
	-c $CPU_REQUEST \
	-C $CPU_LIMIT \
	-e OPENAI_API_KEY=$OPENAI_API_KEY \
	-e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
	-e ANALYSIS=1 \
	-e OSS_FUZZ=1 \
    -e COMPARISON=1 \
    -e TRIAL=$TRIAL \
	-e EXP_ID=$EXP_ID \
	-s regcred \
	-n "aijon-comparative-analysis-$EXP_ID-$TRIAL"
