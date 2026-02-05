#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <experiment_id>"
	exit 1
fi

EXP_ID=$1
IMAGE=ghcr.io/aijon:latest
EXP_FILE="./oss_fuzz_coverage_target_mapping.csv"

TRIAL=${TRIAL:-1}
NO_CACHE=${NO_CACHE:-1}

NUM_HARNESSES=$(grep "^$EXP_ID," $EXP_FILE | tr ',' '\n' | tail -n+3 | wc -l)
CPU_REQUEST="$((NUM_HARNESSES + 1))"
CPU_LIMIT="$((NUM_HARNESSES + 2))"

pod_create -i $IMAGE \
	-c $CPU_REQUEST \
	-C $CPU_LIMIT \
	-e OPENAI_API_KEY=$OPENAI_API_KEY \
	-e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
	-e OSS_FUZZ=1 \
	-e DEFAULT=1 \
	-e EXP_ID=$EXP_ID \
	-e NO_CACHE=$NO_CACHE \
    -e TRIAL=$TRIAL \
	-s regcred \
	-n "aijon-default-$EXP_ID-$TRIAL"
