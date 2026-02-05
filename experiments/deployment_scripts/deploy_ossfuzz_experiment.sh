#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <experiment_id>"
	exit 1
fi

EXP_ID=$1
IMAGE=ghcr.io/aijon:latest
EXP_FILE="./ossfuzz_target_mapping.csv"

TRIAL=${TRIAL:-1}
NO_CACHE=${NO_CACHE:-1}

NUM_HARNESSES=$(grep "^$EXP_ID," $EXP_FILE | tr ',' '\n' | tail -n+3 | wc -l)
NUM_CORES=$(echo "$NUM_HARNESSES * 2" | bc)
CPU_REQUEST="$((NUM_CORES + 1))"
CPU_LIMIT="$((NUM_CORES + 2))"

pod_create -i $IMAGE \
    -c $CPU_REQUEST \
    -C $CPU_LIMIT \
    -m 4Gi \
    -M 8Gi \
    -e OPENAI_API_KEY=$OPENAI_API_KEY \
    -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
    -e OSS_FUZZ=1 \
    -e EXP_ID=$EXP_ID \
    -e NO_CACHE=$NO_CACHE \
    -e TRIAL=$TRIAL \
    -s regcred \
    -n "aijon-ossfuzz-$EXP_ID"
