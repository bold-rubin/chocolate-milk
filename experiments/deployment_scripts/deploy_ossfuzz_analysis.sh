#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <experiment_id>"
	exit 1
fi

NO_CACHE=${NO_CACHE:-1}

EXP_ID=$1
IMAGE=ghcr.io/aijon:latest
EXP_FILE="./oss_fuzz_coverage_target_mapping.csv"

TRIAL=${TRIAL:-1}
NO_CACHE=${NO_CACHE:-1}

pod_create -i $IMAGE \
	-c 1 \
	-C 2 \
	-e OPENAI_API_KEY=$OPENAI_API_KEY \
	-e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
	-e ANALYSIS=1 \
	-e OSS_FUZZ=1 \
	-e EXP_ID=$EXP_ID \
    -e NO_CACHE=$NO_CACHE \
    -e TRIAL=$TRIAL \
	-s regcred \
	-n "aijon-ossfuzz-analysis-$EXP_ID"
