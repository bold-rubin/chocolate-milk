#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <experiment_id>"
	exit 1
fi

NO_CACHE=${NO_CACHE:-1}

EXP_ID=$1
IMAGE=ghcr.io/aijon:latest

pod_create -i $IMAGE \
	-c 1 \
	-C 2 \
	-e OPENAI_API_KEY=$OPENAI_API_KEY \
	-e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
	-e EXP_ID=$EXP_ID \
	-e ANALYSIS=1 \
	-s regcred \
	-n "aijon-analysis-$EXP_ID"
