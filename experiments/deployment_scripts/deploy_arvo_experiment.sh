#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <experiment_id>"
	exit 1
fi

EXP_ID=$1
CRAZY_MODE=${CRAZY_MODE:-0}
IMAGE=ghcr.io/aijon:latest

pod_create -i $IMAGE \
	-c 1 \
	-C 2 \
	-e OPENAI_API_KEY=$OPENAI_API_KEY \
	-e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
	-e EXP_ID=$EXP_ID \
	-e NO_CACHE=1 \
	-e ARVO=1 \
	-e CRAZY_MODE=$CRAZY_MODE \
	-s regcred \
	-n "aijon-arvo-$EXP_ID"
