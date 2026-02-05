#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <experiment_id>"
	exit 1
fi

NO_CACHE=${NO_CACHE:-1}

EXP_ID=$1
IMAGE=ghcr.io/aijon:latest

case "$EXP_ID" in
	46|79|87|90|91)
		# Re-use cached instrumentation for these experiments
		NO_CACHE=1
		;;
	*)
		NO_CACHE=1
		;;
esac

pod_create -i $IMAGE \
	-c 1 \
	-C 2 \
	-e OPENAI_API_KEY=$OPENAI_API_KEY \
	-e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
	-e EXP_ID=$EXP_ID \
	-e NO_CACHE=$NO_CACHE \
	-s regcred \
	-n "aijon-$EXP_ID"
