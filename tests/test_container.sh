#!/bin/bash

set -e
set -x

if [ $# -eq 1 ]; then
	IDX=$1
else
	IDX=42
fi

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PARENT_DIR=$(dirname "$SCRIPT_DIR")
pushd "$PARENT_DIR" > /dev/null
docker build -t ghcr.io/aijon:latest .
popd > /dev/null

docker run \
	--rm \
	--privileged \
	-v $HOME/projects/aijon:/shared//aijon_stuff \
	-e "OPENAI_API_KEY=$OPENAI_API_KEY" \
	-e "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" \
	-e "EXP_ID=$IDX" \
	-e "NO_CACHE=1" \
	-it ghcr.io/aijon:latest
