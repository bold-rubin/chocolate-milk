#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <experiment_id>"
    exit 1
fi


MODE=""

while [[ "$#" -gt 1 ]]; do
    case $1 in
        --mode) MODE="$2"; shift 2 ;;
        ?) break ;;
    esac
done

IMAGE=ghcr.io/magma:latest
if [ -n "$MODE" ]; then
    IMAGE=ghcr.io/magma:$MODE
fi

if [ "$MODE" == "manual" ]; then
    MANUAL_PATCHES=1
    IMAGE=ghcr.io/magma:ijon
else
    MANUAL_PATCHES=0
fi

EXP_ID=$1
TARGET=$(grep "^$EXP_ID," experiment_mapping.csv | cut -d',' -f2)
HARNESS=$(grep "^$EXP_ID," experiment_mapping.csv | cut -d',' -f3)

if [ "$MANUAL_PATCHES" -eq 1 ]; then
    NAME="magma-manual-default-$EXP_ID"
else
    NAME="magma-default${MODE}-$EXP_ID"
fi

pod_create -i $IMAGE \
    -c 21 \
    -C 22 \
    -e EXP_ID=$EXP_ID \
    -e TARGET=$TARGET \
    -e HARNESS=$HARNESS \
    -e MANUAL_PATCHES=$MANUAL_PATCHES \
    -e MODE="$MODE" \
    -s regcred \
    -n "$NAME"
