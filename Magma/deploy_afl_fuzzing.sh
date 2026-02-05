#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <experiment_id>"
    exit 1
fi

IMAGE=ghcr.io/magma:aflpp

EXP_ID=$1
TARGET=$(grep "^$EXP_ID," experiment_mapping.csv | cut -d',' -f2)
HARNESS=$(grep "^$EXP_ID," experiment_mapping.csv | cut -d',' -f3)

NAME="magma-aflpp-default-$EXP_ID"

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
