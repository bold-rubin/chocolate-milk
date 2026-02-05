#!/bin/bash

set -x
EXP_FILE="./arvo_experiment_mapping.csv"

tail -n+2 $EXP_FILE | while IFS=',' read ID DATASET PROJECT; do
	./deploy_arvo_experiment.sh "$ID"
	# if [ $? -eq 0 ]; then
	# 	sleep 1m
	# fi
done
