#!/bin/bash

pod_names -e | grep -E 'aijon-[0-9]+' |while read -r line; do
  idx=$(echo $line | cut -d'-' -f3)
  pod_delete $line
  ./deploy_experiment.sh $idx
done
