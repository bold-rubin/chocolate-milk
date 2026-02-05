#!/bin/bash

TRIAL=1
NO_CACHE=0

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --trial) TRIAL="$2"; shift ;;
        --no-cache) NO_CACHE="$2"; shift ;;
    esac
    shift
done

export TRIAL
export NO_CACHE

pod_names -e | grep -E 'aijon-ossfuzz-[0-9]+' |while read -r line; do
  idx=$(echo $line | cut -d'-' -f4)
  pod_delete $line
  ./deploy_ossfuzz_experiment.sh $idx
done
