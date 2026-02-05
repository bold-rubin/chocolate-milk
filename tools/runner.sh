#!/bin/bash

set -e
set -x

ANALYSIS=${ANALYSIS:-0}
OSS_FUZZ=${OSS_FUZZ:-0}
DEFAULT=${DEFAULT:-0}
COMPARISON=${COMPARISON:-0}
ARVO=${ARVO:-0}
USER=${USER:-root}

export USER="$USER"

if [ "$COMPARISON" -eq 1 ]; then
    if [ "$OSS_FUZZ" -eq 1 ]; then
        echo "Running OSS-Fuzz coverage comparison mode"
        # /aijon/tools/compare_coverage.sh
        /aijon/tools/analyze_ossfuzz_annotations.sh
        echo "OSS-Fuzz coverage comparison mode completed"
        exit 0
    else
        echo "Coverage comparison mode is only supported for OSS-Fuzz experiments."
        exit 1
    fi
fi

if [ "$ANALYSIS" -eq 1 ]; then
    if [ "$OSS_FUZZ" -eq 1 ]; then
        echo "Running OSS-Fuzz analysis mode"
        /aijon/tools/analyze_ossfuzz_crashes.sh
        /aijon/tools/analyze_ossfuzz_coverage.sh
        # /aijon/tools/analyze_ossfuzz_annotations.sh
        echo "OSS-Fuzz analysis mode completed"
        exit 0
    else
        echo "Running analysis mode"
        /aijon/tools/analyze_crashes.sh
        /aijon/tools/analyze_annotations.sh
        echo "Analysis mode completed"
        exit 0
    fi
fi

if [ "$OSS_FUZZ" -eq 1 ]; then
    if [ "$DEFAULT" -eq 1 ]; then
        echo "Running default OSS-Fuzz experiment"
        /aijon/tools/run_default_ossfuzz.sh
    else
        echo "Running in OSS-Fuzz environment"
        /aijon/tools/run_oss_fuzz_experiment.sh
    fi
    echo "Performing crash analysis"
    /aijon/tools/analyze_ossfuzz_crashes.sh
    echo "Performing coverage analysis"
    /aijon/tools/analyze_ossfuzz_coverage.sh
    # echo "Performing annotation analysis"
    # /aijon/tools/analyze_ossfuzz_annotations.sh
elif [ "$ARVO" -eq 1 ]; then
    echo "Running in ARVO environment"
    /aijon/tools/run_arvo_experiment.sh
elif [ "$MAGMA" -eq 1 ]; then
    echo "Running in MAGMA environment"
    /aijon/tools/run_magma_experiment.sh
else
    echo "Running in default environment"
    /aijon/tools/run_experiment.sh
    echo "Performing crash analysis"
    /aijon/tools/analyze_crashes.sh
    echo "Performing annotation analysis"
    /aijon/tools/analyze_annotations.sh
fi

echo "Experiment completed successfully."
# sleep 1d
