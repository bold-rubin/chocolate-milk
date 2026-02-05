#!/bin/bash

##
# Pre-requirements:
# - $1: path to test case
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
##

find_triggered()
{
    ##
    # Pre-requirements:
    # - $1: human-readable monitor output
    ##
    echo "$1" | while read line; do
        triggered=$(awk '{print $5}' <<< "$line")
        if [ ! -z $triggered ] && [ $triggered -ne 0 ]; then
            awk '{print $1}' <<< "$line"
            return 1
        fi
    done
}

find_reached()
{
    ##
    # Pre-requirements:
    # - $1: human-readable monitor output
    ##
    local found=0
    while read -r line; do
        fields=$(echo "$line" | wc -w)
        # Parse repeating 5-token groups:
        # BUGID reached N triggered M
        for ((i=1; i<=fields; i+=5)); do
            bug=$(awk -v j="$i" '{print $j}' <<< "$line")
            reached=$(awk -v j="$((i+2))" '{print $j}' <<< "$line")
            if [ -n "$reached" ] && [ "$reached" -ne 0 ]; then
                echo "$bug"
                found=1
            fi
        done
    done <<< "$1"  # Use here-string instead of pipe
    [ $found -eq 1 ] && return 1
    return 0
}

cd "$SHARED"
tmpfile=$(mktemp "$SHARED/runonce.XXXXXX.tmp")
cp --force "$1" "$tmpfile"
out="$($OUT/monitor --fetch watch --dump human "$FUZZER/runonce.sh" "$tmpfile")"
exit_code=$?
bug=$(find_triggered "$out")
is_triggered=$?

reached_bugs=$(find_reached "$out")
is_reached=$?

reached_bugs=$(echo "$reached_bugs" | tr '\n' ' ')

annotations="$($FUZZER/runonce.sh $tmpfile 2>&1 | grep 'PATCHID' | tr '\n' ' ')"

msg="exit_code $exit_code"


if [ "$is_triggered" -ne 0 ]; then
    msg="$msg bug $bug"
fi

if [ "$is_reached" -ne 0 ]; then
    msg="$msg reached $reached_bugs"
fi

if [ -n "$annotations" ]; then
    msg="$msg annotations $annotations"
fi

echo "$msg"
rm "$tmpfile"

if [ $is_triggered -ne 0 ] || [ $exit_code -ne 0 ]; then
    exit 1
fi
