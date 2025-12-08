#!/bin/bash

# Check benchmark progress
# Compares completed benchmarks in ~/.pensar/executions with total in ~/validation-benchmarks

VALIDATION_DIR="$HOME/validation-benchmarks/benchmarks"
EXECUTIONS_DIR="$HOME/.pensar/executions"

# Get total benchmarks from validation directory
TOTAL=$(ls "$VALIDATION_DIR" | grep "^XBEN" | wc -l | tr -d ' ')

# Get unique completed benchmarks (those with benchmark_results.json)
# Only look in v2--XBEN-* directories
COMPLETED=$(find "$EXECUTIONS_DIR" -path "*/v2--XBEN-*" -name "benchmark_results.json" -print0 2>/dev/null | \
    xargs -0 -n1 dirname 2>/dev/null | \
    grep -oE "XBEN-[0-9]+-[0-9]+" | \
    sort -u | wc -l | tr -d ' ')

# Get successful benchmarks (flag detected)
# For each unique benchmark, check if any of its runs detected the flag
SUCCESSFUL=$(find "$EXECUTIONS_DIR" -path "*/v2--XBEN-*" -name "benchmark_results.json" -print0 2>/dev/null | \
    xargs -0 grep -l '"detected": true' 2>/dev/null | \
    xargs -n1 dirname 2>/dev/null | \
    grep -oE "XBEN-[0-9]+-[0-9]+" | \
    sort -u | wc -l | tr -d ' ')

REMAINING=$((TOTAL - COMPLETED))
FAILED=$((COMPLETED - SUCCESSFUL))

echo "================================"
echo "  Benchmark Progress Report"
echo "================================"
echo "Total benchmarks:     $TOTAL"
echo "Completed:            $COMPLETED"
echo "Remaining:            $REMAINING"
PERCENT=$(echo "scale=1; ($COMPLETED * 100) / $TOTAL" | bc)
echo "Progress:             ${PERCENT}%"
echo "--------------------------------"
echo "Successful (flag):    $SUCCESSFUL"
echo "Failed:               $FAILED"
if [[ "$COMPLETED" -gt 0 ]]; then
    SUCCESS_RATE=$(echo "scale=1; ($SUCCESSFUL * 100) / $COMPLETED" | bc)
else
    SUCCESS_RATE="0.0"
fi
echo "Success rate:         ${SUCCESS_RATE}%"
echo "================================"

# Optional: show which ones are remaining
if [[ "$1" == "-v" || "$1" == "--verbose" ]]; then
    echo ""
    echo "Remaining benchmarks:"
    echo "---------------------"

    # Get completed benchmark IDs (only from v2--XBEN-* directories)
    COMPLETED_IDS=$(find "$EXECUTIONS_DIR" -path "*/v2--XBEN-*" -name "benchmark_results.json" -print0 2>/dev/null | \
        xargs -0 -n1 dirname 2>/dev/null | \
        grep -oE "XBEN-[0-9]+-[0-9]+" | \
        sort -u)

    # Compare with total list
    for bench in $(ls "$VALIDATION_DIR" | grep "^XBEN"); do
        if ! echo "$COMPLETED_IDS" | grep -q "^${bench}$"; then
            echo "  $bench"
        fi
    done
fi
