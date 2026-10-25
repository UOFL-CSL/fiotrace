#!/bin/bash
set -euo pipefail

# DEPRECATED as on 10/25/2026, DO NOT USE !!
# use fiotrace.py instead

# usage (as of 10/1/2026):
# fiotrace.sh <device> <label> <output_dir> -- <fio cmd + args>
# example:
# ./fiotrace.sh /dev/nvme0n1 \
#   nvme0n1__mq-deadline__randread__iodepth128__rep03 \
#   ./traces \  
#   -- fio portion_run1.fio --output-format=json --output=result.json

DEVICE="$1"
LABEL="$2"
OUTDIR="$3"
shift 3

if [[ "${1:-}" != "--" ]]; then
  echo "Usage: $0 <device> <label> <output_dir> -- <fio cmd + args>" >&2
  exit 1
fi
shift

RUN_DIR="${OUTDIR}/${LABEL}"
mkdir -p "$RUN_DIR"

# short warm up + runtime + small tail margin
# adjust the TRACE_SECONDS if fio runtime changes
TRACE_SECONDS=35

echo "[fiotrace] device=$DEVICE label=$LABEL"
echo "[fiotrace] output=$RUN_DIR"

cat "/sys/block/$(basename "$DEVICE")/queue/scheduler" \
  > "$RUN_DIR/scheduler.txt" || true

# start blktrace
sudo blktrace \
  -d "$DEVICE" \
  -w "$TRACE_SECONDS" \
  -a queue \
  -a issue \
  -a complete \
  -o "$RUN_DIR/trace" &
TRACE_PID=$!

# give blktrace a moment to attach
sleep 1

# run fio
set +e
"$@" > "$RUN_DIR/fio.stdout" 2> "$RUN_DIR/fio.stderr"
FIO_RC=$?
set -e

# stop blktrace
sudo kill -INT "$TRACE_PID" 2>/dev/null || true
wait "$TRACE_PID" 2>/dev/null || true

echo "$FIO_RC" > "$RUN_DIR/fio.rc"

if [[ "$FIO_RC" -ne 0 ]]; then
  echo "[fiotrace] fio failed with rc=$FIO_RC" >&2
fi

# convert and summarize
sudo blkparse -i "$RUN_DIR/trace" -d "$RUN_DIR/trace.bin" -o "$RUN_DIR/trace.txt"
sudo btt -i "$RUN_DIR/trace.bin" -o "$RUN_DIR/btt-summary"

sudo btt -i "$RUN_DIR/trace.bin" -d "$RUN_DIR/btt-perio" || true

echo "[fiotrace] done: $RUN_DIR"
exit "$FIO_RC"

