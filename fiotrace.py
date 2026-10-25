#!/usr/bin/env python3
# author: Preet Patel
# license: GPL 2.0


import os
import argparse
from datetime import datetime
import hashlib
import json
import re
import struct
import sys
import signal
import shutil
import subprocess
import tarfile
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parent


TRACE_HDR = struct.Struct("<IIQQIIIIIHH")
BLK_IO_TRACE_MAGIC = 0x65617407
BLK_TC_NOTIFY = 1 << (10 + 16)
BLK_TN_PROCESS = 0 | BLK_TC_NOTIFY
BLK_TA_QUEUE_MASK = 1
RAMP_TIME_RE = re.compile(r"^\s*ramp_time\s*=\s*([^\s#;]+)", re.IGNORECASE)
DURATION_RE = re.compile(r"^\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*([a-zA-Z]*)\s*$")
BLKTRACE_TOTAL_RE = re.compile(
    r"Total:\s+(\d+)\s+events\s+\(dropped\s+(\d+)\)", re.IGNORECASE
)
ACTIVE_SCHED_RE = re.compile(r"\[([^\]]+)\]")
BTT_ROW_RE = re.compile(
    r"^\s*(Q2G|G2I|I2D|D2C|Q2C)\s+"
    r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\s+"
    r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\s+"
    r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\s+"
    r"(\d+)\s*$"
)
DURATION_UNITS = {
    "": 1.0,
    "s": 1.0,
    "sec": 1.0,
    "secs": 1.0,
    "ms": 1e-3,
    "msec": 1e-3,
    "msecs": 1e-3,
    "us": 1e-6,
    "usec": 1e-6,
    "usecs": 1e-6,
    "ns": 1e-9,
    "nsec": 1e-9,
    "nsecs": 1e-9,
    "m": 60.0,
    "min": 60.0,
    "mins": 60.0,
    "h": 3600.0,
    "hr": 3600.0,
    "hrs": 3600.0,
    "d": 86400.0,
}


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def log(message):
    print(f"[fiotrace] {message}", file=sys.stderr, flush=True)


def handle_signal(signum, frame):
    raise Interrupted(signum)


def stop_process(proc, first_signal, timeout=15):
    # stop the process group
    if proc is None or proc.poll() is not None:
        return
    for sig, wait_seconds in (
        (first_signal, timeout),
        (signal.SIGTERM, 5),
        (signal.SIGKILL, 5),
    ):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass

        try:
            proc.wait(timeout=wait_seconds)
            return
        except subprocess.TimeoutExpired:
            continue

    raise RuntimeError(
        f"[fiotrace | function: stop_process] could not stop process: {proc.pid}"
    )


def _coerce_scalar(text):
    value = text.strip()
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def save_scheduler(device, destination):
    device_name = Path(device).resolve().name
    queue_dir = Path("/sys/class/block") / device_name / "queue"
    source = queue_dir / "scheduler"

    scheduler_raw = None
    active_scheduler = None
    iosched_params = {}

    try:
        raw_text = source.read_text()
        destination.write_text(raw_text)
        scheduler_raw = raw_text.strip()
        match = ACTIVE_SCHED_RE.search(scheduler_raw)
        if match is not None:
            active_scheduler = match.group(1)
        elif scheduler_raw:
            active_scheduler = scheduler_raw
    except OSError as exc:
        destination.write_text(f"Unavaialble: {exc}\n")
        log(f"[fiotrace | function: save_scheduler] could not record scheduler: {exc}")

    iosched_dir = queue_dir / "iosched"
    if iosched_dir.is_dir():
        for entry in sorted(iosched_dir.iterdir()):
            if not entry.is_file():
                continue
            try:
                iosched_params[entry.name] = _coerce_scalar(
                    entry.read_text(errors="replace")
                )
            except OSError:
                continue

    return active_scheduler, scheduler_raw, iosched_params


def parse_blktrace_stats(blktrace_stdout_path):
    total_events = None
    dropped_events = None
    try:
        text = blktrace_stdout_path.read_text(errors="replace")
    except OSError:
        return total_events, dropped_events

    for line in text.splitlines():
        match = BLKTRACE_TOTAL_RE.search(line)
        if match is not None:
            total_events = int(match.group(1))
            dropped_events = int(match.group(2))
    return total_events, dropped_events


def parse_btt_counts(summary_path):
    counts = {}
    in_all_devices = False
    try:
        lines = summary_path.read_text(errors="replace").splitlines()
    except OSError:
        return counts

    for line in lines:
        if "==================== All Devices" in line:
            in_all_devices = True
            continue
        if in_all_devices and line.startswith("===================="):
            break
        if not in_all_devices:
            continue
        match = BTT_ROW_RE.match(line)
        if match is not None:
            metric, count_str = match.groups()
            counts[metric] = int(count_str)
    return counts


def parse_fio_duration_seconds(raw_value):
    match = DURATION_RE.match(str(raw_value))
    if match is None:
        raise ValueError(f"Invalid ramp_time duration: {raw_value!r}")

    amount_str, unit_str = match.groups()
    unit_key = unit_str.lower()
    if unit_key not in DURATION_UNITS:
        raise ValueError(f"Unsupported ramp_time unit in {raw_value!r}")

    seconds = float(amount_str) * DURATION_UNITS[unit_key]
    if seconds < 0:
        raise ValueError(f"ramp_time must be nonnegative: {raw_value!r}")
    return seconds


def extract_ramp_time_from_text(text):
    ramp_seconds = None
    for line in text.splitlines():
        match = RAMP_TIME_RE.match(line)
        if match is not None:
            ramp_seconds = parse_fio_duration_seconds(match.group(1))
    return ramp_seconds


def resolve_ramp_time_seconds(explicit_ramp_time, fio_command, stdin_text):
    if explicit_ramp_time is not None:
        return parse_fio_duration_seconds(explicit_ramp_time)

    detected = None
    for i, token in enumerate(fio_command[1:], start=1):
        if token.startswith("--ramp_time=") or token.startswith("--ramp-time="):
            detected = parse_fio_duration_seconds(token.split("=", 1)[1])
        elif token in ("--ramp_time", "--ramp-time") and i + 1 < len(fio_command):
            detected = parse_fio_duration_seconds(fio_command[i + 1])
        elif not token.startswith("-") and token != "-":
            candidate = Path(token)
            if candidate.is_file():
                try:
                    from_file = extract_ramp_time_from_text(
                        candidate.read_text(errors="replace")
                    )
                except OSError:
                    from_file = None
                if from_file is not None:
                    detected = from_file

    if stdin_text is not None:
        from_stdin = extract_ramp_time_from_text(stdin_text)
        if from_stdin is not None:
            detected = from_stdin

    return detected if detected is not None else 0.0


def find_fio_window_bounds_sec(run_dir, fio_root_pid=None):
    """
    Scan per-CPU trace.blktrace.* files to compute:
      1. fio_start_offset_sec: timestamp (in seconds relative to blkparse's
         genesis t=0) of fio's first queued I/O event (Q).
      2. post_fio_cutoff_sec: if any non-fio process queued a stray I/O after
         fio's last Q event, returns the timestamp just before that stray Q
         event so post-fio background noise is excluded while preserving all
         of fio's in-flight completions (C). Otherwise returns None.
    """
    raw_files = sorted(run_dir.glob("trace.blktrace.*"))
    if not raw_files:
        return 0.0, None

    fio_pids = set()
    if fio_root_pid is not None:
        fio_pids.add(int(fio_root_pid))

    genesis_ns = None

    # Pass 1: discover genesis_ns (first non-notify event per CPU) and fio PIDs.
    for path in raw_files:
        found_cpu_genesis = False
        try:
            with path.open("rb") as f:
                while True:
                    hdr = f.read(TRACE_HDR.size)
                    if len(hdr) < TRACE_HDR.size:
                        break
                    (
                        magic,
                        _seq,
                        time_ns,
                        _sector,
                        _bytes_len,
                        action,
                        pid,
                        _dev,
                        _cpu,
                        _err,
                        pdu_len,
                    ) = TRACE_HDR.unpack(hdr)
                    if magic != BLK_IO_TRACE_MAGIC:
                        break
                    pdu = f.read(pdu_len) if pdu_len else b""
                    if action & BLK_TC_NOTIFY:
                        if action == BLK_TN_PROCESS and pdu:
                            proc_name = pdu.split(b"\x00", 1)[0].decode(
                                "ascii", errors="ignore"
                            )
                            if proc_name.startswith("fio"):
                                fio_pids.add(pid)
                    elif not found_cpu_genesis:
                        found_cpu_genesis = True
                        if genesis_ns is None or time_ns < genesis_ns:
                            genesis_ns = time_ns
        except OSError:
            continue

    if genesis_ns is None:
        return 0.0, None

    # Pass 2: find earliest and latest Q events from fio_pids, plus any non-fio Q timestamps.
    first_fio_q_ns = None
    last_fio_q_ns = None
    first_any_q_ns = None
    non_fio_q_times = []

    for path in raw_files:
        try:
            with path.open("rb") as f:
                while True:
                    hdr = f.read(TRACE_HDR.size)
                    if len(hdr) < TRACE_HDR.size:
                        break
                    (
                        magic,
                        _seq,
                        time_ns,
                        _sector,
                        _bytes_len,
                        action,
                        pid,
                        _dev,
                        _cpu,
                        _err,
                        pdu_len,
                    ) = TRACE_HDR.unpack(hdr)
                    if magic != BLK_IO_TRACE_MAGIC:
                        break
                    if pdu_len:
                        f.seek(pdu_len, os.SEEK_CUR)
                    if action & BLK_TC_NOTIFY:
                        continue
                    if (action & 0xFFFF) == BLK_TA_QUEUE_MASK:
                        if first_any_q_ns is None or time_ns < first_any_q_ns:
                            first_any_q_ns = time_ns
                        if pid in fio_pids:
                            if first_fio_q_ns is None or time_ns < first_fio_q_ns:
                                first_fio_q_ns = time_ns
                            if last_fio_q_ns is None or time_ns > last_fio_q_ns:
                                last_fio_q_ns = time_ns
                        else:
                            non_fio_q_times.append(time_ns)
        except OSError:
            continue

    target_q_ns = first_fio_q_ns if first_fio_q_ns is not None else first_any_q_ns
    if target_q_ns is None or target_q_ns <= genesis_ns:
        fio_start_offset_sec = 0.0
    else:
        fio_start_offset_sec = (target_q_ns - genesis_ns) / 1e9

    post_fio_cutoff_sec = None
    if last_fio_q_ns is not None and non_fio_q_times:
        post_fio_stray_q = [t for t in non_fio_q_times if t > last_fio_q_ns]
        if post_fio_stray_q:
            earliest_stray_ns = min(post_fio_stray_q)
            if earliest_stray_ns > genesis_ns:
                post_fio_cutoff_sec = (earliest_stray_ns - 1 - genesis_ns) / 1e9

    return fio_start_offset_sec, post_fio_cutoff_sec


def find_fio_start_offset_sec(run_dir, fio_root_pid=None):
    fio_start_offset_sec, _ = find_fio_window_bounds_sec(
        run_dir, fio_root_pid=fio_root_pid
    )
    return fio_start_offset_sec


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create_snapshot(snapshot_dir, run_dir, output_dir, args, fio_command, metadata):
    snapshot_dir = Path(snapshot_dir).resolve()
    run_dir = Path(run_dir).resolve()
    output_dir = Path(output_dir).resolve()
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    run_script = Path(__file__).resolve()
    script_dir = run_script.parent

    files_to_archive = [run_script]

    cwd = Path.cwd().resolve()
    search_dirs = [
        script_dir,
        script_dir.parent / "fiobatch",
        cwd,
        cwd.parent,
        cwd.parent.parent,
    ]
    for search_dir in search_dirs:
        for companion in ("fiobatch.py", "custom_fiobatch.py", "fiotrace.sh", "fiotrace.md"):
            companion_path = search_dir / companion
            if companion_path.is_file():
                files_to_archive.append(companion_path.resolve())

    for pattern in ("*.json", "*.fio", "*.sh", "*.md"):
        for candidate in sorted(cwd.glob(pattern)):
            if candidate.is_file():
                files_to_archive.append(candidate.resolve())

    for token in fio_command[1:]:
        if not token.startswith("-") and token != "-":
            candidate = Path(token)
            if candidate.is_file():
                files_to_archive.append(candidate.resolve())

    for per_job_file in (
        "job.fio",
        "scheduler.txt",
        "iosched_params.json",
        "metadata.json",
        "btt-summary.avg",
        "fio.stdout",
    ):
        candidate = run_dir / per_job_file
        if candidate.is_file():
            files_to_archive.append(candidate.resolve())

    time_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = snapshot_dir / f"configs_{time_stamp}.tar.gz"
    manifest_path = snapshot_dir / f"manifest_{args.label}_{time_stamp}.txt"
    resolved_config_path = snapshot_dir / f"resolved_config_{time_stamp}.json"

    resolved_config = {
        **metadata,
        "run_dir": str(run_dir),
        "output_dir": str(output_dir),
        "snapshot_dir": str(snapshot_dir),
        "cwd": str(cwd),
        "keep_raw": args.keep_raw,
        "rm_trace_bin": args.rm_trace_bin,
        "fail_on_drop": args.fail_on_drop,
        "no_snapshot": args.no_snapshot,
    }

    resolved_config_path.write_text(
        json.dumps(resolved_config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    files_to_archive.append(resolved_config_path.resolve())

    # Deduplicate while preserving order.
    deduped = []
    seen = set()
    for p in files_to_archive:
        p_str = str(p)
        if p.exists() and p_str not in seen:
            seen.add(p_str)
            deduped.append(p)
    files_to_archive = deduped

    def archive_name(path):
        path = Path(path).resolve()
        try:
            rel = os.path.relpath(path, ROOT)
            if not rel.startswith(".."):
                return rel
        except ValueError:
            pass
        return os.path.join("external", path.name)

    with tarfile.open(archive_path, "w:gz") as tar:
        for path in files_to_archive:
            tar.add(str(path), arcname=archive_name(path))

    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write(f"timestamp={datetime.now().isoformat()}\n")
        mf.write(f"root={ROOT}\n")
        mf.write(f"cwd={cwd}\n")
        mf.write(f"label={args.label}\n")
        mf.write(f"device={args.device}\n")
        mf.write(f"resolved_device={metadata.get('resolved_device')}\n")
        mf.write(f"run_dir={run_dir}\n")
        mf.write(f"output_dir={output_dir}\n")
        mf.write(f"fio_command={' '.join(fio_command)}\n")
        mf.write(f"active_scheduler={metadata.get('active_scheduler')}\n")
        mf.write(f"startup_gap_sec={metadata.get('startup_gap_sec')}\n")
        mf.write(f"ramp_time_sec={metadata.get('ramp_time_sec')}\n")
        mf.write(f"fio_start_offset_sec={metadata.get('fio_start_offset_sec')}\n")
        mf.write(f"analysis_start_sec={metadata.get('analysis_start_sec')}\n")
        mf.write(f"analysis_end_sec={metadata.get('analysis_end_sec')}\n")
        mf.write(f"fio_runtime_sec={metadata.get('fio_runtime_sec')}\n")
        mf.write(f"blktrace_total_events={metadata.get('blktrace_total_events')}\n")
        mf.write(f"blktrace_dropped_events={metadata.get('blktrace_dropped_events')}\n")
        mf.write(f"fio_rc={metadata.get('fio_rc')}\n")
        mf.write(f"wrapper_rc={metadata.get('wrapper_rc')}\n")
        mf.write("\n[checksums]\n")
        for path in files_to_archive:
            mf.write(f"{sha256_file(path)}  {archive_name(path)}\n")

    return archive_path, manifest_path, resolved_config_path


def main():
    parser = argparse.ArgumentParser(
        usage="%(prog)s DEVICE LABEL OUTPUT_DIR -- FIO_COMMAND [ARGS...] | as of 10/25/2026"
    )
    parser.add_argument("device")
    parser.add_argument("label")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--startup-gap",
        type=float,
        default=5.0,
        help="Seconds to wait between starting blktrace and launching fio",
    )
    parser.add_argument(
        "--ramp-time",
        default=None,
        help="fio ramp_time to exclude from blkparse/btt (e.g. 10 or 10s); auto-detected from fio job if omitted",
    )
    parser.add_argument(
        "--buf-size-kb",
        type=int,
        default=None,
        help="Per-CPU blktrace relay buffer size in KiB (blktrace -b)",
    )
    parser.add_argument(
        "--num-bufs",
        type=int,
        default=None,
        help="Number of per-CPU blktrace relay subbuffers (blktrace -n)",
    )
    parser.add_argument(
        "--fail-on-drop",
        action="store_true",
        help="Fail the run if blktrace reports any dropped events",
    )
    parser.add_argument(
        "--keep-raw",
        action="store_true",
        help="keep per-CPU trace.blktrace.* files after successful processing (note will take up a lot of disk space)",
    )
    parser.add_argument(
        "--rm-trace-bin",
        action="store_true",
        help="remove merged trace.bin after btt summaries are generated to save disk space",
    )
    parser.add_argument(
        "--no-snapshot",
        action="store_true",
        help="Do not create a config/manifest snapshot in the run directory",
    )
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Custom directory for snapshot archive and manifest (defaults to <run_dir>/snapshot)",
    )
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        parser.parse_args(["--help"])

    if "--" not in sys.argv[1:]:
        parser.error("separate the fio command with --")

    separator = sys.argv.index("--")
    args = parser.parse_args(sys.argv[1:separator])
    if args.startup_gap < 0:
        parser.error("--startup-gap must be nonnegative")
    if args.buf_size_kb is not None and args.buf_size_kb <= 0:
        parser.error("--buf-size-kb must be positive")
    if args.num_bufs is not None and args.num_bufs <= 0:
        parser.error("--num-bufs must be positive")
    fio_command = sys.argv[separator + 1:]  # fmt: skip

    if not fio_command:
        parser.error("A fio command is required after --")
    if os.geteuid() != 0:
        parser.error("run fiobatch or this wrapper as root")

    if args.label in ("", ".", "..") or Path(args.label).name != args.label:
        parser.error("LABEL must be a single directory name")

    if not Path(args.device).is_block_device():
        parser.error(f"Not a block device: {args.device}")

    for tool in ("blktrace", "blkparse", "btt", fio_command[0]):
        if shutil.which(tool) is None:
            parser.error(f"Executable not found: {tool}")

    stdin_bytes = None
    stdin_text = None
    if "-" in fio_command[1:]:
        stdin_bytes = sys.stdin.buffer.read()
        stdin_text = stdin_bytes.decode("utf-8", errors="replace")

    try:
        ramp_time_sec = resolve_ramp_time_seconds(
            args.ramp_time, fio_command, stdin_text
        )
    except ValueError as exc:
        parser.error(str(exc))

    # NOTE: (maybe remove this, idk)
    # refuse to overwrite a previous run.
    run_dir = args.output_dir.resolve() / args.label
    run_dir.mkdir(parents=True, exist_ok=False)

    job_fio_path = None
    if stdin_bytes is not None:
        job_fio_path = run_dir / "job.fio"
        job_fio_path.write_bytes(stdin_bytes)

    trace_prefix = run_dir / "trace"
    trace_binary = run_dir / "trace.bin"

    log(f"device={args.device}")
    log(f"output={run_dir}")
    log(f"startup_gap={args.startup_gap:.2f}s ramp_time={ramp_time_sec:.2f}s")

    trace_proc = None
    fio_proc = None
    fio_rc = None
    wrapper_rc = 1

    metadata = {
        "device": args.device,
        "resolved_device": str(Path(args.device).resolve()),
        "label": args.label,
        "fio_command": fio_command,
        "startup_gap_sec": args.startup_gap,
        "ramp_time_sec": ramp_time_sec,
        "buf_size_kb": args.buf_size_kb,
        "num_bufs": args.num_bufs,
        "active_scheduler": None,
        "scheduler_raw": None,
        "iosched_params": {},
        "fio_runtime_sec": None,
        "fio_start_offset_sec": None,
        "analysis_start_sec": None,
        "analysis_end_sec": None,
        "blktrace_total_events": None,
        "blktrace_dropped_events": None,
        "btt_counts": {},
        "fio_rc": None,
        "wrapper_rc": None,
    }

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, handle_signal)

    try:
        # trace_command = [
        #     "blktrace",
        #     "-d",
        #     args.device,
        #     "-o",
        #     str(trace_prefix),
        # ]
        # fmt: skip
        trace_command = [
            "blktrace",
            "-d",
            args.device,
            "-D",
            str(run_dir),
            "-o",
            "trace",
        ]
        if args.buf_size_kb is not None:
            trace_command.extend(["-b", str(args.buf_size_kb)])
        if args.num_bufs is not None:
            trace_command.extend(["-n", str(args.num_bufs)])

        with (
            (run_dir / "blktrace.stdout").open("wb") as trace_stdout,
            (run_dir / "blktrace.stderr").open("wb") as trace_stderr,
        ):
            trace_proc = subprocess.Popen(
                trace_command,
                stdin=subprocess.DEVNULL,
                stdout=trace_stdout,
                stderr=trace_stderr,
                start_new_session=True,
            )

            # Startup grace period, not a trace-duration limit.
            log(f"Waiting {args.startup_gap:.2f} seconds before starting fio")

            deadline = time.monotonic() + args.startup_gap

            while True:
                if trace_proc.poll() is not None:
                    raise RuntimeError(
                        "blktrace exited during startup; inspect blktrace.stderr"
                    )

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break

                time.sleep(min(0.1, remaining))

            log("Startup gap complete; launching fio")
            fio_wall_start = time.monotonic()

            with (
                (run_dir / "fio.stdout").open("wb") as fio_stdout,
                (run_dir / "fio.stderr").open("wb") as fio_stderr,
            ):
                if job_fio_path is not None:
                    with job_fio_path.open("rb") as fio_stdin:
                        fio_proc = subprocess.Popen(
                            fio_command,
                            stdin=fio_stdin,
                            stdout=fio_stdout,
                            stderr=fio_stderr,
                            start_new_session=True,
                        )
                else:
                    fio_proc = subprocess.Popen(
                        fio_command,
                        stdin=None,  # Preserve fiobatch's piped job-file input.
                        stdout=fio_stdout,
                        stderr=fio_stderr,
                        start_new_session=True,
                    )

                while True:
                    fio_rc = fio_proc.poll()
                    if fio_rc is not None:
                        break

                    if trace_proc.poll() is not None:
                        raise RuntimeError(
                            "blktrace exited before fio finished; "
                            "the trace may be incomplete"
                        )

                    time.sleep(0.1)

            metadata["fio_runtime_sec"] = round(time.monotonic() - fio_wall_start, 6)
            metadata["fio_rc"] = fio_rc
            (run_dir / "fio.rc").write_text(f"{fio_rc}\n")

            active_sched, sched_raw, iosched_params = save_scheduler(
                args.device, run_dir / "scheduler.txt"
            )
            metadata["active_scheduler"] = active_sched
            metadata["scheduler_raw"] = sched_raw
            metadata["iosched_params"] = iosched_params
            if iosched_params:
                (run_dir / "iosched_params.json").write_text(
                    json.dumps(iosched_params, indent=2, sort_keys=True) + "\n"
                )

            # Flush/close tracing before reading the raw files.
            stop_process(trace_proc, signal.SIGINT)

        total_events, dropped_events = parse_blktrace_stats(run_dir / "blktrace.stdout")
        metadata["blktrace_total_events"] = total_events
        metadata["blktrace_dropped_events"] = dropped_events
        if total_events is not None:
            log(f"blktrace total_events={total_events} dropped={dropped_events}")
        if dropped_events and dropped_events > 0:
            drop_msg = (
                f"blktrace dropped {dropped_events} events "
                f"(out of {total_events}); consider --buf-size-kb / --num-bufs"
            )
            if args.fail_on_drop:
                raise RuntimeError(drop_msg)
            log(f"WARNING: {drop_msg}")

        # Forward ONLY fio output to fiobatch's result parser.
        with (run_dir / "fio.stdout").open("rb") as source:
            shutil.copyfileobj(source, sys.stdout.buffer)
        sys.stdout.buffer.flush()

        with (run_dir / "fio.stderr").open("rb") as source:
            shutil.copyfileobj(source, sys.stderr.buffer)
        sys.stderr.buffer.flush()

        fio_start_sec, post_fio_cutoff_sec = find_fio_window_bounds_sec(
            run_dir, fio_root_pid=fio_proc.pid if fio_proc else None
        )
        analysis_start_sec = fio_start_sec + ramp_time_sec
        metadata["fio_start_offset_sec"] = round(fio_start_sec, 9)
        metadata["analysis_start_sec"] = round(analysis_start_sec, 9)
        metadata["analysis_end_sec"] = (
            round(post_fio_cutoff_sec, 9) if post_fio_cutoff_sec is not None else None
        )

        blkparse_cmd = [
            "blkparse",
            "-i",
            "trace",
            "-d",
            "trace.bin",
            "-O",
        ]
        btt_cmd = [
            "btt",
            "-i",
            "trace.bin",
            "-o",
            "btt-summary",
        ]

        if ramp_time_sec > 0 or post_fio_cutoff_sec is not None:
            start_arg = f"{analysis_start_sec:.9f}"
            blkparse_end_arg = (
                f"{post_fio_cutoff_sec:.9f}"
                if post_fio_cutoff_sec is not None
                else "999999"
            )
            btt_end_arg = (
                f"{post_fio_cutoff_sec:.9f}"
                if post_fio_cutoff_sec is not None
                else "1e9"
            )
            log(
                f"fio_start_offset={fio_start_sec:.6f}s "
                f"ramp_time={ramp_time_sec:.2f}s "
                f"analysis_start={analysis_start_sec:.6f}s "
                f"analysis_end={btt_end_arg}"
            )
            blkparse_cmd.extend(["-w", f"{start_arg}:{blkparse_end_arg}"])
            btt_cmd.extend(["-t", start_arg, "-T", btt_end_arg])

        with (run_dir / "postprocess.log").open("wb") as tool_log:
            # subprocess.run(
            #     [
            #         "blkparse",
            #         "-i",
            #         str(trace_prefix),
            #         "-d",
            #         str(trace_binary),
            #         "-O",
            #     ],
            #     stdin=subprocess.DEVNULL,
            #     stdout=tool_log,
            #     stderr=subprocess.STDOUT,
            #     check=True,
            # )
            subprocess.run(
                blkparse_cmd,
                cwd=run_dir,
                stdin=subprocess.DEVNULL,
                stdout=tool_log,
                stderr=subprocess.STDOUT,
                check=True,
            )

            if not trace_binary.exists() or trace_binary.stat().st_size == 0:
                raise RuntimeError("blkparse produced no binary trace data")

            subprocess.run(
                btt_cmd,
                cwd=run_dir,
                stdin=subprocess.DEVNULL,
                stdout=tool_log,
                stderr=subprocess.STDOUT,
                check=True,
            )

        summary = run_dir / "btt-summary.avg"
        if not summary.exists() or summary.stat().st_size == 0:
            raise RuntimeError("btt produced no nonempty summary")

        btt_counts = parse_btt_counts(summary)
        metadata["btt_counts"] = btt_counts
        if not btt_counts:
            raise RuntimeError("btt-summary.avg contains no All Devices latency rows")
        q2c_n = btt_counts.get("Q2C")
        d2c_n = btt_counts.get("D2C")
        if q2c_n is not None and d2c_n is not None and q2c_n != d2c_n:
            log(
                f"WARNING: btt Q2C count ({q2c_n}) != D2C count ({d2c_n}); "
                "downstream paired scripts may reject this run"
            )

        # Keep raw files on fio failure for investigation.
        if fio_rc == 0 and not args.keep_raw:
            for path in run_dir.glob("trace.blktrace.*"):
                path.unlink()

        if fio_rc == 0 and args.rm_trace_bin and trace_binary.exists():
            trace_binary.unlink()

        wrapper_rc = fio_rc if fio_rc >= 0 else 128 - fio_rc
        log(f"done; fio exit code={fio_rc}")

    except Interrupted as exc:
        wrapper_rc = 128 + exc.signum
        log(f"Interrupted by signal {exc.signum}; preserving trace files")

    except Exception as exc:
        log(f"ERROR: {exc}")
        log("Preserving available files for investigation")
        wrapper_rc = 1

    finally:
        # Avoid interruption halfway through cleanup.
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)

        try:
            stop_process(fio_proc, signal.SIGTERM)
            stop_process(trace_proc, signal.SIGINT)
        except Exception as exc:
            log(f"Cleanup error: {exc}")
            wrapper_rc = 1

        if fio_proc is not None:
            actual_rc = fio_proc.poll()
            if actual_rc is not None:
                metadata["fio_rc"] = actual_rc
                (run_dir / "fio.rc").write_text(f"{actual_rc}\n")

        metadata["wrapper_rc"] = wrapper_rc
        (run_dir / "wrapper.rc").write_text(f"{wrapper_rc}\n")
        try:
            (run_dir / "metadata.json").write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n"
            )
        except OSError as exc:
            log(f"Could not write metadata.json: {exc}")

        if not args.no_snapshot:
            target_snapshot_dir = (
                args.snapshot_dir
                if args.snapshot_dir is not None
                else run_dir / "snapshot"
            )
            try:
                create_snapshot(
                    target_snapshot_dir,
                    run_dir,
                    args.output_dir,
                    args,
                    fio_command,
                    metadata,
                )
            except Exception as exc:
                log(f"Could not create snapshot: {exc}")

    return wrapper_rc


if __name__ == "__main__":
    sys.exit(main())
