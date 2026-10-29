# Fixtures

Synthetic evidence and harmless decoys only. Do not add malware, persistence, or network-beaconing code.

## Harmless Decoys

1. `disk_link_decoy.py --parent PATH --mode hold|reopen`:
   Creates a temporary folder under `PATH`, prints its folder and writer PID, and appends dummy bytes for about 60 seconds or until 128 MiB is written, whichever comes first. `--seconds` and `--max-bytes` can set the limits. The target drive needs at least 1 GiB free. The temporary folder is removed on exit. `hold` keeps the file handle open; `reopen` closes it after each write. It is for controlled process-to-disk attribution checks only.

2. `harmless_process_decoy.py --mode idler|temp_writer|renamed_copy`:
   Runs a bounded, harmless live process decoy in a dedicated temporary folder. Supports idling (`idler`), bounded dummy file writes (`temp_writer`), and benign utility/script copies (`renamed_copy`). Guarantees automatic cleanup on exit. Strictly enforces a 60-second runtime ceiling and 10 MiB write limit with zero network access and zero persistence.

## Labeled Scenarios

- `fixtures/scenarios/process/`: 50 labeled process scenarios (common benign, benign-but-odd, simulated suspicious).
- `fixtures/scenarios/storage/`: 36 labeled storage scenarios (clearly safe, review first, do not touch).
- `fixtures/scenarios/injection/`: 6 prompt injection defense scenarios.
- `fixtures/scenarios/api_failure/`: 5 AI provider failure and fallback scenarios.
- `fixtures/reports/`: Handwritten, fully grounded investigation report fixtures for realistic testing.
