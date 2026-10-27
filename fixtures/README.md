# Fixtures

Synthetic evidence and harmless decoys only. Do not add malware, persistence, or network-beaconing code.

`disk_link_decoy.py --parent PATH --mode hold|reopen` creates a temporary folder
under `PATH`, prints its folder and writer PID, and appends dummy bytes for about
60 seconds or until 128 MiB is written, whichever comes first. `--seconds` and
`--max-bytes` can set the limits. The target drive needs at least 1 GiB free.
The temporary folder is removed on exit. `hold` keeps the file handle open;
`reopen` closes it after each write. It is for controlled process-to-disk
attribution checks only.
