# Results

- [`RESULTS.md`](RESULTS.md): Generated offline evaluation report across 143 test cases covering process rule precision/recall, storage safety, prompt injection defenses, policy rejection, grounding verification with mock provider, and orchestrator API fallback resilience.
- [`eval_results.json`](eval_results.json): Machine-readable JSON output documenting row-level results and provider/model provenance.
- [`storage-benchmark.json`](storage-benchmark.json): Records three Windows scans of a synthetic 1,008-file tree. See [reproduction and timing scope](../docs/storage.md#reproducible-sample-tree-timing).

## Reproduction

Run the offline evaluation harness from the repository root:

```powershell
python -m moonlight.eval --offline
```
