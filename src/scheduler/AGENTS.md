# Schedulers

The backend (`src/start_fact_backend.py`) wires everything together; all schedulers use multiprocessing.

```text
frontend upload → Redis task queue → InterComBackEndBinding (src/intercom/back_end_binding.py)
  → UnpackingScheduler: extracts files in fact_extractor Docker containers
  → post_unpack = AnalysisScheduler.start_analysis_of_object (for the firmware and every extracted file)
  → AnalysisScheduler: runs plugins (dependencies first) in worker processes, results → PostgreSQL
ComparisonScheduler: separate queue, runs compare plugins on finished firmwares
```

- The extractor is a separate project (`fkiecad/fact_extractor` on Docker Hub); unpacking itself is not done
  in this repo, only the container handling (`src/unpacker/`).
- Settings: `[backend]` and `[backend.unpacking]` in `src/config/fact-core-config.toml`
  (worker counts, `max-depth`, mime `whitelist` = files not extracted, `throttle-limit`).
- Files are identified by uid (hash): a file occurring several times in a firmware is unpacked and analyzed
  only once (only its virtual file paths are added).
- Many worker processes → many open file descriptors; `start_fact_backend.py:_check_ulimit` raises the soft limit.
- `analysis_status.py` tracks per-firmware progress in a separate process (shown in the frontend).
- Tests: scheduler fixtures in `src/test/conftest.py` are configured with the `SchedulerTestConfig` marker
  (see `src/test/AGENTS.md`).
