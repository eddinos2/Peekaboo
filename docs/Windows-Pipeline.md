# Windows Pipeline (Scaffold)

Full Windows gather is **deferred** until a Windows host or VM is available.

## Planned flow (from patchdiff-ai study)

1. MSRC CVRF advisory fetch
2. Microsoft Update Catalog KB download (pre/post `.msu`)
3. 7-Zip + PSF delta apply
4. WinSxS binary index
5. Shared RE + VR pipeline

## Available today on macOS

```bash
peekaboo windows cve CVE-2025-29824 --pre ./pre_dlls/ --post ./post_dlls/
```

## When VM ready

- Implement `platforms/windows/kb_downloader.py`
- Implement `platforms/windows/extractor.py`
- Add `peekaboo windows index` for WinSxS
