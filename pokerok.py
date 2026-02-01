#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

FILES = ["pokerok.dmg", "pokerok.msi"]


def run_cmd(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run a command safely and capture output."""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as e:
        return {"cmd": cmd, "error": str(e)}


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")


def basic_file_info(path: Path) -> Dict[str, Any]:
    st = path.stat()
    return {
        "path": str(path.resolve()),
        "exists": True,
        "size_bytes": st.st_size,
        "modified": fmt_ts(st.st_mtime),
        "created": fmt_ts(st.st_ctime),
    }


def dmg_info(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {"type": "dmg"}
    # macOS-specific: hdiutil info (doesn't require mounting)
    if platform.system() == "Darwin" and shutil.which("hdiutil"):
        info["hdiutil_imageinfo"] = run_cmd(["hdiutil", "imageinfo", str(path)])
    # cross-platform: just note not available
    return info


def msi_info(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {"type": "msi"}

    # Windows-specific: signature info with PowerShell (Get-AuthenticodeSignature)
    if platform.system() == "Windows":
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if ps:
            script = (
                "param($p)\n"
                "$sig = Get-AuthenticodeSignature -FilePath $p\n"
                "$out = [ordered]@{\n"
                "  Status = $sig.Status.ToString();\n"
                "  StatusMessage = $sig.StatusMessage;\n"
                "  SignerCertificate = if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{$null};\n"
                "  TimeStamperCertificate = if($sig.TimeStamperCertificate){$sig.TimeStamperCertificate.Subject}else{$null};\n"
                "}\n"
                "$out | ConvertTo-Json -Compress\n"
            )
            info["authenticode"] = run_cmd([ps, "-NoProfile", "-Command", script, "-p", str(path)])

        # Also try to extract MSI properties via msiexec logging (lightweight hint)
        if shutil.which("msiexec"):
            info["msiexec_help_present"] = True

    return info


def file_kind_hint(path: Path) -> Optional[str]:
    # Optional: unix "file" command
    if shutil.which("file"):
        res = run_cmd(["file", "-b", str(path)])
        if res.get("returncode") == 0:
            return res.get("stdout")
    return None


def collect(path_str: str) -> Dict[str, Any]:
    path = Path(path_str)
    if not path.exists():
        return {"path": str(path), "exists": False}

    data: Dict[str, Any] = basic_file_info(path)
    data["sha256"] = sha256_file(path)
    data["kind_hint"] = file_kind_hint(path)

    lower = path.name.lower()
    if lower.endswith(".dmg"):
        data.update(dmg_info(path))
    elif lower.endswith(".msi"):
        data.update(msi_info(path))
    else:
        data["type"] = "unknown"

    return data


def main() -> None:
    report = {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "files": [collect(f) for f in FILES],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()