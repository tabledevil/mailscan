"""Subprocess wrappers for external JS analysis tools (box-js, JStillery, de4js).

Pure functions — no Analyzer coupling. Each tool degrades silently if not installed.
All tools run locally with no network access (box-js emulates network calls).
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile

log = logging.getLogger("matt")

# ---------------------------------------------------------------
# box-js
# ---------------------------------------------------------------

def boxjs_available() -> bool:
    return shutil.which("box-js") is not None


def run_boxjs(raw_data: bytes, timeout: int = 30) -> dict | None:
    """Run box-js on raw JS data. Returns parsed results dict or None.

    Result keys: urls, active_urls, iocs, snippets, resources, payloads
    """
    with tempfile.TemporaryDirectory(prefix="matt_boxjs_") as tmpdir:
        js_path = os.path.join(tmpdir, "sample.js")
        with open(js_path, "wb") as f:
            f.write(raw_data)

        try:
            subprocess.run(
                ["box-js", "--no-kill", "--no-echo", "--output-dir",
                 os.path.join(tmpdir, "results"), "--timeout", str(timeout),
                 js_path],
                capture_output=True, timeout=timeout + 10,
                cwd=tmpdir,
            )
        except subprocess.TimeoutExpired:
            log.debug("box-js timed out")
            return None
        except Exception as e:
            log.debug("box-js failed: %s", e)
            return None

        # box-js may create results/ or sample.js.results/
        results_dir = os.path.join(tmpdir, "results")
        if not os.path.isdir(results_dir):
            results_dir = js_path + ".results"
            if not os.path.isdir(results_dir):
                return None

        result = {}
        for name in ("urls", "active_urls", "IOC", "snippets", "resources"):
            json_path = os.path.join(results_dir, f"{name}.json")
            if os.path.isfile(json_path):
                try:
                    with open(json_path) as fh:
                        result[name.lower()] = json.load(fh)
                except Exception:
                    pass

        # Collect extracted payload files (non-JSON, non-log)
        payloads = []
        for entry in os.listdir(results_dir):
            full = os.path.join(results_dir, entry)
            if os.path.isfile(full) and not entry.endswith(".json") and entry != "analysis.log":
                try:
                    with open(full, "rb") as fh:
                        payloads.append({"filename": entry, "data": fh.read()})
                except Exception:
                    pass
        if payloads:
            result["payloads"] = payloads

        return result if result else None


# ---------------------------------------------------------------
# JStillery
# ---------------------------------------------------------------

def jstillery_available() -> bool:
    return shutil.which("jstillery_cli.js") is not None or shutil.which("jstillery") is not None


def _jstillery_cmd() -> str:
    return shutil.which("jstillery_cli.js") or shutil.which("jstillery") or "jstillery_cli.js"


def run_jstillery(source: str, timeout: int = 15) -> str | None:
    """Run JStillery on JS source. Returns deobfuscated source or None."""
    try:
        result = subprocess.run(
            [_jstillery_cmd()],
            input=source, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            deobfuscated = result.stdout
            if deobfuscated.strip() != source.strip():
                return deobfuscated
    except subprocess.TimeoutExpired:
        log.debug("JStillery timed out")
    except Exception as e:
        log.debug("JStillery failed: %s", e)
    return None


# ---------------------------------------------------------------
# de4js (node-based deobfuscator)
# ---------------------------------------------------------------

def de4js_available() -> bool:
    return shutil.which("de4js") is not None


def run_de4js(source: str, timeout: int = 15) -> str | None:
    """Run de4js on JS source. Returns unpacked source or None."""
    try:
        result = subprocess.run(
            ["de4js"],
            input=source, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            unpacked = result.stdout
            if unpacked.strip() != source.strip():
                return unpacked
    except subprocess.TimeoutExpired:
        log.debug("de4js timed out")
    except Exception as e:
        log.debug("de4js failed: %s", e)
    return None
