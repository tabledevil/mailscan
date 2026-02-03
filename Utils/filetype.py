from __future__ import annotations

from dataclasses import dataclass, field
import importlib
import importlib.util
import logging
import mimetypes
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence

from Config.config import flags


@dataclass(frozen=True)
class DetectionResult:
    mime: str
    description: str
    provider: str
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "mime": self.mime,
            "description": self.description,
            "provider": self.provider,
            "errors": list(self.errors),
        }


class ProviderError(RuntimeError):
    pass


class BaseProvider:
    name: str = "base"

    def detect(self, data: bytes, filename: Optional[str] = None) -> DetectionResult:
        raise NotImplementedError


class PythonMagicProvider(BaseProvider):
    name = "python_magic"

    def detect(self, data: bytes, filename: Optional[str] = None) -> DetectionResult:
        if importlib.util.find_spec("magic") is None:
            raise ProviderError("python-magic is not installed")
        magic_module = importlib.import_module("magic")
        mime = magic_module.from_buffer(data, mime=True)
        description = magic_module.from_buffer(data)
        return DetectionResult(mime=mime, description=description, provider=self.name)


class FileCommandProvider(BaseProvider):
    name = "file_command"

    def __init__(self, timeout_s: Optional[float] = None) -> None:
        self.timeout_s = timeout_s

    def _run(self, args: Sequence[str], data: bytes) -> subprocess.CompletedProcess:
        if not shutil.which(args[0]):
            raise ProviderError(f"Missing system command: {args[0]}")
        try:
            return subprocess.run(
                list(args),
                input=data,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(f"file command timed out after {self.timeout_s}s") from exc

    def detect(self, data: bytes, filename: Optional[str] = None) -> DetectionResult:
        mime_proc = self._run(["file", "--mime-type", "--brief", "-"], data)
        if mime_proc.returncode != 0:
            stderr = mime_proc.stderr.strip()
            raise ProviderError(f"file command failed: {stderr or 'unknown error'}")
        mime = mime_proc.stdout.strip()

        description = ""
        desc_proc = self._run(["file", "--brief", "-"], data)
        if desc_proc.returncode == 0:
            description = desc_proc.stdout.strip()
        else:
            logging.warning(
                "file command description failed: %s",
                desc_proc.stderr.strip() or "unknown error",
            )
        return DetectionResult(mime=mime, description=description, provider=self.name)


class MagikaProvider(BaseProvider):
    name = "magika"
    _instance = None

    def _get_instance(self):
        if importlib.util.find_spec("magika") is None:
            raise ProviderError("magika is not installed")
        magika_module = importlib.import_module("magika")
        if MagikaProvider._instance is None:
            MagikaProvider._instance = magika_module.Magika()
        return MagikaProvider._instance

    @staticmethod
    def _read_attr(obj, *names):
        for name in names:
            if hasattr(obj, name):
                return getattr(obj, name)
        return None

    def detect(self, data: bytes, filename: Optional[str] = None) -> DetectionResult:
        instance = self._get_instance()
        prediction = instance.identify_bytes(data)
        output = self._read_attr(prediction, "output") or prediction
        mime = self._read_attr(output, "mime_type", "mime")
        label = self._read_attr(output, "label", "description")
        if not mime:
            raise ProviderError("magika did not return a mime type")
        description = label or ""
        return DetectionResult(mime=mime, description=description, provider=self.name)


_PROVIDERS: Dict[str, BaseProvider] = {
    PythonMagicProvider.name: PythonMagicProvider(),
    FileCommandProvider.name: FileCommandProvider(timeout_s=getattr(flags, "mime_file_command_timeout", 2.0)),
    MagikaProvider.name: MagikaProvider(),
}


def _parse_provider_order(value: Optional[object]) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _resolve_provider_order() -> List[str]:
    env_value = os.getenv("MAILSCAN_MIME_PROVIDER_ORDER")
    order = _parse_provider_order(getattr(flags, "mime_provider_order", None))
    env_order = _parse_provider_order(env_value)
    if env_order:
        return env_order
    if order:
        return order
    return ["python_magic", "file_command", "magika"]


def detect_mime(data: bytes, filename: Optional[str] = None) -> DetectionResult:
    errors: List[str] = []
    order = _resolve_provider_order()
    for provider_name in order:
        provider = _PROVIDERS.get(provider_name)
        if provider is None:
            message = f"Unknown provider: {provider_name}"
            logging.warning(message)
            errors.append(message)
            continue
        try:
            result = provider.detect(data, filename=filename)
            if errors:
                return DetectionResult(
                    mime=result.mime,
                    description=result.description,
                    provider=result.provider,
                    errors=errors,
                )
            return result
        except ProviderError as exc:
            message = f"{provider_name}: {exc}"
            logging.warning(message)
            errors.append(message)
        except Exception as exc:
            message = f"{provider_name}: unexpected error {exc}"
            logging.exception(message)
            errors.append(message)

    guessed_mime, _ = mimetypes.guess_type(filename or "")
    fallback_mime = guessed_mime or "application/octet-stream"
    description = "Unknown"
    return DetectionResult(
        mime=fallback_mime,
        description=description,
        provider="fallback",
        errors=errors,
    )
