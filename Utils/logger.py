"""Logging setup for MATT."""

import logging
import sys


def setup_logging(verbosity=0, debug=False, log_file=None):
    """Configure the ``matt`` logger with console and optional file handlers.

    Args:
        verbosity: 0 = WARNING, 1 = INFO, 2+ = DEBUG.
        debug:     If True, force DEBUG level.
        log_file:  Path to a log file.  ``None`` disables file logging.
    """
    if debug or verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    # Use a named logger so third-party noise (chardet, urllib3, PIL …)
    # stays at WARNING unless the user explicitly wants root-level debug.
    matt_logger = logging.getLogger("matt")
    matt_logger.setLevel(logging.DEBUG)

    # Remove existing handlers (in case setup_logging is called twice)
    for handler in matt_logger.handlers[:]:
        matt_logger.removeHandler(handler)

    # --- Console handler (stderr) ---
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    matt_logger.addHandler(console)

    # --- File handler (optional) ---
    if log_file:
        try:
            fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            fh.setLevel(logging.DEBUG if debug else logging.INFO)
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(levelname)s - %(name)s - %(module)s:%(lineno)d - %(message)s"
                )
            )
            matt_logger.addHandler(fh)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to setup log file '{log_file}': {e}\n")

    # Suppress noisy third-party loggers
    for noisy in ("chardet", "charset_normalizer", "urllib3", "PIL", "magika"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
