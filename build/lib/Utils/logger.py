import logging
import sys
import os

def setup_logging(verbosity=0, debug=False, log_file="mailscan.log"):
    """
    Configures the root logger with console and file handlers.

    Args:
        verbosity (int): Verbosity level (0-5).
        debug (bool): If True, enables debug logging.
        log_file (str): Path to log file.
    """
    # Determine base logging level
    if debug or verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Set root to DEBUG to allow handlers to filter

    # Remove existing handlers
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # Console Handler (Stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)

    # Simpler formatter for console
    console_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File Handler
    try:
        # Ensure directory exists? Current dir is assumed writable.
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        # File always logs at least INFO, or DEBUG if requested
        file_level = logging.DEBUG if debug or verbosity >= 1 else logging.INFO
        file_handler.setLevel(file_level)

        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(name)s - %(module)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        # Use basic print since logger is not fully set up
        sys.stderr.write(f"Warning: Failed to setup log file '{log_file}': {e}\n")
