"""Common util functions."""

import os


def check_read_access(filepath: str) -> None:
    """Check if the file exists and has read access."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File '{filepath}' does not exist.")
    if not os.access(filepath, os.R_OK):
        raise PermissionError(f"No read access to file '{filepath}'.")


def check_write_access(filepath: str) -> None:
    """Check if the file exists and has write access."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File '{filepath}' does not exist.")
    if not os.access(filepath, os.W_OK):
        raise PermissionError(f"No write access to file '{filepath}'.")
