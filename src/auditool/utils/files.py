from datetime import datetime
from pathlib import Path


def create_timestamped_output_dir(base_output_dir: str) -> Path:
    """
    Create an output directory with timestamp for the current execution.
    Example: output/scan_20260421_120530
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(base_output_dir) / f"scan_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir
