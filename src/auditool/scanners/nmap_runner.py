import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from auditool.exceptions import NmapExecutionError


def build_nmap_command(
    targets: list[str],
    xml_output: Path,
    normal_output: Path,
    scan_config: dict[str, Any]
) -> list[str]:
    """
    Build a safe Nmap command as a list of arguments.
    """
    nmap_path = scan_config.get("nmap_path", "nmap")
    command = [nmap_path]

    ping_discovery = scan_config.get("ping_discovery", True)
    service_detection = scan_config.get("service_detection", True)
    resolve_dns = scan_config.get("resolve_dns", True)
    top_ports = int(scan_config.get("top_ports", 1000))
    timing_template = int(scan_config.get("timing_template", 3))

    if not ping_discovery:
        command.append("-Pn")

    if service_detection:
        command.append("-sV")

    if not resolve_dns:
        command.append("-n")

    command.extend(["--top-ports", str(top_ports)])
    command.extend(["-T", str(timing_template)])

    command.extend(["-oX", str(xml_output)])
    command.extend(["-oN", str(normal_output)])

    command.extend(targets)

    return command


def ensure_nmap_available(nmap_path: str = "nmap") -> None:
    """
    Ensure Nmap exists in the system path.
    """
    if shutil.which(nmap_path) is None:
        raise NmapExecutionError(
            f"Nmap executable not found in PATH: {nmap_path}"
        )


def run_nmap(command: list[str], timeout: int | None = None) -> dict[str, Any]:
    """
    Execute Nmap and return execution details.
    """
    start = time.time()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapExecutionError("Nmap execution timed out") from exc
    except OSError as exc:
        raise NmapExecutionError(f"Failed to execute Nmap: {exc}") from exc

    duration = round(time.time() - start, 2)

    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration_seconds": duration,
        "command": command,
    }
