from pathlib import Path
from typing import Any

from auditool.config import load_config
from auditool.exceptions import NmapExecutionError
from auditool.scanners.nmap_runner import (
    build_nmap_command,
    ensure_nmap_available,
    run_nmap,
)
from auditool.utils.files import create_timestamped_output_dir
from auditool.utils.validators import load_and_validate_targets


def write_text_file(path: Path, content: str) -> None:
    """
    Write plain text content to a file using UTF-8.
    """
    path.write_text(content, encoding="utf-8")


def run_scan_workflow(
    targets_file: str,
    config_path: str,
    logger: Any
) -> Path:
    """
    Main workflow for phase 1:
    - load config
    - validate targets
    - create output dir
    - execute Nmap
    - write evidence files
    - return output directory path
    """
    config = load_config(config_path)
    scan_config = config.get("scan", {})
    output_base_dir = config.get("output_dir", "output")

    logger.info("Loading and validating targets from: %s", targets_file)
    targets = load_and_validate_targets(targets_file)
    logger.info("Validated %d target entries", len(targets))

    output_dir = create_timestamped_output_dir(output_base_dir)
    logger.info("Output directory created: %s", output_dir)

    xml_output = output_dir / "scan.xml"
    normal_output = output_dir / "scan.txt"
    command_output = output_dir / "command.txt"
    metadata_output = output_dir / "metadata.txt"
    targets_copy_output = output_dir / "targets.txt"

    nmap_path = scan_config.get("nmap_path", "nmap")
    ensure_nmap_available(nmap_path)

    command = build_nmap_command(
        targets=targets,
        xml_output=xml_output,
        normal_output=normal_output,
        scan_config=scan_config
    )

    logger.info("Executing Nmap command")
    logger.info("Command: %s", " ".join(command))

    result = run_nmap(command)

    logger.info("Nmap finished in %s seconds", result["duration_seconds"])
    logger.info("Nmap return code: %s", result["returncode"])

    if result["stdout"].strip():
        logger.info("Nmap stdout:\n%s", result["stdout"].strip())

    if result["stderr"].strip():
        logger.warning("Nmap stderr:\n%s", result["stderr"].strip())

    if result["returncode"] != 0:
        raise NmapExecutionError(
            f"Nmap returned non-zero exit code: {result['returncode']}"
        )

    if not xml_output.exists():
        raise NmapExecutionError(
            f"Nmap finished but XML output was not created: {xml_output}"
        )

    if not normal_output.exists():
        raise NmapExecutionError(
            f"Nmap finished but normal output was not created: {normal_output}"
        )

    write_text_file(command_output, " ".join(command) + "\n")
    write_text_file(targets_copy_output, "\n".join(targets) + "\n")

    metadata_content = (
        f"targets_file: {targets_file}\n"
        f"validated_targets: {len(targets)}\n"
        f"xml_output: {xml_output}\n"
        f"normal_output: {normal_output}\n"
        f"return_code: {result['returncode']}\n"
        f"duration_seconds: {result['duration_seconds']}\n"
    )

    if result["stderr"].strip():
        metadata_content += "\nstderr:\n"
        metadata_content += result["stderr"].strip() + "\n"

    write_text_file(metadata_output, metadata_content)

    logger.info("Scan XML saved to: %s", xml_output)
    logger.info("Scan text output saved to: %s", normal_output)
    logger.info("Command saved to: %s", command_output)
    logger.info("Metadata saved to: %s", metadata_output)
    logger.info("Targets copy saved to: %s", targets_copy_output)

    return output_dir
