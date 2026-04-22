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


def generate_summary(scan_txt: Path, output_summary: Path) -> None:
    """
    Generate a simplified technical summary from Nmap normal output.

    The goal is to keep only the most useful host-level information
    for later use in report drafting or LLM-assisted analysis.
    """
    content = scan_txt.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    summary_lines: list[str] = []
    current_host = None

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("Nmap scan report for"):
            current_host = stripped
            summary_lines.append("")
            summary_lines.append(stripped)

        elif stripped.startswith("PORT"):
            if current_host:
                summary_lines.append(stripped)

        elif stripped.startswith("Not shown"):
            continue

        elif stripped and current_host:
            if "/tcp" in stripped and "open" in stripped:
                summary_lines.append(stripped)

    output_summary.write_text("\n".join(summary_lines).strip() + "\n", encoding="utf-8")


def run_scan_workflow(
    targets_file: str,
    config_path: str,
    logger: Any
) -> Path:
    """
    Main workflow:
    - load config
    - validate targets
    - create output dir
    - execute normal Nmap scan
    - execute vulnerability scan with NSE
    - write evidence files
    - generate summary
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
    vuln_output = output_dir / "vuln.txt"
    summary_output = output_dir / "summary.txt"
    command_output = output_dir / "command.txt"
    metadata_output = output_dir / "metadata.txt"
    targets_copy_output = output_dir / "targets.txt"

    nmap_path = scan_config.get("nmap_path", "nmap")
    ensure_nmap_available(nmap_path)

    # ===============================
    # FIRST SCAN: NORMAL ENUMERATION
    # ===============================
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

    # ===============================
    # SECOND SCAN: VULNERABILITIES
    # ===============================
    logger.info("Starting vulnerability scan with NSE")

    vuln_command = [
        nmap_path,
        "--script", "vuln",
        "-T", str(scan_config.get("timing_template", 3)),
        "-oN", str(vuln_output),
    ] + targets

    logger.info("Executing vulnerability command: %s", " ".join(vuln_command))

    vuln_result = run_nmap(vuln_command)

    logger.info(
        "Vulnerability scan finished in %s seconds",
        vuln_result["duration_seconds"]
    )
    logger.info(
        "Vulnerability scan return code: %s",
        vuln_result["returncode"]
    )

    if vuln_result["stdout"].strip():
        logger.info("Vulnerability stdout:\n%s", vuln_result["stdout"].strip())

    if vuln_result["stderr"].strip():
        logger.warning("Vulnerability stderr:\n%s", vuln_result["stderr"].strip())

    if vuln_result["returncode"] != 0:
        raise NmapExecutionError(
            f"Vulnerability scan failed with code: {vuln_result['returncode']}"
        )

    if not vuln_output.exists():
        raise NmapExecutionError("Vulnerability output file was not created")

    logger.info("Vulnerability output saved to: %s", vuln_output)

    # ===============================
    # WRITE EVIDENCE FILES
    # ===============================
    write_text_file(command_output, " ".join(command) + "\n")
    write_text_file(targets_copy_output, "\n".join(targets) + "\n")

    metadata_content = (
        f"targets_file: {targets_file}\n"
        f"validated_targets: {len(targets)}\n"
        f"xml_output: {xml_output}\n"
        f"normal_output: {normal_output}\n"
        f"vuln_output: {vuln_output}\n"
        f"return_code_normal: {result['returncode']}\n"
        f"duration_seconds_normal: {result['duration_seconds']}\n"
        f"return_code_vuln: {vuln_result['returncode']}\n"
        f"duration_seconds_vuln: {vuln_result['duration_seconds']}\n"
    )

    if result["stderr"].strip():
        metadata_content += "\nnormal_stderr:\n"
        metadata_content += result["stderr"].strip() + "\n"

    if vuln_result["stderr"].strip():
        metadata_content += "\nvuln_stderr:\n"
        metadata_content += vuln_result["stderr"].strip() + "\n"

    write_text_file(metadata_output, metadata_content)

    logger.info("Scan XML saved to: %s", xml_output)
    logger.info("Scan text output saved to: %s", normal_output)
    logger.info("Command saved to: %s", command_output)
    logger.info("Metadata saved to: %s", metadata_output)
    logger.info("Targets copy saved to: %s", targets_copy_output)

    # ===============================
    # GENERATE SUMMARY
    # ===============================
    generate_summary(normal_output, summary_output)
    logger.info("Summary saved to: %s", summary_output)

    return output_dir
