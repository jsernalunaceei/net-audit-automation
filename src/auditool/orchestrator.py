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


def extract_host_blocks(nmap_text: str) -> list[list[str]]:
    """
    Split Nmap normal output into blocks, one per host.
    Each block starts with 'Nmap scan report for ...'
    """
    lines = nmap_text.splitlines()
    blocks: list[list[str]] = []
    current_block: list[str] = []

    for line in lines:
        if line.startswith("Nmap scan report for"):
            if current_block:
                blocks.append(current_block)
            current_block = [line]
        else:
            if current_block:
                current_block.append(line)

    if current_block:
        blocks.append(current_block)

    return blocks


def get_host_header(block: list[str]) -> str:
    """
    Return the host header line from a host block.
    """
    if not block:
        return "UNKNOWN HOST"
    return block[0].strip()


def extract_relevant_scan_lines(block: list[str]) -> list[str]:
    """
    Extract factual, non-interpretive lines from a normal Nmap host block.
    """
    extracted: list[str] = []
    capture_ports = False

    for raw_line in block[1:]:
        line = raw_line.rstrip()

        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("Host is up"):
            extracted.append(stripped)
            continue

        if stripped.startswith("Other addresses for"):
            extracted.append(stripped)
            continue

        if stripped.startswith("MAC Address:"):
            extracted.append(stripped)
            continue

        if stripped.startswith("Device type:"):
            extracted.append(stripped)
            continue

        if stripped.startswith("Running:"):
            extracted.append(stripped)
            continue

        if stripped.startswith("OS details:"):
            extracted.append(stripped)
            continue

        if stripped.startswith("Service Info:"):
            extracted.append(stripped)
            continue

        if stripped.startswith("PORT"):
            capture_ports = True
            extracted.append(stripped)
            continue

        if capture_ports:
            if stripped.startswith("Service detection performed"):
                capture_ports = False
                continue

            if stripped.startswith("Nmap done:"):
                capture_ports = False
                continue

            if stripped.startswith("Not shown:"):
                continue

            if "/tcp" in stripped or "/udp" in stripped:
                extracted.append(stripped)
                continue

    return extracted


def extract_relevant_vuln_lines(block: list[str]) -> list[str]:
    """
    Extract factual lines from an NSE vulnerability block for one host.
    No interpretation is added.
    """
    extracted: list[str] = []

    for raw_line in block[1:]:
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("Host is up"):
            continue

        if stripped.startswith("Not shown:"):
            continue

        if stripped.startswith("PORT"):
            extracted.append(stripped)
            continue

        if "/tcp" in stripped or "/udp" in stripped:
            extracted.append(stripped)
            continue

        if stripped.startswith("|") or stripped.startswith("|_"):
            extracted.append(stripped)
            continue

        if stripped.startswith("Service Info:"):
            extracted.append(stripped)
            continue

    return extracted


def build_summary_text(scan_txt: Path, vuln_txt: Path) -> str:
    """
    Build a factual technical summary using scan.txt and vuln.txt.
    It groups facts by host and includes raw NSE findings where available.
    """
    scan_content = scan_txt.read_text(encoding="utf-8", errors="ignore")
    vuln_content = vuln_txt.read_text(encoding="utf-8", errors="ignore")

    scan_blocks = extract_host_blocks(scan_content)
    vuln_blocks = extract_host_blocks(vuln_content)

    vuln_map: dict[str, list[str]] = {}
    for block in vuln_blocks:
        header = get_host_header(block)
        vuln_map[header] = extract_relevant_vuln_lines(block)

    output_lines: list[str] = []
    output_lines.append("TECHNICAL SUMMARY")
    output_lines.append("=================")

    for scan_block in scan_blocks:
        header = get_host_header(scan_block)
        scan_lines = extract_relevant_scan_lines(scan_block)
        vuln_lines = vuln_map.get(header, [])

        output_lines.append("")
        output_lines.append(header)
        output_lines.append("-" * len(header))

        if scan_lines:
            output_lines.append("NORMAL SCAN")
            output_lines.extend(scan_lines)
        else:
            output_lines.append("NORMAL SCAN")
            output_lines.append("No relevant lines extracted.")

        output_lines.append("")
        output_lines.append("NSE VULNERABILITY OUTPUT")

        if vuln_lines:
            output_lines.extend(vuln_lines)
        else:
            output_lines.append("No NSE output captured for this host.")

    output_lines.append("")
    return "\n".join(output_lines)


def generate_summary(scan_txt: Path, vuln_txt: Path, output_summary: Path) -> None:
    """
    Generate a factual technical summary from Nmap normal output and NSE output.
    """
    summary_text = build_summary_text(scan_txt, vuln_txt)
    output_summary.write_text(summary_text, encoding="utf-8")


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
    generate_summary(normal_output, vuln_output, summary_output)
    logger.info("Summary saved to: %s", summary_output)

    return output_dir
