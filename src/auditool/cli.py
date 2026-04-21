import argparse
import sys
from pathlib import Path

from auditool.config import load_config
from auditool.exceptions import AuditoolError
from auditool.logger import setup_logger
from auditool.orchestrator import run_scan_workflow

DEFAULT_CONFIG_PATH = "config/default.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditool",
        description="Authorized internal network audit automation toolkit"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a basic authorized scan")
    scan_parser.add_argument(
        "--targets",
        required=True,
        help="Path to targets file"
    )
    scan_parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to YAML config file (default: {DEFAULT_CONFIG_PATH})"
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        output_base_dir = config.get("output_dir", "output")
        Path(output_base_dir).mkdir(parents=True, exist_ok=True)

        bootstrap_log = Path(output_base_dir) / "bootstrap.log"
        logger = setup_logger(
            log_level=config.get("log_level", "INFO"),
            log_file=bootstrap_log
        )

        if args.command == "scan":
            output_dir = run_scan_workflow(
                targets_file=args.targets,
                config_path=args.config,
                logger=logger
            )
            print(f"[OK] Scan completed. Output directory: {output_dir}")

    except AuditoolError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("[ERROR] Execution interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"[ERROR] Unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)
