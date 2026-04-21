import ipaddress
import re
from pathlib import Path

from auditool.exceptions import ValidationError

HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9][-A-Za-z0-9.]{0,251}[A-Za-z0-9]$"
)


def is_valid_target(value: str) -> bool:
    """
    Validate a single target.
    Accepted values:
    - IPv4 or IPv6 address
    - CIDR network
    - Simple hostname / FQDN
    """
    value = value.strip()

    if not value:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass

    if HOSTNAME_REGEX.match(value):
        return True

    return False


def load_and_validate_targets(targets_file: str) -> list[str]:
    """
    Read targets from file, ignore comments/blank lines, and validate entries.
    """
    path = Path(targets_file)

    if not path.exists():
        raise ValidationError(f"Targets file not found: {targets_file}")

    valid_targets: list[str] = []
    invalid_targets: list[str] = []

    with path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if is_valid_target(line):
                valid_targets.append(line)
            else:
                invalid_targets.append(line)

    if invalid_targets:
        invalid_text = ", ".join(invalid_targets)
        raise ValidationError(f"Invalid targets found: {invalid_text}")

    if not valid_targets:
        raise ValidationError("No valid targets found in file")

    return valid_targets
