class AuditoolError(Exception):
    """Base exception for the project."""


class ConfigError(AuditoolError):
    """Raised when configuration is invalid or cannot be loaded."""


class ValidationError(AuditoolError):
    """Raised when user input is invalid."""


class NmapExecutionError(AuditoolError):
    """Raised when Nmap execution fails."""
