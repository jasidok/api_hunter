"""
Logging configuration for API Hunter with rich formatting.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install

# Install rich traceback handler for better error formatting
install(show_locals=True)


class APIHunterLogger:
    """Custom logger class for API Hunter."""

    def __init__(self, name: str = "api_hunter"):
        self.name = name
        self.logger = logging.getLogger(name)
        self._console = Console()
        self._configured = False

    def configure(
            self,
            level: str = "INFO",
            log_file: Optional[Path] = None,
            rich_console: bool = True,
            show_time: bool = True,
            show_path: bool = False
    ):
        """Configure the logger with handlers and formatting."""
        if self._configured:
            return

        # Clear any existing handlers
        self.logger.handlers.clear()

        # Set log level
        self.logger.setLevel(getattr(logging, level.upper()))

        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        simple_formatter = logging.Formatter(
            '%(levelname)s - %(message)s'
        )

        # Add rich console handler
        if rich_console:
            rich_handler = RichHandler(
                console=self._console,
                show_time=show_time,
                show_path=show_path,
                rich_tracebacks=True,
                tracebacks_show_locals=True
            )
            rich_handler.setFormatter(simple_formatter)
            self.logger.addHandler(rich_handler)
        else:
            # Standard console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(simple_formatter)
            self.logger.addHandler(console_handler)

        # Add file handler if log file specified
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(detailed_formatter)
            self.logger.addHandler(file_handler)

        self._configured = True

    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        if not self._configured:
            self.configure()
        return self.logger


# Global logger instance
_global_logger = APIHunterLogger()


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Optional logger name. If None, returns the global logger.
        
    Returns:
        Configured logger instance.
    """
    if name:
        return logging.getLogger(name)
    return _global_logger.get_logger()


def configure_logging(
        level: str = "INFO",
        log_file: Optional[Path] = None,
        rich_console: bool = True,
        show_time: bool = True,
        show_path: bool = False
):
    """
    Configure the global logging system.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        rich_console: Use rich console formatting
        show_time: Show timestamps in console output
        show_path: Show file paths in console output
    """
    _global_logger.configure(
        level=level,
        log_file=log_file,
        rich_console=rich_console,
        show_time=show_time,
        show_path=show_path
    )


def get_scan_logger(scan_id: str) -> logging.Logger:
    """
    Get a logger for a specific scan.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Logger instance specific to the scan
    """
    return logging.getLogger(f"api_hunter.scan.{scan_id}")


def get_component_logger(component: str) -> logging.Logger:
    """
    Get a logger for a specific component.
    
    Args:
        component: Component name (e.g., 'discovery', 'fuzzing', 'auth')
        
    Returns:
        Logger instance specific to the component
    """
    return logging.getLogger(f"api_hunter.{component}")


class LogContext:
    """Context manager for temporary logging configuration."""

    def __init__(self, level: str):
        self.level = level
        self.original_level = None

    def __enter__(self):
        logger = get_logger()
        self.original_level = logger.level
        logger.setLevel(getattr(logging, self.level.upper()))
        return logger

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger = get_logger()
        logger.setLevel(self.original_level)
