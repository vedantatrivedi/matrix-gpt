#!/usr/bin/env python3
"""Start the orchestrator server with correct paths"""
import sys
import os
from pathlib import Path

sys.path.insert(0, "/Users/jinit/personal/matrix-gpt-main/.venv/lib/python3.11/site-packages")

# Load .env BEFORE importing anything else
from dotenv import load_dotenv
load_dotenv()

import uvicorn

if __name__ == "__main__":
    # Create logs directory if it doesn't exist
    logs_dir = Path(__file__).parent / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Configure uvicorn to log to file in logs/ directory
    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "fmt": "%(levelprefix)s %(message)s",
                "use_colors": None,
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.FileHandler",
                "filename": str(logs_dir / "orchestrator.log"),
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": "INFO"},
            "uvicorn.error": {"level": "INFO"},
            "uvicorn.access": {"handlers": ["default"], "level": "INFO", "propagate": False},
        },
    }

    uvicorn.run(
        "orchestrator.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_config=log_config
    )
