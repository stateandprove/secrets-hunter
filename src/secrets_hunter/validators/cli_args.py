import os

from pathlib import Path

from secrets_hunter.config import settings


class CLIArgsValidator:
    def __init__(self, parser):
        self.parser = parser

    def validate_common_args(self, args):
        self.validate_config_files(args.config)

    def validate_scan_args(self, args):
        self.validate_entropy(args.hex_entropy, "hex-entropy", settings.HEX_ENTROPY_MAX)
        self.validate_entropy(args.b64_entropy, "b64-entropy", settings.B64_ENTROPY_MAX)

        self.validate_min_length(args.min_length)
        self.validate_workers(args.workers)
        self.validate_min_confidence(args.min_confidence)

        self.validate_output_file(args.json_output, "json")
        self.validate_output_file(args.sarif_output, "sarif")

    def validate_entropy(self, value, name, v_max):
        if not 0.0 <= value <= v_max:
            self.parser.error(f"--{name} must be between 0.0 and {v_max}")

    def validate_min_length(self, value):
        if value <= 0:
            self.parser.error("--min-length must be > 0")

    def validate_min_confidence(self, value):
        if value < 0 or value > 100:
            self.parser.error("--min-confidence must be between 0 and 100")

    def validate_config_files(self, paths):
        for p in paths or []:
            path = Path(p).expanduser().resolve()
            if not path.exists() or not path.is_file():
                self.parser.error(f"--config file does not exist: {path}")
            if path.suffix.lower() != ".toml":
                self.parser.error(f"--config must be a .toml file: {path}")

    def validate_workers(self, value):
        max_workers = (os.cpu_count() or 1) * settings.MAX_WORKERS_MULTIPLIER

        if value <= 0:
            self.parser.error("--workers must be > 0")
        if value > max_workers:
            self.parser.error(f"--workers cannot exceed {max_workers}")

    def validate_output_file(self, path, flag_name):
        if not path:
            return

        parent = Path(path).parent

        if not parent.exists() or not parent.is_dir():
            self.parser.error(f"--{flag_name} parent dir does not exist: {parent}")
