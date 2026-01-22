import sys
import os
import argparse
import logging

from pathlib import Path

from secrets_hunter import __version__
from secrets_hunter.scanner import SecretsHunter
from secrets_hunter.config import settings, CliArgs, load_runtime_config
from secrets_hunter.reporters.console_reporter import ConsoleReporter
from secrets_hunter.reporters.json_reporter import JSONReporter
from secrets_hunter.reporters.sarif_reporter import SARIFReporter


logo_ascii = rf"""
     ________ ___      ___ ___       ________  ________      
    |\  _____\\  \    /  /|\  \     |\   ____\|\   ___  \    
    \ \  \__/\ \  \  /  / | \  \    \ \  \___|\ \  \\ \  \   
     \ \   __\\ \  \/  / / \ \  \    \ \  \    \ \  \\ \  \  
      \ \  \_| \ \    / /   \ \  \____\ \  \____\ \  \\ \  \ 
       \ \__\   \ \__/ /     \ \_______\ \_______\ \__\\ \__\
        \|__|    \|__|/       \|_______|\|_______|\|__| \|__|
                    +=======================+                
                    | Secrets Hunter v{__version__} |        
                    +=======================+                
"""


class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Detect secrets and sensitive information in your codebase",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.add_args()

    def add_args(self):
        p = self.parser

        p.add_argument(
            "target",
            nargs="?",
            default=".",
            help="File or directory to scan (default: current directory)",
        )

        p.add_argument(
            "--reveal-findings",
            action="store_true",
            default=CliArgs.REVEAL_FINDINGS,
            help=f"Reveal findings in output (default: {CliArgs.REVEAL_FINDINGS})"
        )

        p.add_argument(
            "--config",
            action="append",
            default=None,
            metavar="FILE",
            help="Path to TOML overlay config. Can be used multiple times."
        )

        p.add_argument(
            '--json',
            dest='json_output',
            metavar='FILE',
            help='Export results to JSON file'
        )

        p.add_argument(
            '--sarif',
            dest='sarif_output',
            metavar='FILE',
            help='Export results to SARIF file'
        )

        p.add_argument(
            '--hex-entropy',
            type=float,
            default=CliArgs.HEX_ENTROPY_THRESHOLD,
            help=f'Hex entropy threshold (default: {CliArgs.HEX_ENTROPY_THRESHOLD})'
        )

        p.add_argument(
            '--b64-entropy',
            type=float,
            default=CliArgs.B64_ENTROPY_THRESHOLD,
            help=f'Base64 entropy threshold (default: {CliArgs.B64_ENTROPY_THRESHOLD})'
        )

        p.add_argument(
            '--min-length',
            type=int,
            default=CliArgs.MIN_STRING_LENGTH,
            help=f'Minimum string length (default: {CliArgs.MIN_STRING_LENGTH})'
        )

        p.add_argument(
            '--workers',
            type=int,
            default=CliArgs.MAX_WORKERS,
            help=f'Number of parallel workers (default: {CliArgs.MAX_WORKERS})'
        )

        p.add_argument(
            '--log-level',
            type=str,
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default=CliArgs.LOG_LEVEL,
            help=f'Log level (default: {CliArgs.LOG_LEVEL})'
        )

        p.add_argument(
            '--min-confidence',
            type=int,
            default=CliArgs.MIN_CONFIDENCE,
            help=f'Minimum confidence (default: {CliArgs.MIN_CONFIDENCE})'
        )

    def parse(self):
        args = self.parser.parse_args()

        validators = [
            (self.validate_entropy, [args.hex_entropy, "hex-entropy", settings.HEX_ENTROPY_MAX]),
            (self.validate_entropy, [args.b64_entropy, "b64-entropy", settings.B64_ENTROPY_MAX]),
            (self.validate_min_length, [args.min_length]),
            (self.validate_config_files, [args.config]),
            (self.validate_min_confidence, [args.min_confidence]),
            (self.validate_output_file, [args.json_output, "json"]),
            (self.validate_output_file, [args.sarif_output, "sarif"])
        ]

        for fn, params in validators:
            fn(*params)

        return args

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


def main():
    print(logo_ascii)

    cli = CLI()
    args = cli.parse()

    cli_args = CliArgs()
    cli_args.HEX_ENTROPY_THRESHOLD = args.hex_entropy
    cli_args.B64_ENTROPY_THRESHOLD = args.b64_entropy
    cli_args.MIN_STRING_LENGTH = args.min_length
    cli_args.MAX_WORKERS = args.workers
    cli_args.MIN_CONFIDENCE = args.min_confidence
    cli_args.REVEAL_FINDINGS = args.reveal_findings

    runtime_cfg = load_runtime_config(args.config)

    logging.basicConfig(
        level=args.log_level,
        format='%(asctime)s | %(levelname)s | %(module)s.%(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    scanner = SecretsHunter(runtime_cfg, cli_args)
    findings, success = scanner.scan(args.target)

    if not success:
        sys.exit(1)

    if args.json_output:
        JSONReporter.export(findings, args.json_output)
    elif args.sarif_output:
        SARIFReporter.export(findings, args.sarif_output)
    else:
        ConsoleReporter.format_report(findings)

    sys.exit(0)


if __name__ == '__main__':
    main()
