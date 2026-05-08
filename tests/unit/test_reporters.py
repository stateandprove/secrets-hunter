import json
import tempfile
import unittest

from pathlib import Path

from secrets_hunter.detection.fragmenter import GenericStringFragment
from secrets_hunter.models import Confidence, DetectionMethod, Finding, Severity
from secrets_hunter.reporters.json_reporter import JSONReporter
from secrets_hunter.reporters.sarif_reporter import SARIFReporter

TOKEN = "ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN"
COMMIT = "4f3c2b1a9e8d7c6b5a4f302918273645abcdef12"
DOMAIN_URL = "https://fvlcn.dev/.env"


def git_finding() -> Finding:
    return Finding(
        title="Hardcoded API key",
        file="repo/.env",
        line=3,
        type="API Key",
        match=TOKEN,
        context=f"GITHUB_TOKEN={TOKEN}",
        severity=Severity.HIGH,
        confidence_reasoning="pattern",
        detection_method=DetectionMethod.PATTERN,
        confidence=Confidence.VERIFIED,
        fragment=GenericStringFragment(TOKEN),
        context_var="GITHUB_TOKEN",
        commit=COMMIT
    )


def domain_finding() -> Finding:
    return Finding(
        title="Hardcoded API key",
        file=DOMAIN_URL,
        line=3,
        type="API Key",
        match=TOKEN,
        context=f"GITHUB_TOKEN={TOKEN}",
        severity=Severity.HIGH,
        confidence_reasoning="pattern",
        detection_method=DetectionMethod.PATTERN,
        confidence=Confidence.VERIFIED,
        fragment=GenericStringFragment(TOKEN),
        context_var="GITHUB_TOKEN",
        vulnerable_url=DOMAIN_URL
    )


class TestReporters(unittest.TestCase):
    def test_json_export_serializes_finding_fields(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "results.json"

            JSONReporter.export([git_finding(), domain_finding()], str(output))

            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(data, [
            {
                "title": "Hardcoded API key",
                "file": "repo/.env",
                "line": 3,
                "type": "API Key",
                "match": TOKEN,
                "context": f"GITHUB_TOKEN={TOKEN}",
                "severity": "HIGH",
                "confidence_reasoning": "pattern",
                "detection_method": "pattern",
                "confidence": 100,
                "context_var": "GITHUB_TOKEN",
                "commit": COMMIT,
                "vulnerable_url": None
            },
            {
                "title": "Hardcoded API key",
                "file": DOMAIN_URL,
                "line": 3,
                "type": "API Key",
                "match": TOKEN,
                "context": f"GITHUB_TOKEN={TOKEN}",
                "severity": "HIGH",
                "confidence_reasoning": "pattern",
                "detection_method": "pattern",
                "confidence": 100,
                "context_var": "GITHUB_TOKEN",
                "commit": None,
                "vulnerable_url": DOMAIN_URL
            },
        ])

    def test_sarif_export_serializes_finding_fields(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "results.sarif"

            SARIFReporter.export([git_finding(), domain_finding()], str(output))

            data = json.loads(output.read_text(encoding="utf-8"))

        results = data["runs"][0]["results"]
        self.assertEqual(results, [
            {
                "ruleId": "API Key",
                "message": {
                    "text": "API Key found in repo/.env"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "repo/.env"
                        },
                        "region": {
                            "startLine": 3,
                            "snippet": {
                                "text": f"GITHUB_TOKEN={TOKEN}"
                            }
                        }
                    }
                }],
                "properties": {
                    "title": "Hardcoded API key",
                    "match": TOKEN,
                    "detection_method": "pattern",
                    "confidence": 100,
                    "context_var": "GITHUB_TOKEN",
                    "commit": COMMIT,
                    "vulnerable_url": None,
                    "severity": "HIGH",
                    "confidence_reasoning": "pattern",
                }
            },
            {
                "ruleId": "API Key",
                "message": {
                    "text": f"API Key found in {DOMAIN_URL}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": DOMAIN_URL
                        },
                        "region": {
                            "startLine": 3,
                            "snippet": {
                                "text": f"GITHUB_TOKEN={TOKEN}"
                            }
                        }
                    }
                }],
                "properties": {
                    "title": "Hardcoded API key",
                    "match": TOKEN,
                    "detection_method": "pattern",
                    "confidence": 100,
                    "context_var": "GITHUB_TOKEN",
                    "commit": None,
                    "vulnerable_url": DOMAIN_URL,
                    "severity": "HIGH",
                    "confidence_reasoning": "pattern",
                }
            },
        ])
