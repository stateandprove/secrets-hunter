from pathlib import Path

from secrets_hunter.models import Confidence, DetectionMethod, Finding, Severity
from secrets_hunter.config import STRIP
from secrets_hunter.models.config import RuntimeConfig

from secrets_hunter.detection.detectors.entropy_detector import EntropyDetector
from secrets_hunter.detection.detectors.pattern_detector import PatternDetector
from secrets_hunter.detection.fragmenter.fragmenter import SourceFragmenter
from secrets_hunter.detection.fragmenter.models import SourceFragment
from secrets_hunter.detection.false_positive_validator import FalsePositiveFindingsValidator


class DetectionEngine:
    def __init__(
        self,
        runtime_cfg: RuntimeConfig,
        pattern_detector: PatternDetector,
        entropy_detector: EntropyDetector,
        source_fragmenter: SourceFragmenter,
        false_positive_validator: FalsePositiveFindingsValidator,
    ):
        self.runtime_cfg = runtime_cfg
        self.pattern_detector = pattern_detector
        self.entropy_detector = entropy_detector
        self.source_fragmenter = source_fragmenter
        self.false_positive_validator = false_positive_validator

    def _is_secret_var(self, v: str) -> tuple[bool, str]:
        v = v.lower()

        for k in self.runtime_cfg.secret_keywords:
            if k in v:
                return True, k

        return False, ""

    def scan_fragment(self, source_fragment: SourceFragment, filepath: Path | str) -> list[Finding]:
        fragment_line = source_fragment.start_line
        fragment_content = source_fragment.content

        # Step 1: Extract all strings from a source fragment
        all_fragments = self.source_fragmenter.extract(source_fragment)

        if not all_fragments:
            return []

        # Step 2: Find high entropy strings
        entropy_findings = self.entropy_detector.detect(
            fragment_content, fragment_line, str(filepath), all_fragments
        )

        # Step 3: Find pattern matching strings
        pattern_findings = self.pattern_detector.detect(
            fragment_content, fragment_line, str(filepath), all_fragments
        )

        # Step 3.5: prioritize pattern findings (dedupe by match)
        pattern_matches = {f.match for f in pattern_findings if f.match}
        all_fragment_findings = list(pattern_findings)

        for entropy_finding in entropy_findings:
            if entropy_finding.match and entropy_finding.match not in pattern_matches:
                all_fragment_findings.append(entropy_finding)

        if not all_fragment_findings:
            return []

        # Step 4: Check and process the assignment context
        assignment_context = self.source_fragmenter.assignment_map(fragment_content)
        return self._process_assignment_context(all_fragment_findings, assignment_context)

    def _process_assignment_context(self, findings: list[Finding], ctx: dict) -> list[Finding]:
        transformed_findings: list[Finding] = []

        for finding in findings:
            finding_value_rejected, rejected_by = (
                self.false_positive_validator.check_rejection_for_finding_value(finding)
            )
            match = finding.match
            norm_match = match.strip().strip(STRIP)
            vars_ = ctx.get(match) or ctx.get(norm_match)

            if not vars_:
                if finding_value_rejected:
                    finding = finding.reject(f"{rejected_by.name} {rejected_by.category} in value")

                transformed_findings.append(finding)
                continue

            # can be multiple keys for a single secret,
            # pick the best var for display / single field
            vars_ordered = sorted(vars_)
            best = next((v for v in vars_ordered if self._is_secret_var(v)[0]), vars_ordered[0])

            reasoning = finding.confidence_reasoning
            severity = finding.severity
            confidence = finding.confidence

            if finding.detection_method == DetectionMethod.ENTROPY:
                reasoning = "High Entropy with assignment context"
                severity = Severity.MEDIUM
                confidence = Confidence.HIGH_ENTROPY_WITH_ASSIGNMENT

            finding = finding.with_context(
                var=best,
                severity=severity,
                confidence=confidence,
                reasoning=reasoning
            )

            kw_rejected, kw_rejected_by = self.false_positive_validator.check_rejection_for_keywords(vars_ordered)

            if kw_rejected:
                finding = finding.reject(kw_rejected_by + " in keyword/variable")
                transformed_findings.append(finding)
                continue

            is_secret, kw = self._is_secret_var(best)

            if finding_value_rejected:
                secret_hash = is_secret and rejected_by.category == "hash"

                if not secret_hash:
                    reasoning = f"{rejected_by.name} {rejected_by.category} in value"
                    transformed_findings.append(finding.reject(reasoning))
                    continue

            if is_secret:
                if finding.detection_method == DetectionMethod.ENTROPY:
                    reasoning = f"High Entropy in context of secret key/variable assignment - {kw}"
                    severity = Severity.CRITICAL
                    confidence = Confidence.VERIFIED

                finding = finding.with_context(
                    var=best,
                    severity=severity,
                    confidence=confidence,
                    reasoning=reasoning
                )

                transformed_findings.append(finding)
                continue

            transformed_findings.append(finding)

        return transformed_findings
