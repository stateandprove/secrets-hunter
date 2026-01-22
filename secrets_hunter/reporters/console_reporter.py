from typing import List, Optional

from secrets_hunter.models import Finding, DetectionMethod


class ConsoleReporter:
    WIDTH = 88

    @staticmethod
    def _truncate(s: Optional[str], max_len: int) -> str:
        if not s:
            return ""
        s = s.replace("\n", "\\n")
        return s if len(s) <= max_len else s[: max_len - 3] + "..."

    @staticmethod
    def format_report(findings: List[Finding]) -> None:
        if not findings:
            print("No secrets detected!")
            return

        total = len(findings)
        plural = "s" if total != 1 else ""

        sep = "=" * ConsoleReporter.WIDTH
        dash = "-" * ConsoleReporter.WIDTH

        lines = [f"\n⚠️  Found {total} potential secret{plural}:", sep]

        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f.type} found at {f.file}:{f.line}")
            lines.append(f"    Severity:   {f.severity} (confidence: {f.confidence}%)")

            if f.detection_method == DetectionMethod.ENTROPY and getattr(f, "context_var", None):
                lines.append(f"    Variable:   {f.context_var}")

            match_str = ConsoleReporter._truncate(f.match, 120)
            if match_str:
                lines.append(f"    Match:      {match_str}")

            ctx_str = ConsoleReporter._truncate(f.context, 160)
            if ctx_str:
                lines.append(f"    Context:    {ctx_str}")

            lines.append(dash)

        print("\n".join(lines))
