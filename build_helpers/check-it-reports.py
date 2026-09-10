#!/usr/bin/env python3
"""Guards against an integration test run that passed without running anything.

Failsafe reports success when its provider discovers no tests at all, which is
exactly what happened while the JUnit 4 provider was being auto-detected: a green
build that exercised nothing. This reads the reports back and fails if no
integration test actually executed.

It also writes the skipped tests and their reasons to the job summary, so
disabled tests stay visible instead of quietly accumulating.
"""
import glob
import os
import sys

# The only input is the failsafe report the same job just produced, so the
# stdlib parser is fine here.
import xml.etree.ElementTree as ET

REPORT_GLOB = os.path.join("target", "failsafe-reports", "TEST-*.xml")


def main() -> int:
    reports = sorted(glob.glob(REPORT_GLOB))
    if not reports:
        print("No failsafe reports found at " + REPORT_GLOB, file=sys.stderr)
        return 1

    total = 0
    skipped = 0
    skipped_details = []

    for report in reports:
        root = ET.parse(report).getroot()
        total += int(root.get("tests", "0"))
        skipped += int(root.get("skipped", "0"))
        for case in root.iter("testcase"):
            marker = case.find("skipped")
            if marker is None:
                continue
            name = "{}.{}".format(case.get("classname", "?"), case.get("name", "?"))
            skipped_details.append((name, marker.get("message", "").strip()))

    executed = total - skipped
    print("integration tests: {} executed, {} skipped, across {} classes".format(executed, skipped, len(reports)))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path and skipped_details:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write("\n### Skipped integration tests\n\n")
            for name, message in sorted(skipped_details):
                summary.write("- `{}` - {}\n".format(name, message or "no reason given"))

    if executed <= 0:
        print("No integration test actually executed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
