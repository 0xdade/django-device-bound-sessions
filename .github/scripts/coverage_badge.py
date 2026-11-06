"""Write a shields.io endpoint badge from coverage.py's JSON report.

Usage: python coverage_badge.py coverage.json badge.json

The README badge points shields.io at the published badge.json:
https://img.shields.io/endpoint?url=<pages-url>/coverage/badge.json
"""

import json
import math
import sys
from pathlib import Path

# Lowest percentage for each colour, checked in order.
COLORS = [(95, "brightgreen"), (90, "green"), (80, "yellowgreen"), (70, "yellow"), (60, "orange")]


def badge(percent: float) -> dict[str, object]:
    # Round down, so the number shown never claims a colour band it hasn't reached.
    shown = math.floor(percent)
    color = next((c for floor, c in COLORS if shown >= floor), "red")
    return {"schemaVersion": 1, "label": "coverage", "message": f"{shown}%", "color": color}


def main(report: str, output: str) -> None:
    totals = json.loads(Path(report).read_text())["totals"]
    data = badge(totals["percent_covered"])
    Path(output).write_text(json.dumps(data) + "\n")
    print(f"coverage badge: {data['message']} ({data['color']})")


if __name__ == "__main__":
    main(*sys.argv[1:])
