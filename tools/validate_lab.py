""""""Validate synthetic authentication and scheduled-task event sequences."""
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from datetime import datetime
import json
from pathlib import Path
import re

PROJECT = Path(__file__).resolve().parents[1]
BASELINE = PROJECT / "data" / "synthetic_events.jsonl"
BACKGROUND = PROJECT / ".local" / "splunk" / "signalchain_background.jsonl"


def load_jsonl(path: Path) -> list[dict]:
    """Read one JSON object per line without evaluating any event contents."""
    result = []
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"Expected object on line {number}: {path.name}")
            result.append(item)
    return result


def time_of(event: dict) -> datetime:
    time = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    if time.tzinfo is None:
        raise ValueError("Event timestamp has no timezone")
    return time


def review_candidates(events: list[dict], failures_required: int = 5, window_seconds: int = 300) -> list[dict]:
    """Find failed-logon -> success -> encoded-task timing candidates.

    Failures and success must match host, account, and source IP. The task must
    match host/account and appear within the configured time after success.
    """
    failed_by_ip = defaultdict(deque)
    qualifying_logins = defaultdict(deque)
    cases = []
    ordered = sorted(events, key=lambda e: (time_of(e), str(e.get("record_id", ""))))
    for event in ordered:
        event_id = int(event.get("event_id", -1))
        when = time_of(event)
        host = str(event.get("asset_host") or event.get("host") or "").lower()
        account = str(event.get("user") or "").lower()
        ip = str(event.get("source_ip") or "")
        session = (host, account, ip)
        principal = (host, account)
        if event_id == 4625:
            failed_by_ip[session].append(when)
        elif event_id == 4624:
            failures = failed_by_ip[session]
            while failures and (when - failures[0]).total_seconds() > window_seconds:
                failures.popleft()
            if len(failures) >= failures_required:
                qualifying_logins[principal].append((when, ip, len(failures)))
        elif event_id == 4698:
            action = str(event.get("task_action") or event.get("task_content") or "")
            if not re.search(r"powershell.*-encodedcommand", action, re.IGNORECASE | re.DOTALL):
                continue
            sessions = qualifying_logins[principal]
            recent = [(login, source, failed) for login, source, failed in sessions
                      if 0 < (when - login).total_seconds() <= window_seconds]
            if recent:
                login, source, failed = recent[-1]
                cases.append({"host": host, "user": account, "source_ip": source,
                              "failed_logins": failed, "successful_login": login.isoformat(),
                              "task_time": when.isoformat(), "task_name": event.get("task_name", "")})
    return cases


def summarize(events: list[dict]) -> dict:
    return {
        "events": len(events),
        "scheduled_tasks": sum(int(event.get("event_id", -1)) == 4698 for event in events),
        "candidates": review_candidates(events),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the synthetic SignalChain dataset")
    parser.add_argument("--expanded", action="store_true", help="Include the 330 generated background events")
    args = parser.parse_args()
    try:
        events = load_jsonl(BASELINE)
        if args.expanded:
            if not BACKGROUND.exists():
                parser.error("Run python tools/generate_background.py first")
            events.extend(load_jsonl(BACKGROUND))
        result = summarize(events)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Events: {result['events']}")
    print(f"Scheduled tasks: {result['scheduled_tasks']}")
    print(f"Review candidates: {len(result['candidates'])}")
    for case in result["candidates"]:
        print(f"- {case['user']} / {case['host']} / {case['task_name']}")
    print("Note: a temporal candidate is not proof of compromise or session ancestry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
