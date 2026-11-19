"""Generate additional synthetic Windows events for the SignalChain Splunk lab.

Run from the project with: py -3 tools/generate_background.py

This script only writes a new JSONL file inside .local/splunk. It does not
modify the original 44 events, connect to Splunk, or execute any commands
contained in the simulated logs.
"""

from __future__ import annotations

import base64
import json
import random
import re
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT / ".local" / "splunk" / "signalchain_background.jsonl"
START = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc)
RANDOM = random.Random(20261017)
EVENTS = []
RECORD_ID = 20000

HOST_USERS = {
    "WS-FIN-07": ["m.davis", "r.lee", "s.patel", "admin"],
    "WS-HR-02": ["k.jones", "a.brown", "l.garcia", "admin"],
    "WS-OPS-03": ["t.chen", "n.wilson", "admin"],
}

APPLICATIONS = [
    (r"C:\Windows\explorer.exe", ""),
    (r"C:\Windows\System32\notepad.exe", " meeting_notes.txt"),
    (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", " https://intranet.example.test"),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", " monthly_report.xlsx"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", " -NoProfile -Command Get-Service"),
    (r"C:\Windows\System32\cmd.exe", " /c whoami"),
]

TASKS = [
    (r"\Company\Inventory", r"C:\Program Files\Company\Inventory\inventory.exe"),
    (r"\Company\Backup", r"C:\Program Files\Company\Backup\backup.exe"),
    (r"\Company\Updates", r"C:\Program Files\Company\Updater\update.exe"),
]


def when(minutes: float) -> datetime:
    """Return a time on the same synthetic workday."""
    return START + timedelta(minutes=minutes)


def add_event(time: datetime, host: str, user: str, event_id: int, **details: object) -> None:
    """Add one JSON record with unique IDs and consistent lab fields."""
    global RECORD_ID
    RECORD_ID += 1
    channel = "sysmon" if event_id in (1, 3) else "security"
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host,
        "asset_host": host.lower(),
        "channel": channel,
        "event_id": event_id,
        "record_id": RECORD_ID,
        "user": user,
        "lab_id": "signalchain",
        "dataset_type": "synthetic",
        "evidence_ref": f"background:{host.lower()}:{channel}:{event_id}:{RECORD_ID}",
    }
    record.update(details)
    EVENTS.append(record)


def add_login(time: datetime, host: str, user: str, ip: str, successful: bool) -> None:
    add_event(
        time, host, user, 4624 if successful else 4625,
        source_ip=ip, logon_type=10 if ip.startswith(("198.51.", "203.0.")) else 2,
        status="0x0" if successful else "0xC000006A",
    )


def add_task(time: datetime, host: str, user: str, encoded: bool) -> None:
    if encoded:
        name = r"\Company\MaintenanceTelemetry"
        executable = "powershell.exe"
        encoded_command = base64.b64encode("Get-Service".encode("utf-16le")).decode("ascii")
        arguments = f"-NoProfile -EncodedCommand {encoded_command}"
    else:
        name, executable = RANDOM.choice(TASKS)
        arguments = ""
    action = f"{executable} {arguments}".strip()
    xml = (f"<Task><Actions><Exec><Command>{executable}</Command>"
           f"<Arguments>{arguments}</Arguments></Exec></Actions></Task>")
    add_event(time, host, user, 4698, task_name=name, task_action=action, task_content=xml)


def add_failures(time: datetime, host: str, user: str, ip: str, count: int) -> None:
    for number in range(count):
        add_login(time + timedelta(seconds=number * 30), host, user, ip, successful=False)


def add_regular_activity() -> None:
    """Create varied workday activity without a perfect one-minute pattern."""
    for _ in range(250):
        host = RANDOM.choice(list(HOST_USERS))
        user = RANDOM.choice(HOST_USERS[host])
        time = START + timedelta(seconds=RANDOM.randrange(120, 7 * 3600))
        ip = f"10.20.30.{20 + list(HOST_USERS[host]).index(user) + list(HOST_USERS).index(host) * 20}"
        event_type = RANDOM.choices([4624, 4625, 4688, 4698], weights=[35, 12, 49, 4])[0]
        if event_type in (4624, 4625):
            add_login(time, host, user, ip, successful=event_type == 4624)
        elif event_type == 4688:
            image, arguments = RANDOM.choice(APPLICATIONS)
            add_event(time, host, user, 4688, image=image, command_line=image + arguments)
        else:
            add_task(time, host, user, encoded=RANDOM.random() < 0.15)

    # Every generated Sysmon network event has a matching process event.
    for number in range(12):
        host = RANDOM.choice(list(HOST_USERS))
        user = RANDOM.choice(HOST_USERS[host])
        time = START + timedelta(seconds=RANDOM.randrange(180, 6 * 3600))
        image, arguments = RANDOM.choice(APPLICATIONS)
        process_guid = "{" + str(uuid.uuid5(uuid.NAMESPACE_DNS, f"signalchain-{number}")).upper() + "}"
        add_event(time, host, user, 1, image=image,
                  command_line=image + arguments, process_guid=process_guid,
                  parent_image=r"C:\Windows\explorer.exe")
        add_event(time + timedelta(seconds=RANDOM.randrange(3, 30)), host, user, 3,
                  image=image, process_guid=process_guid, initiated=True,
                  destination_ip=RANDOM.choice(["10.20.30.1", "192.0.2.60", "203.0.113.60"]),
                  destination_port=RANDOM.choice([53, 443, 445]))


def add_validation_scenarios() -> None:
    """Add cases that challenge timing, IP matching, and task interpretation."""
    # One additional complete suspicious chain; should be REVIEW.
    add_failures(when(25), "WS-OPS-09", "t.chen", "198.51.100.80", 6)
    add_login(when(28), "WS-OPS-09", "t.chen", "198.51.100.80", True)
    process = "{" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "signalchain-second-chain")).upper() + "}"
    image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    add_event(when(29), "WS-OPS-09", "t.chen", 1, image=image,
              command_line=image + " -NoProfile -Command Get-Service", process_guid=process,
              parent_image=r"C:\Windows\explorer.exe")
    add_event(when(29) + timedelta(seconds=8), "WS-OPS-09", "t.chen", 3,
              image=image, process_guid=process, initiated=True,
              destination_ip="203.0.113.90", destination_port=443)
    add_task(when(30), "WS-OPS-09", "t.chen", encoded=True)

    # Same account, but success came from a different IP. NOT FLAGGED.
    add_failures(when(60), "WS-QA-01", "p.ward", "198.51.100.55", 6)
    add_login(when(63), "WS-QA-01", "p.ward", "10.20.30.90", True)
    add_task(when(65), "WS-QA-01", "p.ward", encoded=True)

    # Success was too long after the failed logins. NOT FLAGGED.
    add_failures(when(120), "WS-QA-01", "e.turner", "198.51.100.56", 6)
    add_login(when(132), "WS-QA-01", "e.turner", "198.51.100.56", True)
    add_task(when(134), "WS-QA-01", "e.turner", encoded=True)

    # Authentication pattern exists, but the scheduled task is ordinary.
    add_failures(when(180), "WS-QA-01", "c.morris", "198.51.100.57", 6)
    add_login(when(183), "WS-QA-01", "c.morris", "198.51.100.57", True)
    add_task(when(185), "WS-QA-01", "c.morris", encoded=False)

    # Encoded task was created more than five minutes after the login.
    add_failures(when(240), "WS-QA-01", "f.hughes", "198.51.100.58", 6)
    add_login(when(243), "WS-QA-01", "f.hughes", "198.51.100.58", True)
    add_task(when(250), "WS-QA-01", "f.hughes", encoded=True)

    # Only four failed logins. NOT FLAGGED.
    add_failures(when(300), "WS-QA-01", "g.meyer", "198.51.100.59", 4)
    add_login(when(302), "WS-QA-01", "g.meyer", "198.51.100.59", True)
    add_task(when(303), "WS-QA-01", "g.meyer", encoded=True)

    # Password-spray-like activity across accounts, not one account.
    for number, name in enumerate(["h.ross", "j.nguyen", "b.hall", "d.adams", "m.green", "v.khan"]):
        add_login(when(360) + timedelta(seconds=number * 20), "WS-QA-02", name,
                  "203.0.113.70", False)
    add_login(when(363), "WS-QA-02", "h.ross", "203.0.113.70", True)
    add_task(when(364), "WS-QA-02", "h.ross", encoded=True)


def detect_chains(events: list[dict]) -> list[tuple[str, str]]:
    """Independently check the intended rule against the generated data."""
    failures = defaultdict(deque)
    qualifying_logins = defaultdict(deque)
    matches = []
    for event in sorted(events, key=lambda row: row["timestamp"]):
        time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        account = (event["asset_host"], event["user"])
        address = (event["asset_host"], event["user"], event.get("source_ip", ""))
        if event["event_id"] == 4625:
            failures[address].append(time)
        elif event["event_id"] == 4624:
            recent = failures[address]
            while recent and (time - recent[0]).total_seconds() > 300:
                recent.popleft()
            if len(recent) >= 5:
                qualifying_logins[account].append(time)
        elif event["event_id"] == 4698:
            action = event.get("task_action", "")
            if re.search(r"powershell.*-encodedcommand", action, re.IGNORECASE):
                recent = qualifying_logins[account]
                if any(0 < (time - success).total_seconds() <= 300 for success in recent):
                    matches.append(account)
    return matches


def main() -> None:
    add_regular_activity()
    add_validation_scenarios()
    EVENTS.sort(key=lambda row: (row["timestamp"], row["record_id"]))
    refs = [row["evidence_ref"] for row in EVENTS]
    if len(refs) != len(set(refs)):
        raise ValueError("Duplicate evidence references")
    matches = detect_chains(EVENTS)
    if matches != [("ws-ops-09", "t.chen")]:
        raise ValueError(f"Unexpected detection results: {matches}")
    if OUTPUT.exists():
        raise FileExistsError(f"Output already exists; no file was changed: {OUTPUT}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as stream:
        for row in EVENTS:
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")
    print(f"Generated {len(EVENTS)} new, synthetic events")
    print("Validated: 1 new complete detection chain; 6 negative test scenarios")
    print(f"Saved: {OUTPUT}")
    print("No original files were changed; nothing was uploaded to Splunk")


if __name__ == "__main__":
    main()
