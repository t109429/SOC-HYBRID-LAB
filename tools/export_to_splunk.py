"""Export synthetic Windows and Sysmon events to JSONL for Splunk ingestion.

The output is saved locally for manual upload to Splunk.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def load_events(path: Path) -> list[dict]:
    """"""Load synthetic JSONL events and assign evidence references.".
    """
    events: list[dict] = []
    with path.open('r', encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError(f'Invalid event at line {line_number}')
            for field in ('host', 'event_id', 'record_id', 'channel', 'timestamp'):
                if field not in event:
                    raise ValueError(f'Missing {field} at line {line_number}')
            event['_ref'] = f"fixture:{str(event['host']).lower()}:{event['channel']}:{event['event_id']}:{event['record_id']}"
            events.append(event)
    return events

FIXTURE = ROOT / 'data' / 'synthetic_events.jsonl'
DEFAULT_OUTPUT = ROOT / '.local' / 'splunk' / 'signalchain_synthetic.jsonl'
# Whitelist only fields that have meaning in the lab. Don't forward
# arbitrary input fields (such as notes, secrets or provider metadata).
FIELDS = (
    'timestamp', 'host', 'channel', 'event_id', 'record_id',
    'user', 'user_domain', 'source_ip', 'logon_type', 'status',
    'image', 'parent_image', 'command_line', 'process_guid',
    'initiated', 'destination_ip', 'destination_port',
    'task_name', 'task_action', 'task_content',
)


def convert(events: list[dict]) -> list[dict]:
    """Produce one JSON object per source record with stable evidence references."""
    result = []
    for event in events:
        row = {key: event[key] for key in FIELDS if key in event}
        row.update(lab_id='signalchain', dataset_type='synthetic',
                   asset_host=event['host'], evidence_ref=event['_ref'])
        result.append(row)
    return result


def write_jsonl(rows: list[dict], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('w', encoding='utf-8', newline='\n') as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Export the bundled synthetic fixture for a Splunk file upload.')
    p.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = p.parse_args(argv)
    try:
        source = load_events(FIXTURE)
        rows = convert(source)
        if len({row['evidence_ref'] for row in rows}) != len(rows):
            raise ValueError('Duplicate evidence references')
        dest = args.output.resolve()
        if not dest.is_relative_to(ROOT.resolve()):
            raise ValueError('Output must remain inside the SignalChain project folder')
        if not dest.is_relative_to((ROOT / '.local').resolve()):
            raise ValueError('Output must be inside .local/ (not tracked by Git)')
        write_jsonl(rows, dest)
        print(f'Exported {len(rows)} synthetic events for Splunk')
        print(f'Path: {dest}')
        print('No data was uploaded. Upload this file manually if you choose to use Splunk.')
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f'Export failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
