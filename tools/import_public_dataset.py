"""Convert a selected public Mordor/Security-Datasets JSONL archive to SignalChain JSONL.

Supports .zip, .tar.gz, .jsonl and newline-delimited .json; processes archives
without extracting files. This is a targeted schema adapter, not a universal
Windows log reader. No third-party dependencies or downloads are performed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import io
import json
from pathlib import Path
import sys
import tarfile
import zipfile

# Keep individual inputs reasonable for 8 GB machines.
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 1 * 1024 * 1024
SUPPORTED_EIDS = {1, 3, 4624, 4625, 4688, 4698}


def get(obj: dict, *names: str):
    """Case-insensitive lookup for a few common event field names."""
    look = {str(k).lower(): v for k, v in obj.items()}
    for key in names:
        val = look.get(key.lower())
        if val is not None and val != "":
            return val
    return None


def record_to_signalchain(raw: dict, fallback_record_id: str) -> dict | None:
    winlog = raw.get('winlog') if isinstance(raw.get('winlog'), dict) else {}
    event_obj = raw.get('event') if isinstance(raw.get('event'), dict) else {}
    host_obj = raw.get('host') if isinstance(raw.get('host'), dict) else {}
    fields = winlog.get('event_data') or raw.get('event_data') or {}
    if not isinstance(fields, dict):
        fields = {}
    # Mordor/NXLog (flat), Winlogbeat (nested), and Elastic ECS formats.
    eid_raw = get(winlog, 'event_id') or get(raw, 'EventID', 'event_id') or get(event_obj, 'code')
    try:
        eid = int(eid_raw)
    except (TypeError, ValueError):
        return None
    if eid not in SUPPORTED_EIDS:
        return None

    channel = str(get(winlog, 'channel', 'log_name') or get(raw, 'Channel', 'log_name') or '')
    if eid in (1, 3) and channel and 'sysmon' not in channel.lower():
        # Event ID 1 can also belong to other providers.
        return None
    if not channel:
        channel = 'Microsoft-Windows-Sysmon/Operational' if eid in (1, 3) else 'Security'

    ts = get(raw, '@timestamp', 'timestamp', 'TimeCreated') or get(event_obj, 'created')
    host = (get(winlog, 'computer_name') or get(raw, 'Hostname', 'ComputerName')
            or get(host_obj, 'name') or (raw.get('host') if isinstance(raw.get('host'), str) else None))
    if not ts or not host:
        return None

    # Both flat and nested forms may contain the Windows EventData fields.
    merged = {**raw, **fields}
    if eid in (4624, 4625):
        user = get(merged, 'TargetUserName', 'user') or ''
        domain = get(merged, 'TargetDomainName', 'user_domain') or ''
    elif eid in (4688, 4698):
        user = get(merged, 'TargetUserName', 'SubjectUserName', 'User') or ''
        domain = get(merged, 'TargetDomainName', 'SubjectDomainName') or ''
    else:
        user = get(merged, 'User') or ''
        domain = ''

    rid = (get(winlog, 'record_id', 'record_number')
           or get(raw, 'EventRecordID', 'RecordNumber', 'RecordId', 'record_id')
           or fallback_record_id)
    return {
        'timestamp': str(ts),
        'event_id': eid,
        'channel': channel,
        'record_id': str(rid),
        'host': str(host),
        'user': str(user),
        'user_domain': str(domain),
        'source_ip': str(get(merged, 'IpAddress', 'SourceIp', 'source_ip') or '') if eid in (4624,4625) else '',
        'logon_type': str(get(merged, 'LogonType', 'logon_type') or ''),
        'image': str(get(merged, 'NewProcessName', 'Image', 'image') or ''),
        'command_line': str(get(merged, 'CommandLine', 'command_line') or ''),
        'process_guid': str(get(merged, 'ProcessGuid', 'process_guid') or ''),
        'destination_ip': str(get(merged, 'DestinationIp', 'destination_ip') or ''),
        'destination_port': str(get(merged, 'DestinationPort', 'destination_port') or ''),
        'initiated': str(get(merged, 'Initiated', 'initiated') or ''),
        'task_name': str(get(merged, 'TaskName', 'task_name') or ''),
        'task_content': str(get(merged, 'TaskContent', 'task_content') or ''),
    }


def is_json_data_file(name: str) -> bool:
    name = name.lower()
    return name.endswith(('.json', '.jsonl', '.ndjson', '.log'))


@contextmanager
def open_members(path: Path):
    """Yield (logical name, file stream) with no archive extraction."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            eligible = [i for i in archive.infolist() if not i.is_dir() and is_json_data_file(i.filename)]
            if not eligible:
                raise ValueError('Archive contains no .json/.jsonl event records')
            yield [(i.filename, archive.open(i)) for i in eligible if i.file_size <= MAX_MEMBER_BYTES]
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, 'r:*') as archive:
            eligible = [i for i in archive.getmembers() if i.isfile() and is_json_data_file(i.name)]
            if not eligible:
                raise ValueError('Archive contains no .json/.jsonl event records')
            yield [(i.name, archive.extractfile(i)) for i in eligible if i.size <= MAX_MEMBER_BYTES]
    else:
        if path.stat().st_size > MAX_MEMBER_BYTES:
            raise ValueError('File exceeds 64 MB; choose one small public dataset instead')
        with path.open('rb') as stream:
            yield [(path.name, stream)]


def convert(source: Path, target: Path, max_events: int = 10000):
    if max_events <= 0 or max_events > 50000:
        raise ValueError('max_events must be 1 to 50,000')
    if source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError('Input exceeds 128 MB; use a smaller dataset')
    target.parent.mkdir(parents=True, exist_ok=True)
    counts = {'seen': 0, 'converted': 0, 'skipped': 0, 'invalid_json': 0}
    # Output only normalized fields; never copy unrelated raw logs.
    with target.open('w', encoding='utf-8') as out, open_members(source) as members:
        if not members:
            raise ValueError('All JSON members were over 64 MB. Choose a smaller dataset.')
        for member_name, binary in members:
            with binary:
                for line_idx, line in enumerate(io.TextIOWrapper(binary, encoding='utf-8-sig'), 1):
                    if len(line) > MAX_LINE_BYTES:
                        counts['skipped'] += 1
                        continue
                    if not line.strip():
                        continue
                    counts['seen'] += 1
                    try:
                        event = json.loads(line)
                    except (ValueError, UnicodeError):
                        counts['invalid_json'] += 1
                        continue
                    if not isinstance(event, dict):
                        counts['skipped'] += 1
                        continue
                    normalized = record_to_signalchain(event, f'import:{member_name}:{line_idx}')
                    if normalized is None:
                        counts['skipped'] += 1
                        continue
                    # Normalize timestamps & ensure the produced file is valid for our analyzer.
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(normalized['timestamp'].replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            raise ValueError('Timezone missing')
                    except (ValueError, TypeError):
                        counts['skipped'] += 1
                        continue
                    out.write(json.dumps(normalized, ensure_ascii=False) + '\n')
                    counts['converted'] += 1
                    if counts['converted'] >= max_events:
                        return counts
    return counts


def main() -> int:
    p = argparse.ArgumentParser(description='Convert a small public Mordor / Winlogbeat JSON dataset, no install needed.')
    p.add_argument('source', type=Path, help='Dataset .zip or .json/.jsonl/.tar.gz saved on your PC')
    p.add_argument('--output', type=Path, default=Path(__file__).resolve().parent.parent/'.local'/'public_import.jsonl')
    p.add_argument('--max-events', type=int, default=10000)
    args = p.parse_args()
    try:
        if not args.source.is_file():
            raise ValueError('Cannot find the downloaded dataset; check the quoted path')
        counts = convert(args.source, args.output, args.max_events)
        print(f"Read {counts['seen']} records; converted {counts['converted']} supported Windows/Sysmon events; skipped {counts['skipped']}; malformed JSON {counts['invalid_json']}.")
        print(f'Private/local normalized file: {args.output}')
        if counts['converted'] == 0:
            print('No compatible records. Try another documented Windows dataset; do not claim this one was validated.')
        return 0 if counts['converted'] else 1
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
