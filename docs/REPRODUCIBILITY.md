# Reproducibility notes

The supplied `data/synthetic_events.jsonl` contains 44 synthetic events. The original `tools/generate_background.py` produces 330 additional events in `.local/splunk/signalchain_background.jsonl` and validates its deliberately inserted positive and negative examples.

The two combined files have 374 records and 20 scheduled-task creation events. The rebuilt `tools/validate_lab.py` checks the basic failed-logon, successful-logon, and encoded-task timing pattern and returns one candidate in the 44-event baseline and two candidates after the expansion.

These are time-based candidate detections. They do not prove the scheduled task ran, that the account was stolen, or that an action can be attributed to a particular logon session.

The previous version of the project had an offline dashboard and a 33-test suite shown in screenshots. The code for that version was not included in the uploaded files assembled here. Do not describe the earlier code as part of this repository. The `tests/` folder here has eight tests for the scripts and data that are actually present.

An original exporter expected to import `load_events` from the unavailable `soclab.py`. This repository's `tools/export_to_splunk.py` includes a small local replacement loader so its baseline export works without that missing module.

Splunk queries cannot be tested with Python alone. Run them in your own Splunk installation and document any changes needed to index settings, timestamp extraction, or source types.
