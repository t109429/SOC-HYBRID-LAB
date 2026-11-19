# Reproducibility notes

## Dataset

The baseline dataset contains 44 synthetic Windows Security and Sysmon events.

The background generator adds another 330 synthetic events, bringing the combined dataset to 374 records, including 20 scheduled-task creation events.

The additional events include one suspicious sequence and six negative test scenarios designed to check the correlation logic.

## Running the Lab

Open PowerShell in the project folder.

Run the Python unit tests:

`py -3 -m unittest discover -s tests -v`

Validate the baseline dataset:

`py -3 tools/validate_lab.py`

Generate the additional events:

`py -3 tools/generate_background.py`

Validate the expanded dataset:

`py -3 tools/validate_lab.py --expanded`

## Expected Results

The current test suite contains eight tests.

The baseline dataset should produce:

- 44 events
- 1 review candidate

The expanded dataset should produce:

- 374 events
- 20 scheduled tasks
- 2 review candidates

The two review candidates correspond to the investigations documented in CASE-001 and CASE-002.

## Detection Limitations

The validation script identifies event sequences based on account, host, source IP, and timestamps.

These correlations identify activity worth investigating. They do not establish that a scheduled task executed or that the activity originated from a particular login session.

The project uses synthetic data, and its findings are limited to the events available in the dataset.

## Project Scope

This repository includes the Python scripts, synthetic datasets, SPL searches, case reports, and eight current validation tests.

The earlier offline dashboard implementation and its 33-test suite are not included in this version.

Splunk queries must be run separately in Splunk to verify their results. The Python tests do not execute SPL searches.
