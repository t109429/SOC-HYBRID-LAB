# CASE-002: Suspicious Login and Encoded Scheduled Task

## Case Information

- **Date:** October 17, 2026 (UTC)
- **Account:** t.chen
- **Computer:** ws-ops-09
- **Source IP:** 198.51.100.80
- **Detection Status:** REVIEW
- **Dataset:** Synthetic Windows Security and Sysmon logs

## 1. Summary

While reviewing security logs in Splunk, I identified six failed login attempts involving the t.chen account on ws-ops-09 between 10:25:00 and 10:27:30 UTC. A successful login occurred at 10:28:00 UTC, 30 seconds after the final failed attempt.

At 10:29:00 UTC, Sysmon recorded a PowerShell process running the `Get-Service` command. Eight seconds later, Sysmon recorded a network connection associated with the same process GUID. At 10:30:00 UTC, a scheduled task named `\Company\MaintenanceTelemetry` was created with an encoded PowerShell command in its task action. The task creation occurred 120 seconds after the successful login.

## 2. Evidence

The following events were identified during the investigation:

- **Event ID 4625:** Six failed login attempts from source IP `198.51.100.80`.
- **Event ID 4624:** A successful login at 10:28:00 UTC from the same source IP.
- **Sysmon Event ID 1:** A PowerShell process was created at 10:29:00 UTC. The recorded command line included `powershell.exe -NoProfile -Command Get-Service`.
- **Sysmon Event ID 3:** A network connection was recorded at 10:29:08 UTC to `203.0.113.90` on port `443`. The process GUID matched the PowerShell process in Event ID 1.
- **Event ID 4698:** The scheduled task `\Company\MaintenanceTelemetry` was created at 10:30:00 UTC. Its action included `powershell.exe -NoProfile -EncodedCommand`.

The events occurred close together on the same computer and involved the same user. The matching process GUID connects the PowerShell process creation and network connection. However, those two events happened **before** the scheduled task was created, so they do not prove that the newly created task executed. The available records also do not establish that the PowerShell process or task creation originated from the successful login session; the timeline alone cannot prove that connection.

### Supporting Screenshots

- [CASE-002 combined event timeline](../screenshots/case-002-final-timeline.png)
- [CASE-002 encoded scheduled task](../screenshots/13_case002_encoded_task.png)
- [CASE-002 Sysmon process and network evidence](../screenshots/14_case002_sysmon_network.png)

## 3. Analyst Assessment

I flagged the activity because six failed login attempts were followed by a successful login, PowerShell activity, a network connection, and the creation of an encoded scheduled task within a short period.

At the same time, `Get-Service` is a legitimate Windows command commonly used to retrieve service information. The presence of an encoded PowerShell argument also does not automatically establish malicious intent. These details could be consistent with an authorized maintenance activity, although authorization was not established from the available logs.

The recorded network destination is part of the lab's synthetic dataset; I would not treat it as a verified malicious address. Based on the evidence, this case warrants further review, but I cannot confirm account compromise or malicious execution.

## 4. Recommended Next Steps

I would take the following steps to investigate further:

1. Confirm whether t.chen was expected to access ws-ops-09 at the time of the events.
2. Compare the source IP address with the account's historical login activity and any approved remote-access sources.
3. Decode the scheduled task's PowerShell argument without executing it, and compare the resulting command with approved maintenance scripts.
4. Review the task's creator, trigger, permissions, and execution history to determine whether it was authorized or actually ran.
5. Examine additional endpoint and PowerShell logs, if available, and verify the purpose of the network connection.

## 5. Final Decision

I would retain the **REVIEW** status and escalate the case to a Tier 2 SOC analyst for authorization checks and additional endpoint investigation.

The sequence is suspicious enough to justify a deeper review, but the available records do not establish that the account was compromised. If the task and activity are verified as authorized maintenance, I would document the explanation and close the alert as benign. If additional evidence indicates unauthorized access or execution, I would recommend escalation to the incident response team.

At this stage, I would **not** classify the activity as a confirmed compromise.

## 6. Investigation Limitations

This investigation was conducted using synthetic Windows Security and Sysmon data in a controlled lab environment. No real compromise was identified.

The available records do not include user confirmation, an established baseline of authorized tasks, full endpoint telemetry, or proof that the new scheduled task executed. Additional investigation would be required to distinguish unauthorized activity from legitimate maintenance.
