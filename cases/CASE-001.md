# CASE-001: Suspicious Login and Scheduled Task

## Case Information

- **Date:** October 17, 2026 (UTC)
- **Account:** j.smith
- **Computer:** ws-fin-07
- **Source IP:** 198.51.100.24
- **Detection Status:** REVIEW
- **Dataset:** Synthetic Windows Security and Sysmon logs

## 1. Summary

While reviewing the security logs in Splunk, I identified six failed login attempts involving the j.smith account. A successful login occurred 85 seconds after the last failed attempt.

Following the successful login, I identified PowerShell process activity and a scheduled task containing an encoded PowerShell command. The task was created 175 seconds after the successful login.

## 2. Evidence

The following events were identified during the investigation:

- **Event ID 4625:** Six failed login attempts.
- **Event ID 4624:** One successful login following the failed attempts.
- **Process activity:** PowerShell execution was recorded after the successful login.
- **Event ID 4698:** A scheduled task named `\WindowsTelemetryUpdate` was created.
- **PowerShell:** The scheduled task contained the `-EncodedCommand` argument.

The events occurred close together and involved the same user and computer. Their timing alone does not prove the scheduled task was executed by the successful logon session.

### Supporting Screenshots

- [Login and task timeline](../screenshots/09_case001_login_task_timeline.png)
- [PowerShell process/network correlation](../screenshots/10_case001_sysmon_correlation.png)
- [Encoded scheduled task](../screenshots/11_case001_encoded_task.png)

## 3. Analyst Assessment

I flagged this activity because multiple failed login attempts were followed by a successful login and PowerShell activity within a short period.

The scheduled task also contained an encoded PowerShell command, which made the activity worth investigating further. However, encoded commands and scheduled tasks can occur during legitimate administration.

Although these events are suspicious, I cannot confirm that the account was compromised based on the available evidence alone.

## 4. Recommended Next Steps

1. Review the affected computer and compare the event times against the user's normal working hours.
2. Check whether the source IP address matches the user's typical login activity.
3. Decode the PowerShell command **without executing it** to determine what it was designed to do.
4. Review the process that launched PowerShell and examine any related network activity.
5. Determine whether the scheduled task was authorized or created without the user's knowledge.

## 5. Final Decision

I would escalate this case to a Tier 2 SOC analyst for further investigation.

The combination of failed logins, a successful login, PowerShell activity, and an encoded scheduled task provides enough reason for a deeper review.

If additional evidence suggests unauthorized access, the case could be referred to an incident response team for forensic analysis. At this stage, I would not classify the activity as a confirmed compromise.

## 6. Investigation Limitations

This investigation was conducted using synthetic security logs in a controlled lab.

The detection identified suspicious behavior, but no actual compromise was confirmed. Additional information, including user verification and further endpoint analysis, would be needed to determine whether the activity was malicious.
