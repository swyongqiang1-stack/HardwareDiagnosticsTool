# Windows Reboot Diagnostics

A lightweight Windows diagnostic tool that helps identify possible hardware-related causes of unexpected reboots, freezes, and BSOD crashes by analyzing native Windows Event Logs.

## Why I Built This

When troubleshooting Windows notebooks in production environments, users often report:

- Random reboots
- Sudden power loss
- System freezes
- Blue screen crashes (BSOD)

Finding the root cause usually requires manually reviewing multiple event logs, which can be time-consuming and inconsistent.

This tool automates the correlation of several important Windows event sources and generates a simple diagnostic report.

## Features

### Kernel-Power Event Analysis

Detects and analyzes:

- Event ID 41
- Bugcheck Codes
- Unexpected shutdown events
- Power button shutdown records

### WHEA Hardware Error Analysis

Detects:

- CPU Machine Check Exceptions
- Cache hierarchy errors
- PCIe bus errors
- Hardware architecture faults

### Memory Diagnostics Detection

Checks Windows Memory Diagnostic results and identifies confirmed memory-related issues.

### Storage Error Detection

Reviews:

- Disk driver errors
- NTFS critical events

### Thermal Shutdown Detection

Detects emergency thermal shutdown events caused by overheating.

## Diagnostic Categories

The tool estimates the likelihood of issues related to:

- CPU
- RAM
- SSD / HDD
- Power Delivery / Motherboard
- GPU

## Example Output

The report includes:

- Suspected faulty component
- Hardware instability scores
- Event log evidence
- Recommended troubleshooting actions

## Requirements

- Windows 10
- Windows 11
- Windows Server 2019+
- .NET Runtime

Administrator privileges are recommended for complete event log access.

## Limitations

This tool does not directly test hardware.

It provides a probability-based assessment using Windows event telemetry and should be used as a troubleshooting aid rather than a definitive hardware diagnosis.

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

You are free to use, modify, and distribute this software under the terms of the GPL-3.0 license.

See the LICENSE file for details.
