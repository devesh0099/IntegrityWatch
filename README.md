# IntegrityWatch

IntegrityWatch is an exam proctoring agent that helps ensure environment integrity during online tests. It's built to detect virtual machines, remote access tools, and suspicious browser activity in real-time, giving a clear verdict on whether a test environment is clean or compromised.

Built for the IICPC Dev Intern Competition.

## Key Features

* **VM \& Sandbox Detection**: We don't just check process names. We look deep CPUID hypervisor bits, firmware tables, MAC addresses, and kernel objects to catch VMs trying to hide.
* **Remote Access Monitoring**: Scans for commercial remote control tools (TeamViewer, AnyDesk), checks for suspicious network connections, and monitors RDP sessions.
* **Browser Integrity**: Uses a custom native host bridge to talk to a browser extension, letting us detect tab switching, large copy-pastes, and banned sites during the exam.
* **Automated Reporting**: Spits out clean JSON reports and heartbeat logs, making it easy to integrate with backend grading systems.

## Prerequisites

* **Python**: 3.11, 3.12, or 3.13 (Required)
* **OS**: Windows 10/11 (x64), modern Linux (x86_64), macOS (x86_64) [Arm based devices only support Process Detection and Browser Monitoring]
* **Browsers**: Chrome, Edge, Brave, or other Chromium-based browsers. 
_(For Browser monitoring)_

### How to Install pipx (if not installed)
_(Note: Python verison should be a supported one i.e. 3.11,3.12 or 3.13)_

#### **Windows:** 
    1. `python -m pip install --user pipx` 
    2. `python -m pipx ensurepath`

#### **Linux/macOS:**
    1. `python3 -m pip install --user pipx`
    2. `pipx ensurepath`

_(Note: After running `ensurepath`, restart the terminal for effect to take place)._

## Installation

- Copying from source

```bash
git clone https://github.com/devesh0099/IntegrityWatch.git
cd IntegrityWatch
```

### 1. On Linux / macOS

```bash
pipx install .
```

### 2. On Windows

```bash
pipx install .
pipx runpip integritywatch install --no-index --find-links=wheels cpuid==0.1.1 cpuid-native==0.1.1
```
_(Note: If the [windows] prefix is not utilized, a single detection technique will fail gracefully; however, all other program features will remain fully functional.)_


### 3. Installation of native bridge

- **Linux/macOS**
```bash
integritywatch-install-extension
```
- **Windows**
```bash
integritywatch-install-extension.exe
```
_(NOTE: Run the program from the same local directory)_
This will install the extension support for the Browser Monitoring. (Run as Admin on windows)

### 4. Loading the browser extension.

To load the extension:

1. Open any Chromium-based browser
2. Navigate to the extensions page:
   - Edge: `edge://extensions`
   - Chrome: `chrome://extensions`
   - Brave: `brave://extensions`
3. Enable **Developer Mode** (toggle in top-right corner)
4. Click **Load unpacked**
5. Navigate to: `<clone-directory>/src/integritywatch/browser_monitor/extension`
6. Select the folder

## Usage

### Scan

To run a full environment check:

- On **Linux/macOS**
```bash
integritywatch
```

- On **Windows**
```bash
integritywatch.exe
```

This runs all engines VM, Remote Access, and Browser and prints a summary.

* **PASS (Green)**: System is clean.
* **FLAG (Yellow)**: Suspicious artifacts found (e.g., suspicious website or extension is allowed), but can also be a false positive.
* **BLOCK (Red)**: Confirmed violation (e.g., active screen sharing or running inside a VM).

### Continuous Monitoring

If the initial scan passes, IntegrityWatch can stay running to monitor the session:

```text
Unified Monitoring Active
Monitoring browser violations and remote access every 5 seconds
Press ENTER to stop monitoring
```

It will generate "heartbeat" files in the `results/` folder, which serve as proof of continuous compliance during the exam.

## Configuration

Settings of the tool can tweak by editing `config/settings.json` (generated after the first run).

* **`monitoring_interval`**: How often (in seconds) to recheck the system.
* **`remote_access`**: Whitelist specific conferencing tools if needed.
* **`browser`**: Configure allowed websites or extensions.

## License

MIT License. See `LICENSE` for details.


