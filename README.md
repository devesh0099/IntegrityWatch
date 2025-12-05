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
* **OS**: Windows 10/11 (x64), modern Linux (x86_64), macOS 
* **Browsers**: Chrome, Edge, Brave, or other Chromium-based browsers. 
_(For Browser monitoring)_

### How to Install pipx (if not installed)

- **Windows:** `py -m pip install --user pipx` followed by `py -m pipx ensurepath`
- **macOS:** `brew install pipx` followed by `pipx ensurepath`
- **Linux (Fedora):** `sudo dnf install pipx` followed by `pipx ensurepath`
- **Linux (Ubuntu/Debian):** `sudo apt install pipx` followed by `pipx ensurepath`
    
_(Note: After running `ensurepath`, you need to close and reopen your terminal)._

## Installation

### 1. Windows Installation (Recommended)

On Windows, we rely on a specific native CPUID library to get accurate hardware readings. You **must** install with the `[windows]` extra to ensure the correct pre-built wheels are pulled in.

```powershell
pipx install "git+https://github.com/devesh0099/IntegrityWatch.git#egg=integritywatch[windows]"
```


### 2. Linux/macOS Installation

Linux and macOS have pre-built binaries avaialable.

```bash
pipx install "git+https://github.com/devesh0099/IntegrityWatch.git"
```

### 3. Browser Extension Setup

After the CLI tool is installed, you need to register the "Native Host", the bridge that lets our Python code talk to the browser. We built a simple helper command for this:

```bash
integritywatch-install-extension
```

* **Windows**: This will set up the necessary Registry keys, hence required to "Run as a Administrator"
* **Linux/macOS**: This writes the manifest files to your browser's configuration directory.

Once that's done, ensure the IntegrityWatch extension is loaded in your browser (e.g., via `chrome://extensions/` in Developer Mode pointing to the `browser_monitor/extension` folder located under `src/integritywatch`).

## Fallback installation

If the installation fails try to do it manually

- Copying from source

```bash
git clone https://github.com/devesh0099/IntegrityWatch.git
cd integritywatch
```

### 1. On Linux / macOS

```bash
pipx install .
```

### 2. On Windows

```bash
pipx install ".[windows]"
```

_(Note: If the [windows] prefix is not utilized, a single detection technique will fail gracefully; however, all other program features will remain fully functional.)_
## Usage

### Scan

To run a full environment check:

```bash
integritywatch
```

This runs all engines—VM, Remote Access, and Browser—and prints a summary.

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

