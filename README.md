# Agent Smith

## Description

**Agent Smith** is a lightweight, asynchronous monitoring tool written in Python 3.10+. 
It is designed to monitor system health metrics and network connectivity, providing real-time 
logging and email alerts when thresholds are exceeded.

## Key Features

* **Load Average Monitoring**: Tracks CPU load for 1, 5, and 15-minute intervals.
* **Memory Usage**: Monitors RAM utilization percentages.
* **Disk Health**: Checks free space and usage across multiple configurable mount points.
* **NTP Drift Detection**: Ensures system time synchronization by checking against NTP pool servers.
* **TCP Port Checks**: Verifies if specific network ports are reachable.
* **Asynchronous Engine**: Built with `asyncio` for non-blocking concurrent checks.
* **Alerting System**: Integrated SMTP support for sending critical and warning email notifications.

## Installation

1. **Clone the repository**:
```bash
$ git clone https://github.com/hvad/agent-smith.git
$ cd agent-smith

```

2. **Set up a virtual environment** (Python 3.10 recommended):
```bash
$ python3 -m venv venv
$ source venv/bin/activate

```

3. **Install dependencies**:
```bash
$ pip install -r requirements.txt

```

## Usage

### 1. Configure the Agent

Edit the generated `agent-smith.ini`. Ensure you set the following essential fields:

* **[Email]**: SMTP server details and recipient addresses for alerts.
* **[System]**: Specific disks to monitor and your desired warning/critical thresholds.
* **[Setting]**: Enable or disable specific check modules.

### 2. Run the Agent

**Foreground Mode (for testing):**

```bash
$ python agent-smith.py -c agent-smith.ini

```

**Daemon Mode (for production):**

```bash
$ python agent-smith.py -d -c agent-smith.ini

```

## CLI Options

| Option | Description |
| --- | --- |
| `-h, --help` | Show the help message and exit. |
| `-d, --daemonize` | Run the process as a background daemon. |
| `-c, --config` | **Required.** Path to your configuration file. |

