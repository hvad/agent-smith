#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Authors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-04-27

import sys
import os
import argparse
import logging
import fcntl
import asyncio
import socket
import smtplib
from configparser import ConfigParser
from contextlib import closing
from email.message import EmailMessage
import ntplib
import psutil

# --- Alert Management ---

class SMTPAlert:
    """Manages sending email alerts via SMTP SSL."""
    def __init__(self, config):
        self.smtp_server = config.get('Email', 'smtp_server')
        self.smtp_port = config.getint('Email', 'smtp_port')
        self.sender_email = config.get('Email', 'sender_email')
        self.receiver_email = config.get('Email', 'receiver_email')
        self.smtp_username = config.get('Email', 'smtp_username', fallback='')
        self.smtp_password = config.get('Email', 'smtp_password', fallback='')

    async def send_alert(self, subject, body):
        """Sends an email alert asynchronously using a thread pool for blocking SMTP calls."""
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email

        try:
            # SMTP operations are synchronous, run in a separate thread to avoid blocking the event loop
            await asyncio.to_thread(self._send_sync_email, msg)
        except Exception as e:
            logging.error(f"Failed to send SMTP alert: {e}")

    def _send_sync_email(self, msg):
        """Synchronous SMTP connection logic."""
        with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)

# --- Monitoring Checks ---

class BaseCheck:
    """Base class for all monitoring checks to ensure consistent structure."""
    def __init__(self, config):
        self.config = config
        # Automatically determine the config key from class name (e.g., MemoryUsageCheck -> memoryusage)
        self.config_key = self.__class__.__name__.lower().replace('check', '')

    async def run(self):
        """Must be implemented by subclasses to perform the actual check."""
        raise NotImplementedError("Subclasses must implement run() method")

    def _format_result(self, category, status, message):
        """Formats the check result into a standard dictionary."""
        return {category: (status, message)}

class NTPDriftCheck(BaseCheck):
    """Checks for time drift against a configured NTP pool server."""
    async def run(self):
        server = self.config.get('Ntp', 'ntp_pool_server')
        warn = self.config.getfloat('Ntp', 'ntp_warning_threshold')
        crit = self.config.getfloat('Ntp', 'ntp_critical_threshold')

        try:
            client = ntplib.NTPClient()
            # ntplib.request is blocking, run in thread
            response = await asyncio.to_thread(client.request, server, version=3)
            offset = abs(response.offset)
            status = "OK"
            if offset >= crit: status = "CRITICAL"
            elif offset >= warn: status = "WARNING"
            return self._format_result("NTP", status, f"NTP Drift Offset: {offset:.4f}s")
        except Exception as e:
            return self._format_result("NTP", "CRITICAL", f"NTP Error: {e}")

class DiskUsageCheck(BaseCheck):
    """Checks disk space usage for specified mount points."""
    async def run(self):
        disks = [d.strip() for d in self.config.get('System', 'disks').split(',')]
        warn = self.config.getint('System', 'disk_warning_threshold')
        crit = self.config.getint('System', 'disk_critical_threshold')

        results = {}
        for path in disks:
            try:
                usage = psutil.disk_usage(path)
                status = "OK"
                if usage.percent >= crit: status = "CRITICAL"
                elif usage.percent >= warn: status = "WARNING"
                results[path] = (status, f"Used: {usage.percent}%")
            except Exception as e:
                results[path] = ("ERROR", f"Could not check {path}: {e}")
        return {"Disk Usage": results}

class MemoryUsageCheck(BaseCheck):
    """Checks system RAM usage."""
    async def run(self):
        mem = psutil.virtual_memory()
        warn = self.config.getfloat('System', 'memory_warning_threshold')
        crit = self.config.getfloat('System', 'memory_critical_threshold')

        status = "OK"
        if mem.percent >= crit: status = "CRITICAL"
        elif mem.percent >= warn: status = "WARNING"
        return self._format_result("Memory Usage", status, f"RAM Usage: {mem.percent}%")

class LoadAverageCheck(BaseCheck):
    """Checks system load average for the last 1 minute."""
    async def run(self):
        load = psutil.getloadavg()
        warn = self.config.getfloat('System', 'load_average_warning_threshold')
        crit = self.config.getfloat('System', 'load_average_critical_threshold')

        status = "OK"
        if load[0] >= crit: status = "CRITICAL"
        elif load[0] >= warn: status = "WARNING"
        return self._format_result("Load", status, f"1min: {load[0]}, 5min: {load[1]}")

# --- Core Engine ---

class AgentSmithEngine:
    """Main engine that orchestrates checks, logging, and alerts."""
    def __init__(self, config_file):
        self.config = ConfigParser()
        self.config.read(config_file)
        self.check_period = self.config.getint('Setting', 'period')
        self.hostname = self.config.get('System', 'hostname', fallback=socket.gethostname())
        self.email_alert = SMTPAlert(self.config)
        self.checks = []
        self._setup_logging()

    def _setup_logging(self):
        """Initializes logging based on configuration file settings."""
        log_path = self.config.get('Setting', 'log_file_path')
        logging.basicConfig(
            filename=log_path,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [%(hostname)s] %(message)s'
        )
        self.logger = logging.getLogger('AgentSmith')

    def add_check(self, check_class):
        """Adds a check to the execution list if it is enabled in the configuration."""
        check_instance = check_class(self.config)
        if self.config.getboolean('Setting', check_instance.config_key, fallback=True):
            self.checks.append(check_instance)

    async def run_checks(self):
        """Continuous loop running all checks at specified intervals."""
        while True:
            start_time = asyncio.get_event_loop().time()

            # Execute all checks in parallel
            tasks = [check.run() for check in self.checks]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logging.error(f"Check execution failed: {result}")
                    continue
                if result:
                    await self._process_result(result)

            # Calculate remaining sleep time to maintain a steady period
            elapsed = asyncio.get_event_loop().time() - start_time
            await asyncio.sleep(max(0, self.check_period - elapsed))

    async def _process_result(self, result):
        """Parses results for logging and conditional alerting."""
        for cat, data in result.items():
            if isinstance(data, dict): # Specialized handling for multi-item checks like Disks
                for item, (status, msg) in data.items():
                    self._log_and_alert(f"{cat} ({item})", status, msg)
            else:
                status, msg = data
                self._log_and_alert(cat, status, msg)

    def _log_and_alert(self, category, status, message):
        """Logs the status and triggers an asynchronous email task if an alert is needed."""
        log_entry = f"{category}: {status} - {message}"
        self.logger.info(log_entry, extra={'hostname': self.hostname})
        print(log_entry)

        # Check if alerts are enabled for this specific category
        alert_key = category.lower().replace(' ', '').split('(')[0] # Clean key
        alert_enabled = self.config.getboolean('Alerts', alert_key, fallback=False)

        if alert_enabled and status in ["CRITICAL", "WARNING"]:
            subject = f"Agent Smith Alert [{status}] - {category} on {self.hostname}"
            asyncio.create_task(self.email_alert.send_alert(subject, message))

# --- Main Entry Point ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent Smith Monitoring Daemon")
    parser.add_argument("-c", "--config", required=True, help="Path to the config.ini file")
    args = parser.parse_args()

    # Initialize Engine
    agent = AgentSmithEngine(args.config)

    # Register available checks
    agent.add_check(LoadAverageCheck)
    agent.add_check(MemoryUsageCheck)
    agent.add_check(DiskUsageCheck)
    agent.add_check(NTPDriftCheck)

    print(f"Agent Smith started monitoring on {agent.hostname}...")
    try:
        asyncio.run(agent.run_checks())
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
