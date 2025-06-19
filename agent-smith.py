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
import time
import socket
import asyncio
import smtplib
from configparser import ConfigParser
from contextlib import closing
from email.message import EmailMessage
import ntplib
import psutil


class SMTPAlert:
    """Manages sending email alerts via SMTP."""

    def __init__(self, config):
        self.smtp_server = config.get('Email', 'smtp_server')
        self.smtp_port = config.getint('Email', 'smtp_port')
        self.sender_email = config.get('Email', 'sender_email')
        self.receiver_email = config.get('Email', 'receiver_email')
        self.smtp_username = config.get('Email', 'smtp_username', fallback='')
        self.smtp_password = config.get('Email', 'smtp_password', fallback='')

    async def send_alert(self, subject, body):
        """Sends an email alert asynchronously."""
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email

        try:
            # SMTP_SSL is synchronous, so we run it in a thread pool
            await asyncio.to_thread(self._send_sync_email, msg)
        except smtplib.SMTPConnectError as e:
            print(f"SMTP connection error: {e}")
        except smtplib.SMTPAuthenticationError as e:
            print(f"SMTP authentication error: {e}")
        except smtplib.SMTPException as e:
            print(f"An SMTP error occurred: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while sending email: {e}")

    def _send_sync_email(self, msg):
        """Synchronous part of sending email, to be run in a thread."""
        with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
            server.ehlo()
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)


class BaseCheck:
    """Base class for all monitoring checks."""

    def __init__(self, config):
        self.config = config
        self.result = None

    async def run(self):
        """Runs the check asynchronously and returns the result."""
        raise NotImplementedError("Subclasses must implement run() method")

    def _format_result(self, category, status, message):
        return {category: (status, message)}


class NTPDriftCheck(BaseCheck):
    """Checks NTP drift."""

    def __init__(self, config):
        super().__init__(config)
        self.ntp_pool_server = config.get('Ntp', 'ntp_pool_server')
        self.warning_threshold = config.getfloat('Ntp', 'ntp_warning_threshold')
        self.critical_threshold = config.getfloat('Ntp', 'ntp_critical_threshold')

    async def check_ntp_drift(self):
        """Performs the NTP drift check asynchronously."""
        try:
            ntp_client = ntplib.NTPClient()
            # ntplib.request is blocking, run in a thread
            response = await asyncio.to_thread(ntp_client.request, self.ntp_pool_server, version=3)
            offset = response.offset
            time_str = f"{abs(offset):.2f}"

            if abs(offset) >= self.critical_threshold:
                self.result = self._format_result("NTP", "CRITICAL", f"NTP Drift Alert: Offset = {time_str}s")
            elif abs(offset) >= self.warning_threshold:
                self.result = self._format_result("NTP", "WARNING", f"NTP Drift Alert: Offset = {time_str}s")
            else:
                self.result = self._format_result("NTP", "OK", f"NTP Drift within thresholds: Offset = {time_str}s")
        except ntplib.NTPException as e:
            self.result = self._format_result("NTP", "CRITICAL", f"NTP Pool server {self.ntp_pool_server} not reachable! Error: {e}")
        except Exception as e:
            self.result = self._format_result("NTP", "CRITICAL", f"An error occurred during NTP check: {e}")

    async def run(self):
        await self.check_ntp_drift()
        return self.result


class TCPCheck(BaseCheck):
    """Checks if a TCP/IP port is open."""

    def __init__(self, config):
        super().__init__(config)
        self.hostname = config.get('System', 'hostname')
        self.port = config.getint('System', 'port')
        self.timeout = config.getint('System', 'timeout')

    async def _perform_tcp_check_sync(self):
        """Synchronous part of TCP check, to be run in a thread."""
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(self.timeout)
            return sock.connect_ex((self.hostname, self.port)) == 0

    async def check_tcp(self):
        """Performs the TCP port check asynchronously."""
        try:
            # socket operations are blocking, run in a thread
            is_open = await asyncio.to_thread(self._perform_tcp_check_sync)
            if is_open:
                self.result = self._format_result("Firewall", "OK", f"Port {self.port} on {self.hostname} is open")
            else:
                self.result = self._format_result("Firewall", "CRITICAL", f"Port {self.port} on {self.hostname} is closed")
        except socket.gaierror:
            self.result = self._format_result("Firewall", "CRITICAL", f"Hostname '{self.hostname}' could not be resolved.")
        except socket.timeout:
            self.result = self._format_result("Firewall", "CRITICAL", f"Connection to {self.hostname}:{self.port} timed out.")
        except Exception as e:
            self.result = self._format_result("Firewall", "CRITICAL", f"Error checking firewall: {e}")

    async def run(self):
        await self.check_tcp()
        return self.result


class DiskUsageCheck(BaseCheck):
    """Checks disk usage."""

    def __init__(self, config):
        super().__init__(config)
        self.disks = [d.strip() for d in config.get('System', 'disks').split(',')]
        self.warning_threshold = config.getint('System', 'disk_warning_threshold')
        self.critical_threshold = config.getint('System', 'disk_critical_threshold')

    @staticmethod
    def bytes2human(n):
        """Converts bytes to human-readable format."""
        symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
        prefix = {s: 1 << (i + 1) * 10 for i, s in enumerate(symbols)}
        for s in reversed(symbols):
            if n >= prefix[s]:
                value = float(n) / prefix[s]
                return f"{value:.2f} {s}B"
        return f"{n} B"

    def _perform_disk_usage_check_sync(self):
        """Synchronous part of disk usage check, to be run in a thread."""
        disk_results = {} # Use a new dictionary to store results for each disk
        overall_status = "OK" # Keep track of the highest severity
        
        for disk_path in self.disks:
            try:
                disk_usage = psutil.disk_usage(disk_path)
                disk_total = self.bytes2human(disk_usage.total)
                disk_used = self.bytes2human(disk_usage.used)
                disk_free = self.bytes2human(disk_usage.free)
                
                status = "OK"
                if disk_usage.percent >= self.critical_threshold:
                    status = "CRITICAL"
                    overall_status = "CRITICAL" # Promote overall status
                elif disk_usage.percent >= self.warning_threshold:
                    status = "WARNING"
                    if overall_status == "OK": # Only promote to WARNING if not already CRITICAL
                        overall_status = "WARNING"
                
                usage_info = f"Total = {disk_total}, Used = {disk_used}, Free = {disk_free}, Percent = {disk_usage.percent}%"
                disk_results[f'{disk_path}'] = (status, usage_info) # Store status and message for each disk
            except Exception as e:
                status = "ERROR"
                usage_info = f"Could not check disk {disk_path}: {e}"
                disk_results[f'{disk_path}'] = (status, usage_info)
                overall_status = "CRITICAL" # If any disk has an error, mark as critical
        
        # The DiskUsageCheck run method will now return a dictionary where the key is "Disk Usage"
        # and the value is another dictionary containing results for each disk.
        return {"Disk Usage": disk_results}

    async def run(self):
        """Performs the disk usage check asynchronously."""
        self.result = await asyncio.to_thread(self._perform_disk_usage_check_sync)
        return self.result


class MemoryUsageCheck(BaseCheck):
    """Checks memory usage."""

    def __init__(self, config):
        super().__init__(config)
        self.warning_threshold = config.getfloat('System', 'memory_warning_threshold')
        self.critical_threshold = config.getfloat('System', 'memory_critical_threshold')

    def _perform_memory_check_sync(self):
        """Synchronous part of memory check, to be run in a thread."""
        memory_info = psutil.virtual_memory()
        memory_percent = memory_info.percent
        if memory_percent >= self.critical_threshold:
            return self._format_result("Memory Usage", "CRITICAL", f"Memory Usage is {memory_percent}%")
        elif memory_percent >= self.warning_threshold:
            return self._format_result("Memory Usage", "WARNING", f"Memory Usage is {memory_percent}%")
        else:
            return self._format_result("Memory Usage", "OK", f"Memory Usage is {memory_percent}%")

    async def run(self):
        """Performs the memory usage check asynchronously."""
        self.result = await asyncio.to_thread(self._perform_memory_check_sync)
        return self.result


class LoadAverageCheck(BaseCheck):
    """Checks load average for 1, 5, and 15 minutes."""

    def __init__(self, config):
        super().__init__(config)
        self.warning_threshold = config.getfloat('System', 'load_average_warning_threshold')
        self.critical_threshold = config.getfloat('System', 'load_average_critical_threshold')

    def _perform_load_average_check_sync(self):
        """Synchronous part of load average check, to be run in a thread."""
        load_average = psutil.getloadavg()
        message = f"1 min={load_average[0]}, 5 min={load_average[1]}, 15 min={load_average[2]}"
        
        if load_average[0] > self.critical_threshold:
            return self._format_result("Load", "CRITICAL", message)
        elif load_average[0] > self.warning_threshold:
            return self._format_result("Load", "WARNING", message)
        else:
            return self._format_result("Load", "OK", message)

    async def run(self):
        """Performs the load average check asynchronously."""
        self.result = await asyncio.to_thread(self._perform_load_average_check_sync)
        return self.result


class ConfigValidator:
    """Validates configuration file settings."""

    def __init__(self, config_file):
        self.config = ConfigParser()
        self.config.read(config_file)

    def validate_setting(self, section, key, expected_value):
        """Validates a specific setting."""
        try:
            actual_value = self.config.get(section, key)
            if actual_value != expected_value:
                print(f"Validation failed for {section}.{key}. Expected: '{expected_value}', Actual: '{actual_value}'")
                sys.exit(1)
        except Exception as e:
            print(f"Error validating setting {section}.{key}: {e}")
            sys.exit(1)


class ConfigGenerator:
    """Generates a default configuration file."""

    def __init__(self, filename):
        self.filename = filename
        self.config = ConfigParser()
        self._initialize_default_settings()

    def _initialize_default_settings(self):
        """Sets up default configuration sections and values."""
        self.config['Setting'] = {
            'period': '60',
            'log_file_path': 'agent-smith.log',
            'pid_file_path': 'agent-smith.pid',
            'lock_file_path': 'agent-smith.lock',
            'loadaveragecheck': 'True',
            'memoryusagecheck': 'True',
            'diskusagecheck': 'True',
            'ntpdriftcheck': 'False',
            'tcpcheck': 'False'
        }
        self.config['System'] = {
            'hostname': self._get_hostname(),
            'load_average_warning_threshold': '16',
            'load_average_critical_threshold': '24',
            'disks': ', '.join(self._get_disks_name()),
            'disk_warning_threshold': '90',
            'disk_critical_threshold': '95',
            'memory_warning_threshold': '85',
            'memory_critical_threshold': '95',
            'port': '443',
            'timeout': '5'
        }
        self.config['Ntp'] = {
            'ntp_pool_server': 'pool.ntp.org', # Sensible default
            'ntp_warning_threshold': '1',
            'ntp_critical_threshold': '3'
        }
        self.config['Email'] = {
            'smtp_server': '',
            'smtp_port': '587', # Common SMTP TLS port
            'sender_email': '',
            'receiver_email': '',
            'smtp_username': '',
            'smtp_password': ''
        }
        self.config['Alerts'] = {
            'loadaveragecheck': 'False',
            'memoryusagecheck': 'False',
            'diskusagecheck': 'False',
            'ntpdriftcheck': 'False',
            'tcpcheck': 'False'
        }

    @staticmethod
    def _get_hostname():
        """Gets the hostname."""
        try:
            return socket.gethostname()
        except socket.error:
            return 'localhost'

    @staticmethod
    def _get_disks_name():
        """Gets a list of relevant disk mount points."""
        excluded_fs_types = ['tmpfs', 'devtmpfs', 'squashfs']
        exclude_partition_names = ['/run', '/sys', '/proc'] # More comprehensive exclusions
        partitions = psutil.disk_partitions(all=False)
        disks = [
            p.mountpoint for p in partitions
            if p.fstype not in excluded_fs_types
            and p.mountpoint not in exclude_partition_names
        ]
        return disks

    def generate_and_write_config(self):
        """Generates and writes the configuration to a file."""
        with open(self.filename, 'w') as f:
            self.config.write(f)


class AgentSmithEngine:
    """Main engine for Agent Smith, orchestrating checks and alerts."""

    def __init__(self, config_file):
        self.config_file_path = config_file
        self.config = ConfigParser()
        self.config.read(self.config_file_path)

        self.log_file_path = self.config.get('Setting', 'log_file_path')
        self.pid_file_path = self.config.get('Setting', 'pid_file_path')
        self.lock_file_path = self.config.get('Setting', 'lock_file_path')
        self.check_period = self.config.getint('Setting', 'period')

        self.email_alert = SMTPAlert(self.config)
        self.alerts_config = self.config['Alerts']
        self.result_logger = AgentSmithLogger(self.log_file_path, self.config.get('System', 'hostname'))

        self.checks = []

    def add_check(self, check_class):
        """Adds a check to the engine if enabled in the config."""
        check_name = check_class.__name__.lower()
        # Remove 'check' suffix for config lookup if present, e.g., 'diskusage' for 'diskusagecheck'
        config_key = check_name.replace('check', '') if check_name.endswith('check') else check_name

        # Ensure the key exists in 'Setting' section before trying to getboolean
        if self.config.has_option('Setting', config_key):
            enabled = self.config.getboolean('Setting', config_key)
        else:
            # Fallback for keys like 'loadaveragecheck' if config only has 'loadaverage'
            if self.config.has_option('Setting', check_name):
                 enabled = self.config.getboolean('Setting', check_name)
            else:
                enabled = True # Default to enabled if not specified

        if enabled:
            self.checks.append(check_class(self.config))

    async def run_checks(self, print_output=False):
        """Runs all enabled checks asynchronously."""
        while True:
            tasks = [check.run() for check in self.checks]
            results = await asyncio.gather(*tasks)

            for result in results:
                if result: # Ensure result is not None
                    self.result_logger.log_result(result)
                    if print_output:
                        print(f"Check result: {result}")
                    await self._handle_alerts(result) # Await the async alert handler
            
            await asyncio.sleep(self.check_period)

    async def _handle_alerts(self, result):
        """Handles alerts based on check results and configuration."""
        for check_category, check_data in result.items():
            # For DiskUsageCheck, check_data is a dictionary of disk results
            if isinstance(check_data, dict):
                alert_key = check_category.replace(' ', '').lower() # e.g., 'diskusage'
                if self.alerts_config.getboolean(alert_key, fallback=False):
                    for disk_name, (status, message) in check_data.items():
                        if status in ["CRITICAL", "WARNING"]:
                            subject = f"{check_category} Alert - {status} on {disk_name}"
                            body = f"Host: {self.result_logger.hostname}\n{message}"
                            await self.email_alert.send_alert(subject, body) # Await send_alert
            else: # For other checks, check_data is a tuple (status, message)
                status, message = check_data
                alert_key = check_category.replace(' ', '').lower() # e.g., 'memoryusage', 'load'

                if self.alerts_config.getboolean(alert_key, fallback=False):
                    if status in ["CRITICAL", "WARNING"]:
                        subject = f"{check_category} Alert - {status}"
                        body = f"Host: {self.result_logger.hostname}\n{message}"
                        await self.email_alert.send_alert(subject, body) # Await send_alert

    def acquire_lock(self):
        """Acquires a file lock to ensure single instance."""
        try:
            self.lock_file = open(self.lock_file_path, 'w')
            # Try to acquire an exclusive non-blocking lock
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            print("Another instance is already running. Exiting.")
            sys.exit(1)

    def run_as_daemon(self):
        """Daemonizes the process."""
        self.acquire_lock()
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0) # Exit first parent
        except OSError as err:
            sys.stderr.write(f"Fork #1 failed: {err}\n")
            sys.exit(1)

        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0) # Exit second parent
        except OSError as err:
            sys.stderr.write(f"Fork #2 failed: {err}\n")
            sys.exit(1)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r', encoding="utf-8")
        so = open(os.devnull, 'a+', encoding="utf-8")
        se = open(os.devnull, 'a+', encoding="utf-8")

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        self.write_pid_file()
        try:
            asyncio.run(self.run_checks())
        except KeyboardInterrupt:
            print("Daemon interrupted. Cleaning up...")
        finally:
            self.remove_pid_file()
            if hasattr(self, 'lock_file'):
                self.lock_file.close()
            if os.path.exists(self.lock_file_path):
                os.remove(self.lock_file_path)

    def write_pid_file(self):
        """Writes the current PID to a file."""
        if self.pid_file_path:
            pid = str(os.getpid())
            with open(self.pid_file_path, 'w', encoding="utf-8") as pid_file:
                pid_file.write(pid)

    def remove_pid_file(self):
        """Removes the PID file."""
        if self.pid_file_path and os.path.exists(self.pid_file_path):
            os.remove(self.pid_file_path)

    def run_as_single_process(self):
        """Runs the agent as a single foreground process."""
        self.acquire_lock()
        try:
            asyncio.run(self.run_checks(print_output=True))
        except KeyboardInterrupt:
            print("\nAgent Smith interrupted. Exiting.")
        finally:
            if hasattr(self, 'lock_file'):
                self.lock_file.close()
            if os.path.exists(self.lock_file_path):
                os.remove(self.lock_file_path)


class AgentSmithLogger:
    """Configures and manages logging for Agent Smith."""

    def __init__(self, log_file, hostname):
        self.log_file = log_file
        self.hostname = hostname # Hostname passed directly
        self.logger = logging.getLogger('AgentSmith')
        self.logger.setLevel(logging.INFO)
        # Prevent adding multiple handlers if logger is re-initialized
        if not self.logger.handlers:
            formatter = logging.Formatter('%(asctime)s - %(hostname)s - %(message)s')
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def log_result(self, result):
        """Logs the result of a check."""
        # Custom logging with hostname. Using extra to pass custom fields
        # Result is already a dictionary: {'Category': ('STATUS', 'Message')}
        # or {'Category': {'disk_name': ('STATUS', 'Message'), ...}}
        
        log_message_parts = []
        for category, data in result.items():
            if isinstance(data, dict): # For DiskUsageCheck
                for item_name, (status, msg) in data.items():
                    log_message_parts.append(f"{category} ({item_name}) - {status}: {msg}")
            else: # For other checks
                status, msg = data
                log_message_parts.append(f"{category} - {status}: {msg}")
        
        self.logger.info(", ".join(log_message_parts), extra={'hostname': self.hostname})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent Smith Daemon")
    parser.add_argument("-d", "--daemonize", action="store_true",
                        help="Daemonize the process")
    parser.add_argument("-c", "--config", required=True,
                        help="Path to the configuration file (e.g., config.ini)")
    parser.add_argument("-g", "--generate-config", action="store_true",
                        help="Generate a default configuration file")
    args = parser.parse_args()

    if args.generate_config:
        config_gen = ConfigGenerator(args.config)
        config_gen.generate_and_write_config()
        print(f"Default configuration generated successfully at {args.config}")
    else:
        # Validate essential settings before proceeding
        validator = ConfigValidator(args.config)
        validator.validate_setting('Setting', 'pid_file_path', 'agent-smith.pid')
        validator.validate_setting('Setting', 'lock_file_path', 'agent-smith.lock')

        agent = AgentSmithEngine(args.config)

        # Add checks dynamically
        agent.add_check(LoadAverageCheck)
        agent.add_check(MemoryUsageCheck)
        agent.add_check(DiskUsageCheck)
        agent.add_check(NTPDriftCheck)
        agent.add_check(TCPCheck)

        if args.daemonize:
            print("Agent Smith daemon starting...")
            agent.run_as_daemon()
        else:
            print("Agent Smith starting in single process mode...")
            agent.run_as_single_process()
