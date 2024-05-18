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
import threading
import asyncio
import smtplib
from configparser import ConfigParser
from contextlib import closing
from email.message import EmailMessage
import configparser
import ntplib
import psutil
import schedule


class SMTPAlert:
    """SMTP Alert."""

    def __init__(self, config):
        self.smtp_server = config.get('Email', 'smtp_server')
        self.smtp_port = config.getint('Email', 'smtp_port')
        self.sender_email = config.get('Email', 'sender_email')
        self.receiver_email = config.get('Email', 'receiver_email')
        self.smtp_username = config.get('Email', 'smtp_username')
        self.smtp_password = config.get('Email', 'smtp_password')

    def send_alert(self, subject, body):
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email

        try:
            if self.smtp_username and self.smtp_password:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
                server.ehlo()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
                server.quit()
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
                server.ehlo()
                server.send_message(msg)
                server.quit()
        except Exception as error:
            print(f"An error occurred while sending the email: {error}")


class NTPDriftCheck:
    """ Class to check NTP drift."""

    def __init__(self, config):
        self.ntp_pool_server = config.get('Ntp', 'ntp_pool_server')
        self.warning_threshold = config.getfloat('Ntp',
                                                 'ntp_warning_threshold')
        self.critical_threshold = config.getfloat('Ntp',
                                                  'ntp_critical_threshold')
        self.result = None

    def check_ntp_drift(self):
        try:
            ntp_client = ntplib.NTPClient()
            response = ntp_client.request(self.ntp_pool_server, version=3)
            offset = response.offset
            time = str(int(abs(offset)))
            if abs(offset) >= self.critical_threshold:
                self.result = "NTP", "CRITICAL", f"NTP Drift Alert: Offset = {time}"
            elif abs(offset) >= self.warning_threshold:
                self.result = "NTP", "WARNING", f"NTP Drift Alert: Offset = {time}"
            else:
                self.result = "NTP", "OK", f"NTP Drift within thresholds: Offset = {time}"
        except ntplib.NTPException:
            self.result = "NTP", "CRITICAL", f"NTP Pool server {self.ntp_pool_server} not reachable !"

    def run(self):
        thread = threading.Thread(target=self.check_ntp_drift)
        thread.start()
        thread.join()
        return self.result


class TCPCheck:
    """ Class to check tcp/ip port is open."""

    def __init__(self, config):
        self.hostname = config.get('System', 'hostname')
        self.port = config.getint('System', 'port')
        self.timeout = config.getint('System', 'timeout')
        self.result = None

    def check_tcp(self):
        try:
            with closing(socket.socket(socket.AF_INET,
                                       socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.hostname, self.port)) == 0:
                    self.result = "Firewall", "OK", f"Port {self.port} is open"
                else:
                    self.result = "Firewall", "CRITICAL", f"Port {self.port} is closed"
        except Exception as error:
            self.result = "Firewall", "CRITICAL", f"Error firewall: {str(error)}"

    def run(self):
        thread = threading.Thread(target=self.check_tcp)
        thread.start()
        thread.join()
        return self.result


class DiskUsageCheck:
    """ Disks usage check."""

    def __init__(self, config):
        self.disks = self.read_config(config)
        self.warning_threshold = config.getint('System',
                                               'disk_warning_threshold')
        self.critical_threshold = config.getint('System',
                                                'disk_critical_threshold')
        self.result = None

    def read_config(self, config):
        disks = config.get('System', 'disks').split(',')
        formatted_disks = {}
        for disk in disks:
            formatted_disks[f'disk_{disk.strip()}'] = None
        return formatted_disks

    def bytes2human(self, n):
        symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
        prefix = {}
        for i, s in enumerate(symbols):
            prefix[s] = 1 << (i + 1) * 10
        for s in reversed(symbols):
            if n >= prefix[s]:
                value = float(n) / prefix[s]
                return f"{value:.2f} {s}B"
        return f"{n} B"

    def check_disk_usage(self):
        disk_usages = {}
        for disk, _ in self.disks.items():
            disk_name = disk.split('_')[
                1]  # Extracting the partition name from the key
            disk_usage = psutil.disk_usage(disk_name)
            disk_total = self.bytes2human(disk_usage.total)
            disk_used = self.bytes2human(disk_usage.used)
            disk_free = self.bytes2human(disk_usage.free)
            if disk_usage.percent >= self.critical_threshold:
                usage_status = "CRITICAL "
            elif disk_usage.percent >= self.warning_threshold:
                usage_status = "WARNING "
            else:
                usage_status = "OK "
            usage_info = usage_status, f"Total = {disk_total} Used = {disk_used} Free = {disk_free}"
            disk_usages[disk] = usage_info
        self.result = disk_usages

    def run(self):
        thread = threading.Thread(target=self.check_disk_usage)
        thread.start()
        thread.join()
        return self.result


class MemoryUsageCheck:
    """ Class to check memory usage."""

    def __init__(self, config):
        self.warning_threshold = config.getfloat('System',
                                                 'memory_warning_threshold')
        self.critical_threshold = config.getfloat('System',
                                                  'memory_critical_threshold')
        self.result = None

    def check_memory(self):
        memory_info = psutil.virtual_memory()
        memory_percent = memory_info.percent
        if memory_percent >= self.critical_threshold:
            self.result = "Memory Usage", "CRITICAL", f"Memory Usage is {memory_percent}%"
        elif memory_percent >= self.warning_threshold:
            self.result = "Memory Usage", "WARNING", f"Memory Usage is {memory_percent}%"
        else:
            self.result = "Memory Usage", "OK", f"Memory Usage is {memory_percent}%"

    def run(self):
        thread = threading.Thread(target=self.check_memory)
        thread.start()
        thread.join()
        return self.result


class LoadAverageCheck:
    """Check load_average for 1, 5, and 15 minutes."""

    def __init__(self, config):
        self.warning_threshold = self.read_config(
            config, 'load_average_warning_threshold')
        self.critical_threshold = self.read_config(
            config, 'load_average_critical_threshold')
        self.result = None

    def read_config(self, config, option):
        return config.getfloat('System', option)

    def check_load_average(self):
        load_average = psutil.getloadavg()
        if load_average[0] > self.critical_threshold:
            self.result = "Load", "CRITICAL", f"1 min={load_average[0]}, 5 min={load_average[1]}, 15 min={load_average[2]}"
        elif load_average[0] > self.warning_threshold:
            self.result = "Load", "WARNING", f"1 min={load_average[0]}, 5 min={load_average[1]}, 15 min={load_average[2]}"
        else:
            self.result = "Load", "OK", f"1 min={load_average[0]}, 5 min={load_average[1]}, 15 min={load_average[2]}"

    def run(self):
        thread = threading.Thread(target=self.check_load_average)
        thread.start()
        thread.join()
        return self.result


class ConfigValidator:
    """ Validate configuration file class."""

    def __init__(self, config_file):
        self.config = ConfigParser()
        self.config.read(config_file)

    def validate_setting(self, section, key, expected_value):
        actual_value = self.config.get(section, key)
        if actual_value != expected_value:
            print(
                f"Validation failed for {section}.{key}. Expected: {expected_value}, Actual: {actual_value}"
            )
            sys.exit(1)


class ConfigGenerator:
    """ Generate configuration file."""

    def __init__(self, filename):
        self.filename = filename
        self.settings = {
            'period': 60,
            'log_file_path': 'agent-smith.log',
            'pid_file_path': 'agent-smith.pid',
            'lock_file_path': 'agent-smith.lock',
            'loadaveragecheck': True,
            'memoryusagecheck': True,
            'diskusagecheck': True,
            'ntpdriftcheck': False,
            'tcpcheck': False
        }
        self.system = {
            'hostname': self.get_hostname(),
            'load_average_warning_threshold': 16,
            'load_average_critical_threshold': 24,
            'disks': ', '.join(self.get_disks_name()),
            'disk_warning_threshold': 90,
            'disk_critical_threshold': 95,
            'memory_warning_threshold': 85,
            'memory_critical_threshold': 95,
            'port': 443,
            'timeout': 5
        }
        self.ntp = {
            'ntp_pool_server': '',
            'ntp_warning_threshold': 1,
            'ntp_critical_threshold': 3
        }
        self.email = {
            'smtp_server': '',
            'smtp_port': 25,
            'sender_email': '',
            'receiver_email': '',
            'smtp_username': '',
            'smtp_password': ''
        }
        self.alerts = {
            'loadaveragecheck': False,
            'memoryusagecheck': False,
            'diskusagecheck': False,
            'ntpdriftcheck': False,
            'tcpcheck': False
        }

    def get_hostname(self):
        try:
            return socket.gethostname()
        except socket.error:
            return 'localhost'  # Default to localhost if hostname detection fails

    def get_full_hostname(self):
        try:
            return socket.getfqdn()
        except socket.error:
            return 'localhost'  # Default to localhost if hostname detection fails

    def get_disks_name(self):
        excluded_fs_types = ['tmpfs']
        exclude_partition_names = ['/run']
        partitions = psutil.disk_partitions(all=False)
        disks = [
            p.mountpoint for p in partitions
            if p.fstype not in excluded_fs_types
            and p.mountpoint not in exclude_partition_names
        ]
        return disks

    def generate_config(self):
        sections = {
            'Setting': self.settings,
            'System': self.system,
            'Ntp': self.ntp,
            'Email': self.email,
            'Alerts': self.alerts
        }

        config = ''
        for section, values in sections.items():
            config += f"[{section}]\n"
            for key, value in values.items():
                config += f"{key} = {value}\n"
            config += "\n"
        return config

    def write_config_file(self, config):
        with open(self.filename, 'w') as file:
            file.write(config)


class AgentSmithEngine:
    """Agent Smith Engine class."""

    def __init__(self, config_file):
        self.checks = []
        self.disabled_checks = []
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.log_file_path = self.config.get('Setting',
                                             'log_file_path',
                                             fallback=None)
        self.pid_file_path = self.config.get('Setting',
                                             'pid_file_path',
                                             fallback=None)
        self.hostname = self.config.get('System', 'hostname', fallback=None)
        self.disks = self.config.get('System', 'disks', fallback=None)
        self.email_alert = SMTPAlert(self.config)
        self.alerts_config = self.config['Alerts']
        self.lock_file_path = self.config.get('Setting',
                                              'lock_file_path',
                                              fallback=None)
        self.config_file_path = config_file
        self.result_logger = AgentSmithLogger(self.log_file_path,
                                              self.config_file_path)

    def add_check(self, check_class):
        check_name = check_class.__name__.lower()
        enabled = self.config.getboolean('Setting', check_name, fallback=True)
        if enabled:
            self.checks.append(check_class(self.config))
        else:
            self.disabled_checks.append(check_class(self.config))

    def run_checks(self, print_output=False):

        def run_check_and_log(check):
            if check in self.disabled_checks:
                return
            result = check.run()
            self.result_logger.log_result(result)
            if print_output:
                print(f"Output result: {result}")
            if hasattr(
                    self, 'enable_maintenance'
            ) and self.enable_maintenance and not self.is_maintenance_time():
                self._handle_alerts(check, result)

        for check in self.checks:
            schedule.every(int(self.config['Setting']['period'])).seconds.do(
                run_check_and_log, check)

        while True:
            schedule.run_pending()
            time.sleep(1)

    def _handle_alerts(self, check, result):
        check_name = check.__class__.__name__.lower()
        if check_name in self.alerts_config and self.alerts_config.getboolean(
                check_name):
            for check_result in result.values():
                if "CRITICAL" in check_result or "WARNING" in check_result:
                    self.email_alert.send_alert(
                        f"{check.__class__.__name__} Alert", check_result)

    def acquire_lock(self):
        try:
            self.lock_file = open(self.lock_file_path, 'w')
            fcntl.flock(
                self.lock_file, fcntl.LOCK_EX |
                fcntl.LOCK_NB)  # Try to acquire an exclusive non-blocking lock
        except IOError:
            print("Another instance is already running. Exiting.")
            sys.exit(1)

    def run_as_daemon(self):
        self.acquire_lock()
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as err:
            sys.stderr.write(f"_Fork #1 failed: {err}")
            sys.exit(1)
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as err:
            sys.stderr.write(f"_Fork #2 failed: {err}")
            sys.exit(1)
        """ Redirect standard file descriptors."""
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r', encoding="utf-8")
        so = open(os.devnull, 'a+', encoding="utf-8")
        se = open(os.devnull, 'a+', encoding="utf-8")

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        self.write_pid_file()
        self.run_checks()

    def write_pid_file(self):
        if self.pid_file_path:
            pid = str(os.getpid())
            with open(self.pid_file_path, 'w', encoding="utf-8") as pid_file:
                pid_file.write(pid)

    def remove_pid_file(self):
        if self.pid_file_path and os.path.exists(self.pid_file_path):
            os.remove(self.pid_file_path)

    def run_as_single_process(self):
        self.acquire_lock()  # Acquire the lock before running the process
        try:
            self.run_checks()
        finally:
            self.lock_file.close()
            os.remove(self.lock_file_path)


class AgentSmithLogger:
    """Log class."""

    def __init__(self, log_file, config_file):
        self.log_file = log_file
        self.config_file = config_file
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(hostname)s - %(message)s')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def get_hostname_from_config(self):
        config = configparser.ConfigParser()
        config.read(self.config_file)
        hostname = config.get('System', 'hostname')
        return hostname

    def log_result(self, result):
        hostname = self.get_hostname_from_config()
        result_str = str(result)
        result_str = result_str.replace('{', '(').replace('}', ')')
        self.logger.info(result_str, extra={'hostname': hostname})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent Smith Daemon")
    parser.add_argument("-d",
                        "--daemonize",
                        action="store_true",
                        help="Daemonize the process")
    parser.add_argument("-c",
                        "--config",
                        required=True,
                        default="config.ini",
                        help="Path to the configuration file")
    parser.add_argument("-g",
                        "--generate_config",
                        action="store_true",
                        help="Generate configuration file")
    args = parser.parse_args()

    if args.generate_config and args.config:
        config_gen = ConfigGenerator(args.config)
        config_file = config_gen.generate_config()
        config_gen.write_config_file(config_file)
        print(f"Configuration generated successfully using {args.config}")
    elif args.generate_config and not args.config:
        print(
            "Error : Configuration file path is required to generate configuration."
        )
        sys.exit(1)
    else:

        validator = ConfigValidator(args.config)
        validator.validate_setting('Setting', 'pid_file_path',
                                   'agent-smith.pid')
        validator.validate_setting('Setting', 'lock_file_path',
                                   'agent-smith.lock')

        agent = AgentSmithEngine(args.config)

        checks = [
            DiskUsageCheck, LoadAverageCheck, NTPDriftCheck, MemoryUsageCheck,
            TCPCheck
        ]
        for check in checks:
            agent.add_check(check)

        if args.daemonize:
            print("Agent Smith deamon started...")
            agent.run_as_daemon()
        else:
            print("Agent Smith started...")
            agent.run_as_single_process()
