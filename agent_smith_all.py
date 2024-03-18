#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import sys
import os
import fcntl
import time
import configparser
import argparse
import socket
import logging
import psutil
import smtplib
from email.message import EmailMessage


class SMTPAlert:
    """ SMTP Alert."""

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

        with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as smtp:
            smtp.login(self.smtp_username, self.smtp_password)
            smtp.send_message(msg)

class DiskUsageCheck:
    """ Disks usage check."""

    def __init__(self, config):
        self.disks = self.read_config(config)
        self.warning_threshold = config.getint('Setting',
                                               'disk_warning_threshold')
        self.critical_threshold = config.getint('Setting',
                                                'disk_critical_threshold')

    def read_config(self, config):
        disks = config.get('Setting', 'disks').split(',')
        return [disk.strip() for disk in disks]

    def run(self):
        disk_usages = {}
        for disk in self.disks:
            disk_usage = psutil.disk_usage(disk)
            usage_info = f"Disk Usage: Total = {disk_usage.total}B, Used = {disk_usage.used}B, Free = {disk_usage.free}B"
            if disk_usage.percent >= self.critical_threshold:
                usage_info += " - CRITICAL"
            elif disk_usage.percent >= self.warning_threshold:
                usage_info += " - WARNING"
            disk_usages[disk] = usage_info
        return disk_usages

class MemoryUsageCheck:
    """ Class to check memory usage."""

    def __init__(self, config):
        self.warning_threshold = config.getfloat('Setting',
                                                 'memory_warning_threshold')
        self.critical_threshold = config.getfloat('Setting',
                                                  'memory_critical_threshold')

    def run(self):
        memory_info = psutil.virtual_memory()
        memory_percent = memory_info.percent
        if memory_percent >= self.critical_threshold:
            return "CRITICAL", f"Memory Usage is {memory_percent}%"
        elif memory_percent >= self.warning_threshold:
            return "WARNING", f"Memory Usage is {memory_percent}%"
        else:
            return "OK", f"Memory Usage is {memory_percent}%"

class LoadAverageCheck:
    """ Check load_average for 1, 5 and 15 minutes."""

    def __init__(self, config):
        self.warning_threshold = self.read_config(
            config, 'load_average_warning_threshold')
        self.critical_threshold = self.read_config(
            config, 'load_average_critical_threshold')

    def read_config(self, config, option):
        return config.getfloat('Setting', option)

    def run(self):
        load_average = os.getloadavg()
        status = "OK"
        if load_average[0] > self.critical_threshold:
            status = "CRITICAL"
        elif load_average[0] > self.warning_threshold:
            status = "WARNING"
        return f"Load : {status} 1 min={load_average[0]}, 5 min={load_average[1]}, 15 min={load_average[2]}"

#class LoadAverageCheck:
#    """ Check load_average for 1, 5 and 15 minutes."""
#
#    def __init__(self, config):
#        self.warning_threshold = config.getfloat('Setting', 'load_average_warning_threshold')
#        self.critical_threshold = config.getfloat('Setting', 'load_average_critical_threshold')
#
#    def run(self):
#        load_average = psutil.getloadavg()
#        load_info = f"Load Average: 1 min={load_average[0]}, 5 min={load_average[1]}, 15 min={load_average[2]}"
#        if load_average[0] >= self.critical_threshold or load_average[1] >= self.critical_threshold or load_average[2] >= self.critical_threshold:
#            load_info += " - CRITICAL"
#        elif load_average[0] >= self.warning_threshold or load_average[1] >= self.warning_threshold or load_average[2] >= self.warning_threshold:
#            load_info += " - WARNING"
#        return load_info


class AgentSmithLogger:
    """ Log Class for checks."""

    def __init__(self, log_file):
        self.log_file = log_file
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(hostname)s - %(message)s')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log_result(self, result):
        hostname = socket.gethostname()
        self.logger.info(result, extra={'hostname': hostname})

class AgentSmithEngine:
    """ Agent Smith Engine class."""

    def __init__(self, config_file):
        self.checks = []
        self.disabled_checks = []
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.log_file_path = self.config.get('Setting', 'log_file_path')
        self.result_logger = AgentSmithLogger(self.log_file_path)
        self.pid_file_path = self.config.get('Setting',
                                             'pid_file_path',
                                             fallback=None)
        self.email_alert = SMTPAlert(self.config)
        self.alerts_config = self.config['Alerts']
        self.lock_file_path = self.config.get('Setting', 'lock_file_path')

    def add_check(self, check_class):
        check_name = check_class.__name__.lower()
        enabled = self.config.getboolean('Setting', check_name, fallback=True)
        if enabled:
            self.checks.append(check_class(self.config))
        else:
            self.disabled_checks.append(check_class(self.config))

    def run_checks(self, print_output=False):
        while True:
            for check in self.checks:
                if check in self.disabled_checks:
                    continue
                result = check.run()
                self.result_logger.log_result(result)
                if print_output:
                    print(result)
                check_name = check.__class__.__name__.lower()
                if check_name in self.alerts_config and self.alerts_config.getboolean(
                        check_name):
                    for check_result in result.values():
                        if "CRITICAL" in check_result or "WARNING" in check_result:
                            self.email_alert.send_alert(
                                f"{check.__class__.__name__} Alert",
                                check_result)

            time.sleep(int(self.config['Setting']['check_period']))

    def acquire_lock(self):
        try:
            self.lock_file = open(self.lock_file_path, 'w')
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)  # Try to acquire an exclusive non-blocking lock
        except IOError:
            print("Another instance of Agent Smith is already running. Exiting.")
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

    def get_check_class(self, check_name):
        check_name = check_name.lower()
        for check_class in self.checks + self.disabled_checks:
            if check_class.__name__.lower() == check_name:
                return check_class
        return None

    def run_as_single_process(self):
        self.acquire_lock()  # Acquire the lock before running the process
        try:
            self.run_checks()
        finally:
            self.lock_file.close()
            os.remove(self.lock_file_path)  # Remove the lock file when the process finishes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Agent Smith Daemon")
    parser.add_argument("-d",
                        "--daemonize",
                        action="store_true",
                        help="Daemonize the process")
    parser.add_argument("-c",
                        "--config",
                        required=True,
                        default="agent_smith.ini",
                        help="Path to the configuration file")
    args = parser.parse_args()

    agent = AgentSmithEngine(args.config)

    checks = [
        DiskUsageCheck, LoadAverageCheck, MemoryUsageCheck
    ]
    for check in checks:
        agent.add_check(check)

    if args.daemonize:
        print("Agent Smith deamon started...")
        agent.run_as_daemon()
    else:
        print("Agent Smith started...")
        agent.run_as_single_process()

    agent.remove_pid_file()
