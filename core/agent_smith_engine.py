#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import sys
import os
import time
import configparser
from log.agent_smith_log import AgentSmithLogger
from alert.smtp import SMTPAlert


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

    def run_as_daemon(self):
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
