#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import argparse
from core.agent_smith_engine import AgentSmithEngine
from checks.load import LoadAverageCheck
from checks.memory import MemoryUsageCheck
from checks.disks import DiskUsageCheck

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
        agent.run_checks()

    agent.remove_pid_file()
