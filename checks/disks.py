#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autor(s):
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import psutil


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
