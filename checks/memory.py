#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autor(s):
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import psutil


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
