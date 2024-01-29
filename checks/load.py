#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autor(s):
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import os


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
