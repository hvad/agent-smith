#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autor(s):
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import ntplib


class NTPDriftCheck:
    """ Class to check NTP drift."""

    def __init__(self, config):
        self.ntp_pool_server = config.get('NTP', 'ntp_pool_server')
        self.warning_threshold = config.getfloat('NTP',
                                                 'ntp_warning_threshold')
        self.critical_threshold = config.getfloat('NTP',
                                                  'ntp_critical_threshold')

    def run(self):
        try:
            ntp_client = ntplib.NTPClient()
            response = ntp_client.request(self.ntp_pool_server, version=3)
            offset = response.offset
            if abs(offset) >= self.critical_threshold:
                return "NTP : CRITICAL", f"NTP Drift Alert: Offset={offset}"
            if abs(offset) >= self.warning_threshold:
                return "NTP : WARNING", f"NTP Drift Alert: Offset={offset}"
            return "NTP : OK", "NTP Drift within thresholds"
        except ntplib.NTPException:
            return "NTP : CRITICAL", f"NTP Pool server {self.ntp_pool_server} not reachable !"
