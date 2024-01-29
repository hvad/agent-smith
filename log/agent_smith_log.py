#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import socket
import logging


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
