#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

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
