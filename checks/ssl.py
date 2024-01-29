#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Autor(s):
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2024-01-29

import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLCertificateCheck:
    """ Class to check certificate expiration date."""

    def __init__(self, config):
        self.certificate_file = config.get('Setting', 'certificate_file')
        self.warning_days = config.getint('Setting', 'ssl_warning_days')
        self.critical_days = config.getint('Setting', 'ssl_critical_days')

    def run(self):
        with open(self.certificate_file, 'rb') as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        expiration_date = cert.not_valid_after.date()
        days_until_expiry = (expiration_date - datetime.date.today()).days

        if days_until_expiry <= 0:
            return "CRITICAL", f"SSL Certificate Expired on {expiration_date}"
        if days_until_expiry <= self.critical_days:
            return "CRITICAL", f"SSL Certificate Expires in {days_until_expiry} days"
        if days_until_expiry <= self.warning_days:
            return "WARNING", f"SSL Certificate Expires in {days_until_expiry} days"
        return "OK", "SSL Certificate is Valid until {days_until_expiry} days"
