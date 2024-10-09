import re
import os
from functools import reduce


class Secret(object):
    likely_extensions = []
    regex_flags = [re.IGNORECASE]
    regex = ''

    def __init__(self, line, mimetype=None, filename=None):
        self.line = line
        self.mimetype = mimetype
        self.filename = filename
        self.confidence = 0
        self.match_result = None

    def description(self):
        """Must return a short string"""
        assert self.description
        return self.description

    def _get_confidence(self):
        """Must return an integer between 0 and 100 based on self.line

        0 means: nothing found. 100 means: certainly a password.
        """
        flags = reduce(lambda x, y: x | y, self.regex_flags)
        m = re.search(self.regex, self.line, flags=flags)
        if m:
            result = self.assess()
            self.match_result = m
            return result
        return 0

    def assess(self):
        # long lines are unlikely in scripts and configs
        result = 90
        if len(self.line) > 512:
            result -= 90
        _, ext = os.path.splitext(self.filename)
        if self.likely_extensions and \
           ext.lower() not in self.likely_extensions:
            result -= 20
        if 'data' in self.mimetype:
            result -= 20
        self.confidentiality = result
        return result

    def get_confidence(self):
        result = self._get_confidence()
        if result < 0:
            result = 0
        if result > 100:
            result = 100
        result = int(result)
        self.confidence = result
        return result

    def get_secret(self):
        if self.match_result:
            s =  self.match_result.groupdict().get('secret', '')
            return s if len(s) > 6 else f"\033[91mQUESTIONABLE\033[0m: {self.line}"
        return ""

    def get_line(self):
        if self.match_result:
            return self.match_result.group('secret').strip()
        return ""


class NetUser(Secret):
    description = "'net use' command in script"
    regex = r'net use.*/user.*'
    likely_extensions = ['.ps1', '.bat']


class RunAs(Secret):
    description = "'RunAs' command in script"
    regex = r'runas.*/user'
    likely_extensions = ['.ps1', '.bat']


class SecureString(Secret):
    description = "'ConvertTo-SecureString' command in script"
    regex = r'ConvertTo-SecureString'
    likely_extensions = ['.ps1', '.bat']


class PasswordConfig(Secret):
    description = "'password =' in config"
    regex = r'[a-z_\-\s]*(password|passphrase|pwd|passwd|secret)\s*=\s*(?P<secret>.*?)$'
    likely_extensions = ['.ini', '.conf', '.cnf', '.config', '.properties','.txt']

    def assess(self):
        # some common strings that cause false positive
        c = super().assess()
        if (
            'ShowPasswordDialog=' in self.get_line()
        ):
            c = 0
        return c


class PasswordJson(Secret):
    description = "'password' value in JSON file"
    regex = r'"[a-z_\-\s]*(password|pwd|passwd|secret)":"(?P<secret>.*?)"'
    likely_extensions = ['.json']

    def assess(self):
        # some strings in adml files on SYSVOL make it a sure false positive
        c = super().assess()
        if (
            'DisableChangePassword=' in self.get_line()
        ):
            c = 0
        return c


class PasswordYaml(Secret):
    description = "'password' value in YAML file"
    regex = r'[a-z_\-\s]*(password|passwd|secret):\s+(?P<secret>.*?)$'
    likely_extensions = ['.yaml', '.yml']

    def assess(self):
        # high likelihood of false positives
        c = super().assess()
        return c - 30


class PasswordXml(Secret):
    description = "'password' element in XML file"
    regex = r'<[a-z_\-]*(passwd|password|passphrase|secret)*>(?P<secret>[!<].*?)</'
    likely_extensions = ['.xml']

    def assess(self):
        result = 90
        _, ext = os.path.splitext(self.filename)
        if self.likely_extensions and \
           ext.lower() not in self.likely_extensions:
            result -= 20
        # cpassword very likely
        if "<cpassword>" in self.get_line():
            result = 95
        return result

class PasswordDocuments(Secret):
    description = "'password' in PDF,docx file"
    regex = r"[a-z_\-\s]*(password|passphrase|pwd|passwd|secret)[:|=|\s]+(?P<secret>\w+)"
    likely_extensions = ['.pdf', '.docx']

    def assess(self):
        result = 90
        _, ext = os.path.splitext(self.filename)
        if self.likely_extensions and \
           ext.lower() not in self.likely_extensions:
            result -= 20
        return result


class PrivateKey(Secret):
    description = 'private key'
    regex = r'----- BEGIN[A-Z ]+ PRIVATE KEY -----'
    likely_extensions = ['.pem', '.key']


class AwsSecrets(Secret):
    description = 'AWS secrets'
    regex = r'(aws_access_key_id|aws_secret_access_key)\s+=(?P<secret>.*?)'
    likely_extensions = ['.ini']


class EmpirumPassword(Secret):
    description = 'Empirum password'
    regex = r'_PASSWORD_(SETUP|EIS|SYNC)=(?P<secret>.*?)'
    likely_extensions = ['.ini']

    def assess(self):
        # high likelihood of false positives
        c = super().assess()
        c += 20
        return c
