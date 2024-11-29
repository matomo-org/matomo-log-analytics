#!/usr/bin/python
# vim: et sw=4 ts=4:
# -*- coding: utf-8 -*-
#
# Matomo - free/libre analytics platform
#
# @link https://matomo.org
# @license https://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
# @version $Id$
#
# For more info see: https://matomo.org/log-analytics/ and https://matomo.org/docs/log-analytics-tool-how-to/
#
# Requires Python 3.5, 3.6 or 3.7
#
from __future__ import print_function  # this is needed that python2 can run the script until the warning below

import sys

if sys.version_info[0] != 3:
    print('The log importer currently does not support Python 2 any more.')
    print('Please use Python 3.5, 3.6, 3.7 or 3.8')
    sys.exit(1)

import base64
import bz2
import configparser
import codecs
import datetime
import fnmatch
import gzip
import hashlib
import http.client
import inspect
import itertools
import json
import logging
import argparse
import os
import os.path
import queue
import re
import ssl
import sys
import threading
import time
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import urllib.parse
import subprocess
import traceback
import socket
import textwrap
import collections
import glob
import io

# Avoid "got more than 100 headers" error
http.client._MAXHEADERS = 1000

##
## Constants.
##

STATIC_EXTENSIONS = set((
    'gif jpg jpeg png bmp ico svg svgz ttf otf eot woff woff2 class swf css js xml webp avif'
).split())

STATIC_FILES = set((
    'robots.txt'
).split())

DOWNLOAD_EXTENSIONS = set((
    '7z aac arc arj asf asx avi bin csv deb dmg doc docx exe flac flv gz gzip hqx '
    'ibooks jar json mpg mp2 mp3 mp4 mpeg mov movie msi msp odb odf odg odp '
    'ods odt ogg ogv pdf phps ppt pptx qt qtm ra ram rar rpm rtf sea sit tar tbz '
    'bz2 tbz tgz torrent txt wav webm wma wmv wpd xls xlsx xml xsd z zip '
    'azw3 epub mobi apk '
    'md5 sig'
).split())

# If you want to add more bots, take a look at the Matomo Device Detector botlist:
# https://github.com/matomo-org/device-detector/blob/master/regexes/bots.yml
# user agents must be lowercase
EXCLUDED_USER_AGENTS = (
    'adsbot-google',
    'ask jeeves',
    'baidubot',
    'bot-',
    'bot/',
    'ccooter/',
    'crawl',
    'curl',
    'echoping',
    'exabot',
    'feed',
    'googlebot',
    'ia_archiver',
    'java/',
    'libwww',
    'mediapartners-google',
    'msnbot',
    'netcraftsurvey',
    'panopta',
    'pingdom.com_bot_',
    'robot',
    'spider',
    'surveybot',
    'twiceler',
    'voilabot',
    'yahoo',
    'yandex',
    'zabbix',
    'googlestackdrivermonitoring',
)

MATOMO_DEFAULT_MAX_ATTEMPTS = 3
MATOMO_DEFAULT_DELAY_AFTER_FAILURE = 10
DEFAULT_SOCKET_TIMEOUT = 300

MATOMO_EXPECTED_IMAGE = base64.b64decode(
    'R0lGODlhAQABAIAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=='
)

##
## Formats.
##

class BaseFormatException(Exception): pass

class BaseFormat:
    def __init__(self, name):
        self.name = name
        self.regex = None
        self.date_format = '%d/%b/%Y:%H:%M:%S'

    def check_format(self, file):
        line = file.readline()
        try:
            file.seek(0)
        except IOError:
            pass

        return self.check_format_line(line)

    def check_format_line(self, line):
        return False

class NginxJsonFormat(BaseFormat):
    def __init__(self, name):
        super(NginxJsonFormat, self).__init__(name)
        self.json = None
        self.date_format = '%Y-%m-%dT%H:%M:%S'

    def check_format_line(self, line):
        try:
            self.json = json.loads(line)
        
            # Check if it contains these: "referrer" and date".
            # Those are currently not used in other detected json formats, so it should be enough
            if "referrer" in self.json and "date" in self.json:
                return True
        
            return False
        except:
            return False

    def match(self, line):
        try:
            # nginx outputs malformed JSON w/ hex escapes when confronted w/ non-UTF input. we have to
            # workaround this by converting hex escapes in strings to unicode escapes. the conversion is naive,
            # so it does not take into account the string's actual encoding (which we don't have access to).
            line = line.replace('\\x', '\\u00')

            self.json = json.loads(line)
            return self
        except:
            self.json = None
            return None

    def get(self, key):
        # Some ugly patchs ...
        if key == 'generation_time_milli':
            self.json[key] =  int(float(self.json[key]) * 1000)
        # Patch date format ISO 8601
        elif key == 'date':
            tz = self.json[key][19:]
            self.json['timezone'] = tz.replace(':', '')
            self.json[key] = self.json[key][:19]

        try:
            return self.json[key]
        except KeyError:
            raise BaseFormatException()
    
    def get_all(self,):
        return self.json

    def remove_ignored_groups(self, groups):
        for group in groups:
            del self.json[group]

class TraefikJsonFormat(BaseFormat):

    TRAEFIK_KEYS_MAPPING = {
        'date': 'time',
        'generation_time_milli': 'Duration',
        'host': 'RequestHost',
        'ip': 'ClientHost',
        'length': 'DownstreamContentSize',
        'method': 'RequestMethod',
        'path': 'RequestPath',
        'referrer': 'request_Referer',
        'status': 'DownstreamStatus',
        'userid': 'ClientUsername',
        'user_agent': 'request_User-Agent',
    }

    def __init__(self, name):
        super(TraefikJsonFormat, self).__init__(name)
        self.json = None
        self.date_format = '%Y-%m-%dT%H:%M:%S'
        
    def check_format_line(self, line):
        try:
            self.json = json.loads(line)

            # Check if it contains all of these: "level", "msg", and "time".
            # This is unique to Traefik, we can use this to tell it apart from other json log formats.
            if "msg" in self.json and "level" in self.json and "time" in self.json:
                return True
        
            return False
        except:
            return False
        
    def match(self, line):
        try:
            self.json = json.loads(line)
            return self
        except:
            self.json = None
            return None

    def get(self, key):

        value = ''
        try:
            value = self.json[self.TRAEFIK_KEYS_MAPPING[key]]
            
            if key == 'generation_time_milli':
                value = value / 1000000
        
            # Patch date format ISO 8601, example: 2023-08-14T12:25:56+02:00
            if key == 'date':
                tz = value[19:] # get the last part
                self.json['timezone'] = tz.replace(':', '')
                value = value[:19]

        except:
            logging.debug("Could not find %s in Traefik log", key)
            return ''

        return str(value)  
    
    def get_all(self,):
        modified_json = self.json.copy()
        
        REVERSED_KEYS_MAPPING = {v: k for k, v in self.TRAEFIK_KEYS_MAPPING.items()}

        for key in self.json:
            new_key = REVERSED_KEYS_MAPPING.get(key, key)
            if new_key != key:
                modified_json[new_key] = modified_json.pop(key)
        
        return modified_json

    def remove_ignored_groups(self, groups):
        for group in groups:
            del self.json[group]

class CaddyJsonFormat(BaseFormat):
    def __init__(self, name):
        super(CaddyJsonFormat, self).__init__(name)
        self.json = None
        self.date_format = '%Y-%m-%dT%H:%M:%S.%f'
        
    def check_format_line(self, line):
        try:
            self.json = json.loads(line)
            return "request" in self.json and "user_id" in self.json and "resp_headers" in self.json
        except:
            return False
        
    def match(self, line):
        try:
            self.json = json.loads(line)
            return self
        except:
            self.json = None
            return None

    def get(self, key):
        try:
            return self.get_all().get(key)
        except KeyError:
            raise BaseFormatException()
    
    def get_all(self,):
        tz = datetime.timezone.utc
        date = datetime.datetime.fromtimestamp(self.json['ts'], tz=tz)
        self.json['date'] = date.strftime(self.date_format)
        self.json['timezone'] = date.strftime('%z')
        self.json['length'] = str(self.json['size'])
        self.json['status'] = str(self.json['status'])
        self.json['generation_time_milli'] = str(self.json['duration'] * 1000.)
        self.json['userid'] = self.json['user_id']
        self.json['ip'] = self.json['request']['client_ip']
        self.json['host'] = self.json['request']['host']
        self.json['method'] = self.json['request']['method']
        self.json['path'] = self.json['request']['uri']
        self.json['referrer'] = next(iter(self.json['request']['headers'].get('Referer', [])), None)
        self.json['user_agent'] = next(iter(self.json['request']['headers'].get('User-Agent', [])), None)
        return self.json

    def remove_ignored_groups(self, groups):
        for group in groups:
            del self.json[group]

class RegexFormat(BaseFormat):

    def __init__(self, name, regex, date_format=None):
        super(RegexFormat, self).__init__(name)
        if regex is not None:
            self.regex = re.compile(regex)
        if date_format is not None:
            self.date_format = date_format
        self.matched = None

    def check_format_line(self, line):
        return self.match(line)

    def match(self,line):
        if not self.regex:
            return None
        match_result = self.regex.match(line)
        if match_result:
            self.matched = match_result.groupdict()
            if 'time' in self.matched:
                self.matched['date'] = self.matched['date'] + ' ' + self.matched['time']
                del self.matched['time']
        else:
            self.matched = None
        return match_result

    def get(self, key):
        try:
            return self.matched[key]
        except KeyError:
            raise BaseFormatException("Cannot find group '%s'." % key)

    def get_all(self,):
        return self.matched

    def remove_ignored_groups(self, groups):
        for group in groups:
            del self.matched[group]

class W3cExtendedFormat(RegexFormat):

    FIELDS_LINE_PREFIX = '#Fields: '
    REGEX_UNKNOWN_FIELD = r'(?:".*?"|\S+)'

    fields = {
        'date': r'"?(?P<date>\d+[-\d+]+)"?',
        'time': r'"?(?P<time>[\d+:]+)[.\d]*?"?',
        'cs-uri-stem': r'(?P<path>/\S*)',
        'cs-uri-query': r'(?P<query_string>\S*)',
        'c-ip': r'"?(?P<ip>[\w*.:-]*)"?',
        'cs(User-Agent)': r'(?P<user_agent>".*?"|\S*)',
        'cs(Referer)': r'(?P<referrer>\S+)',
        'sc-status': r'(?P<status>\d+)',
        'sc-bytes': r'(?P<length>\S+)',
        'cs-host': r'(?P<host>\S+)',
        'cs-method': r'(?P<method>\S+)',
        'cs-username': r'(?P<userid>\S+)',
        'time-taken': r'(?P<generation_time_secs>[.\d]+)'
    }

    def __init__(self):
        super(W3cExtendedFormat, self).__init__('w3c_extended', None, '%Y-%m-%d %H:%M:%S')

    def check_format(self, file):
        try:
            file.seek(0)
        except IOError:
            pass

        self.create_regex(file)

        # if we couldn't create a regex, this file does not follow the W3C extended log file format
        if not self.regex:
            try:
                file.seek(0)
            except IOError:
                pass

            return

        first_line = file.readline()

        try:
            file.seek(0)
        except IOError:
            pass

        return self.check_format_line(first_line)

    def create_regex(self, file):
        fields_line = None
        if config.options.w3c_fields:
            fields_line = config.options.w3c_fields

        # collect all header lines up until the Fields: line
        # if we're reading from stdin, we can't seek, so don't read any more than the Fields line
        header_lines = []
        while fields_line is None:
            line = file.readline().strip()

            if not line:
                continue

            if not line.startswith('#'):
                break

            if line.startswith(self.FIELDS_LINE_PREFIX):
                fields_line = line
            else:
                header_lines.append(line)

        if not fields_line:
            return

        # store the header lines for a later check for IIS
        self.header_lines = header_lines

        # Parse the 'Fields: ' line to create the regex to use
        full_regex = []

        expected_fields = type(self).fields.copy() # turn custom field mapping into field => regex mapping

        # if the --w3c-time-taken-millisecs option is used, make sure the time-taken field is interpreted as milliseconds
        if config.options.w3c_time_taken_in_millisecs:
            expected_fields['time-taken'] = r'(?P<generation_time_milli>[\d.]+)'

        for mapped_field_name, field_name in config.options.custom_w3c_fields.items():
            expected_fields[mapped_field_name] = expected_fields[field_name]
            del expected_fields[field_name]

        # add custom field regexes supplied through --w3c-field-regex option
        for field_name, field_regex in config.options.w3c_field_regexes.items():
            expected_fields[field_name] = field_regex

        # Skip the 'Fields: ' prefix.
        fields_line = fields_line[9:].strip()
        for field in re.split(r'\s+', fields_line):
            try:
                regex = expected_fields[field]
            except KeyError:
                regex = self.REGEX_UNKNOWN_FIELD
            full_regex.append(regex)
        full_regex = r'\s+'.join(full_regex)

        logging.debug("Based on 'Fields:' line, computed regex to be %s", full_regex)

        self.regex = re.compile(full_regex)

    def check_for_iis_option(self):
        if not config.options.w3c_time_taken_in_millisecs and self._is_time_taken_milli() and self._is_iis():
            logging.info("WARNING: IIS log file being parsed without --w3c-time-taken-milli option. IIS"
                         " stores millisecond values in the time-taken field. If your logfile does this, the aforementioned"
                         " option must be used in order to get accurate generation times.")

    def _is_iis(self):
        return len([line for line in self.header_lines if 'internet information services' in line.lower() or 'iis' in line.lower()]) > 0

    def _is_time_taken_milli(self):
        return 'generation_time_milli' not in self.regex.pattern

class IisFormat(W3cExtendedFormat):

    fields = W3cExtendedFormat.fields.copy()
    fields.update({
        'time-taken': r'(?P<generation_time_milli>[.\d]+)',
        'sc-win32-status': r'(?P<__win32_status>\S+)' # this group is useless for log importing, but capturing it
                                                     # will ensure we always select IIS for the format instead of
                                                     # W3C logs when detecting the format. This way there will be
                                                     # less accidental importing of IIS logs w/o --w3c-time-taken-milli.
    })

    def __init__(self):
        super(IisFormat, self).__init__()

        self.name = 'iis'

class IncapsulaW3CFormat(W3cExtendedFormat):

    # use custom unknown field regex to make resulting regex much simpler
    REGEX_UNKNOWN_FIELD = r'".*?"'

    fields = W3cExtendedFormat.fields.copy()
    # redefines all fields as they are always encapsulated with "
    fields.update({
        'cs-uri': r'"(?P<host>[^\/\s]+)(?P<path>\S+)"',
        'cs-uri-query': r'"(?P<query_string>\S*)"',
        'c-ip': r'"(?P<ip>[\w*.:-]*)"',
        'cs(User-Agent)': r'"(?P<user_agent>.*?)"',
        'cs(Referer)': r'"(?P<referrer>\S+)"',
        'sc-status': r'(?P<status>"\d*")',
        'cs-bytes': r'(?P<length>"\d*")',
    })

    def __init__(self):
        super(IncapsulaW3CFormat, self).__init__()

        self.name = 'incapsula_w3c'

    def get(self, key):
        value = super(IncapsulaW3CFormat, self).get(key)
        if key == 'status' or key == 'length':
            value = value.strip('"')
        if key == 'status' and value == '':
            value = '200'
        return value

class ShoutcastFormat(W3cExtendedFormat):

    fields = W3cExtendedFormat.fields.copy()
    fields.update({
        'c-status': r'(?P<status>\d+)',
        'x-duration': r'(?P<generation_time_secs>[.\d]+)'
    })

    def __init__(self):
        super(ShoutcastFormat, self).__init__()

        self.name = 'shoutcast'

    def get(self, key):
        if key == 'user_agent':
            user_agent = super(ShoutcastFormat, self).get(key)
            return urllib.parse.unquote(user_agent)
        else:
            return super(ShoutcastFormat, self).get(key)

class AmazonCloudFrontFormat(W3cExtendedFormat):

    fields = W3cExtendedFormat.fields.copy()
    fields.update({
        'x-event': r'(?P<event_action>\S+)',
        'x-sname': r'(?P<event_name>\S+)',
        'cs-uri-stem': r'(?:rtmp:/)?(?P<path>/\S*)',
        'c-user-agent': r'(?P<user_agent>".*?"|\S+)',

        # following are present to match cloudfront instead of W3C when we know it's cloudfront
        'x-edge-location': r'(?P<x_edge_location>".*?"|\S+)',
        'x-edge-result-type': r'(?P<x_edge_result_type>".*?"|\S+)',
        'x-edge-request-id': r'(?P<x_edge_request_id>".*?"|\S+)',
        'x-host-header': r'(?P<host>".*?"|\S+)'
    })

    def __init__(self):
        super(AmazonCloudFrontFormat, self).__init__()

        self.name = 'amazon_cloudfront'

    def get(self, key):
        if key == 'event_category' and 'event_category' not in self.matched:
            return 'cloudfront_rtmp'
        elif key == 'status' and 'status' not in self.matched:
            return '200'
        elif key == 'user_agent':
            user_agent = super(AmazonCloudFrontFormat, self).get(key)
            return urllib.parse.unquote(urllib.parse.unquote(user_agent))  # Value is double quoted!
        else:
            return super(AmazonCloudFrontFormat, self).get(key)

_HOST_PREFIX = r'(?P<host>[\w\-\.]*)(?::\d+)?\s+'

_COMMON_LOG_FORMAT = (
    r'(?P<ip>[\w*.:-]+)\s+\S+\s+(?P<userid>\S+)\s+\[(?P<date>.*?)\s+(?P<timezone>.*?)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>.*?)\s+\S+"\s+(?P<status>\d+)\s+(?P<length>\S+)'
)
_NCSA_EXTENDED_LOG_FORMAT = (_COMMON_LOG_FORMAT +
    r'\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'
)


_S3_LOG_FORMAT = (
    r'\S+\s+(?P<host>\S+)\s+\[(?P<date>.*?)\s+(?P<timezone>.*?)\]\s+(?P<ip>[\w*.:-]+)\s+'
    r'(?P<userid>\S+)\s+\S+\s+\S+\s+\S+\s+"(?P<method>\S+)\s+(?P<path>.*?)\s+\S+"\s+(?P<status>\d+)\s+\S+\s+(?P<length>\S+)\s+'
    r'\S+\s+\S+\s+\S+\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'
)
_ICECAST2_LOG_FORMAT = ( _NCSA_EXTENDED_LOG_FORMAT +
    r'\s+(?P<session_time>[0-9-]+)'
)
_ELB_LOG_FORMAT = (
    r'(?:\S+\s+)?(?P<date>[0-9-]+T[0-9:]+)\.\S+\s+\S+\s+(?P<ip>[\w*.:-]+):\d+\s+\S+:\d+\s+\S+\s+(?P<generation_time_secs>\S+)\s+\S+\s+'
    r'(?P<status>\d+)\s+\S+\s+\S+\s+(?P<length>\S+)\s+'
    r'"\S+\s+\w+:\/\/(?P<host>[\w\-\.]*):\d+(?P<path>\/\S*)\s+[^"]+"\s+"(?P<user_agent>[^"]+)"\s+\S+\s+\S+'
)

_OVH_FORMAT = (
    r'(?P<ip>\S+)\s+' + _HOST_PREFIX + r'(?P<userid>\S+)\s+\[(?P<date>.*?)\s+(?P<timezone>.*?)\]\s+'
    r'"\S+\s+(?P<path>.*?)\s+\S+"\s+(?P<status>\S+)\s+(?P<length>\S+)'
    r'\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'
)

_HAPROXY_FORMAT = (
    r'.*:\ (?P<ip>[\w*.]+).*\[(?P<date>.*)\].*\ (?P<status>\b\d{3}\b)\ (?P<length>\d+)\ -.*\"(?P<method>\S+)\ (?P<path>\S+).*'
)

_GANDI_SIMPLE_HOSTING_FORMAT = (
    r'(?P<host>[0-9a-zA-Z-_.]+)\s+(?P<ip>[a-zA-Z0-9.]+)\s+\S+\s+(?P<userid>\S+)\s+\[(?P<date>.+?)\s+(?P<timezone>.+?)\]\s+\((?P<generation_time_secs>[0-9a-zA-Z\s]*)\)\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(\S+)"\s+(?P<status>[0-9]+)\s+(?P<length>\S+)\s+"(?P<referrer>\S+)"\s+"(?P<user_agent>[^"]+)"'
)

FORMATS = {
    'common': RegexFormat('common', _COMMON_LOG_FORMAT),
    'common_vhost': RegexFormat('common_vhost', _HOST_PREFIX + _COMMON_LOG_FORMAT),
    'ncsa_extended': RegexFormat('ncsa_extended', _NCSA_EXTENDED_LOG_FORMAT),
    'common_complete': RegexFormat('common_complete', _HOST_PREFIX + _NCSA_EXTENDED_LOG_FORMAT),
    'w3c_extended': W3cExtendedFormat(),
    'amazon_cloudfront': AmazonCloudFrontFormat(),
    'incapsula_w3c': IncapsulaW3CFormat(),
    'iis': IisFormat(),
    'shoutcast': ShoutcastFormat(),
    's3': RegexFormat('s3', _S3_LOG_FORMAT),
    'icecast2': RegexFormat('icecast2', _ICECAST2_LOG_FORMAT),
    'elb': RegexFormat('elb', _ELB_LOG_FORMAT, '%Y-%m-%dT%H:%M:%S'),
    'traefik_json': TraefikJsonFormat('traefik_json'),
    'nginx_json': NginxJsonFormat('nginx_json'),
    'caddy_json': CaddyJsonFormat('caddy_json'),
    'ovh': RegexFormat('ovh', _OVH_FORMAT),
    'haproxy': RegexFormat('haproxy', _HAPROXY_FORMAT, '%d/%b/%Y:%H:%M:%S.%f'),
    'gandi': RegexFormat('gandi', _GANDI_SIMPLE_HOSTING_FORMAT, '%d/%b/%Y:%H:%M:%S')
}

##
## Code.
##

class StoreDictKeyPair(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        my_dict = getattr(namespace, self.dest, None)
        if not my_dict:
            my_dict = {}
        for kv in values.split(","):
            k,v = kv.split("=")
            my_dict[k] = v
        setattr(namespace, self.dest, my_dict)

class Configuration:
    """
    Stores all the configuration options by reading sys.argv and parsing,
    if needed, the config.inc.php.

    It has 2 attributes: options and filenames.
    """

    class Error(Exception):
        pass

    def _create_parser(self):
        """
        Initialize and return the OptionParser instance.
        """
        parser = argparse.ArgumentParser(
            # usage='Usage: %prog [options] log_file [ log_file [...] ]',
            description="Import HTTP access logs to Matomo. "
                         "log_file is the path to a server access log file (uncompressed, .gz, .bz2, or specify - to read from stdin). "
                         " You may also import many log files at once (for example set log_file to *.log or *.log.gz)."
                         " By default, the script will try to produce clean reports and will exclude bots, static files, discard http error and redirects, etc. This is customizable, see below.",
            epilog="About Matomo Server Log Analytics: https://matomo.org/log-analytics/ "
                   "              Found a bug? Please create a ticket in https://github.com/matomo-org/matomo-log-analytics/ "
                   "              Please send your suggestions or successful user story to hello@matomo.org "
        )

        parser.add_argument('file', type=str, nargs='+')

        # Basic auth user
        parser.add_argument(
            '--auth-user', dest='auth_user',
            help="Basic auth user",
        )
        # Basic auth password
        parser.add_argument(
            '--auth-password', dest='auth_password',
            help="Basic auth password",
        )
        parser.add_argument(
            '--debug', '-d', dest='debug', action='count', default=0,
            help="Enable debug output (specify multiple times for more verbose)",
        )
        parser.add_argument(
            '--debug-tracker', dest='debug_tracker', action='store_true', default=False,
            help="Appends &debug=1 to tracker requests and prints out the result so the tracker can be debugged. If "
            "using the log importer results in errors with the tracker or improperly recorded visits, this option can "
            "be used to find out what the tracker is doing wrong. To see debug tracker output, you must also set the "
            "[Tracker] debug_on_demand INI config to 1 in your Matomo's config.ini.php file."
        )
        parser.add_argument(
            '--debug-request-limit', dest='debug_request_limit', type=int, default=None,
            help="Debug option that will exit after N requests are parsed. Can be used w/ --debug-tracker to limit the "
            "output of a large log file."
        )
        parser.add_argument(
            '--url', dest='matomo_url', required=True,
            help="REQUIRED Your Matomo server URL, eg. https://example.com/matomo/ or https://analytics.example.net",
        )
        parser.add_argument(
            '--api-url', dest='matomo_api_url',
            help="This URL will be used to send API requests (use it if your tracker URL differs from UI/API url), "
            "eg. https://other-example.com/matomo/ or https://analytics-api.example.net",
        )
        parser.add_argument(
            '--tracker-endpoint-path', dest='matomo_tracker_endpoint_path', default='/piwik.php',
            help="The tracker endpoint path to use when tracking. Defaults to /piwik.php."
        )
        parser.add_argument(
            '--dry-run', dest='dry_run',
            action='store_true', default=False,
            help="Perform a trial run with no tracking data being inserted into Matomo",
        )
        parser.add_argument(
            '--show-progress', dest='show_progress',
            action='store_true', default=hasattr(sys.stdout, 'fileno') and os.isatty(sys.stdout.fileno()),
            help="Print a progress report X seconds (default: 1, use --show-progress-delay to override)"
        )
        parser.add_argument(
            '--show-progress-delay', dest='show_progress_delay',
            type=int, default=1,
            help="Change the default progress delay"
        )
        parser.add_argument(
            '--add-sites-new-hosts', dest='add_sites_new_hosts',
            action='store_true', default=False,
            help="When a hostname is found in the log file, but not matched to any website "
            "in Matomo, automatically create a new website in Matomo with this hostname to "
            "import the logs"
        )
        parser.add_argument(
            '--idsite', dest='site_id',
            help= ("When specified, "
                   "data in the specified log files will be tracked for this Matomo site ID."
                   " The script will not auto-detect the website based on the log line hostname (new websites will not be automatically created).")
        )
        parser.add_argument(
            '--idsite-fallback', dest='site_id_fallback',
            help="Default Matomo site ID to use if the hostname doesn't match any "
            "known Website's URL. New websites will not be automatically created. "
            "                         Used only if --add-sites-new-hosts or --idsite are not set",
        )
        default_config = os.path.abspath(
            os.path.join(os.path.dirname(__file__),
            '../../config/config.ini.php'),
        )
        parser.add_argument(
            '--config', dest='config_file', default=default_config,
            help=(
                "This is only used when --login and --password is not used. "
                "Matomo will read the configuration file (default: %(default)s) to "
                "fetch the Super User token_auth from the config file. "
            )
        )
        parser.add_argument(
            '--login', dest='login',
            help="You can manually specify the Matomo Super User login"
        )
        parser.add_argument(
            '--password', dest='password',
            help="You can manually specify the Matomo Super User password"
        )
        parser.add_argument(
            '--token-auth', dest='matomo_token_auth',
            help="Matomo user token_auth, the token_auth is found in Matomo > Settings > API. "
                 "You must use a token_auth that has at least 'admin' or 'super user' permission. "
                 "If you use a token_auth for a non admin user, your users' IP addresses will not be tracked properly. "
        )

        parser.add_argument(
            '--hostname', dest='hostnames', action='append', default=[],
            help="Accepted hostname (requests with other hostnames will be excluded). "
            " You may use the star character * "
            " Example: --hostname=*domain.com"
            " Can be specified multiple times"
        )
        parser.add_argument(
            '--exclude-path', dest='excluded_paths', action='append', default=[],
            help="Any URL path matching this exclude-path will not be imported in Matomo. "
            " You must use the star character *. "
            " Example: --exclude-path=*/admin/*"
            " Can be specified multiple times. "
        )
        parser.add_argument(
            '--exclude-path-from', dest='exclude_path_from',
            help="Each line from this file is a path to exclude. Each path must contain the character * to match a string. (see: --exclude-path)"
        )
        parser.add_argument(
            '--include-path', dest='included_paths', action='append', default=[],
            help="Paths to include. Can be specified multiple times. If not specified, all paths are included."
        )
        parser.add_argument(
            '--include-path-from', dest='include_path_from',
            help="Each line from this file is a path to include"
        )
        parser.add_argument(
            '--useragent-exclude', dest='excluded_useragents',
            action='append', default=[],
            help="User agents to exclude (in addition to the standard excluded "
            "user agents). Can be specified multiple times",
        )
        parser.add_argument(
            '--enable-static', dest='enable_static',
            action='store_true', default=False,
            help="Track static files (images, css, js, ico, ttf, etc.)"
        )
        parser.add_argument(
            '--enable-bots', dest='enable_bots',
            action='store_true', default=False,
            help="Track bots. All bot visits will have a Custom Variable set with name='Bot' and value='$Bot_user_agent_here$'"
        )
        parser.add_argument(
            '--enable-http-errors', dest='enable_http_errors',
            action='store_true', default=False,
            help="Track HTTP errors (status code 4xx or 5xx)"
        )
        parser.add_argument(
            '--enable-http-redirects', dest='enable_http_redirects',
            action='store_true', default=False,
            help="Track HTTP redirects (status code 3xx except 304)"
        )
        parser.add_argument(
            '--enable-reverse-dns', dest='reverse_dns',
            action='store_true', default=False,
            help="Enable reverse DNS, used to generate the 'Providers' report in Matomo. "
                 "Disabled by default, as it impacts performance"
        )
        parser.add_argument(
            '--strip-query-string', dest='strip_query_string',
            action='store_true', default=False,
            help="Strip the query string from the URL"
        )
        parser.add_argument(
            '--query-string-delimiter', dest='query_string_delimiter', default='?',
            help="The query string delimiter (default: %(default)s)"
        )
        parser.add_argument(
            '--log-format-name', dest='log_format_name', default=None,
            help=("Access log format to detect (supported are: %s). "
                  "When not specified, the log format will be autodetected by trying all supported log formats."
                  % ', '.join(sorted(FORMATS.keys())))
        )
        available_regex_groups = ['date', 'path', 'query_string', 'ip', 'user_agent', 'referrer', 'status',
                                  'length', 'host', 'userid', 'generation_time_milli', 'event_action',
                                  'event_name', 'timezone', 'session_time']
        parser.add_argument(
            '--log-format-regex', dest='log_format_regex', default=None,
            help="Regular expression used to parse log entries. Regexes must contain named groups for different log fields. "
                 "Recognized fields include: %s. For an example of a supported Regex, see the source code of this file. "
                 "Overrides --log-format-name." % (', '.join(available_regex_groups))
        )
        parser.add_argument(
            '--log-date-format', dest='log_date_format', default=None,
            help="Format string used to parse dates. You can specify any format that can also be specified to "
                 "the strptime python function."
        )
        parser.add_argument(
            '--log-hostname', dest='log_hostname', default=None,
            help="Force this hostname for a log format that doesn't include it. All hits "
            "will seem to come to this host"
        )
        parser.add_argument(
            '--skip', dest='skip', default=0, type=int,
            help="Skip the n first lines to start parsing/importing data at a given line for the specified log file",
        )
        parser.add_argument(
            '--recorders', dest='recorders', default=1, type=int,
            help="Number of simultaneous recorders (default: %(default)s). "
            "It should be set to the number of CPU cores in your server. "
            "You can also experiment with higher values which may increase performance until a certain point",
        )
        parser.add_argument(
            '--recorder-max-payload-size', dest='recorder_max_payload_size', default=200, type=int,
            help="Maximum number of log entries to record in one tracking request (default: %(default)s). "
        )
        parser.add_argument(
            '--replay-tracking', dest='replay_tracking',
            action='store_true', default=False,
            help="Replay piwik.php requests found in custom logs (only piwik.php requests expected). \nSee https://matomo.org/faq/how-to/faq_17033/"
        )
        parser.add_argument(
            '--replay-tracking-expected-tracker-file', dest='replay_tracking_expected_tracker_file', default=None,
            help="The expected suffix for tracking request paths. Only logs whose paths end with this will be imported. By default "
            "requests to the piwik.php file or the matomo.php file will be imported."
        )
        parser.add_argument(
            '--output', dest='output',
            help="Redirect output (stdout and stderr) to the specified file"
        )
        parser.add_argument(
            '--encoding', dest='encoding', default='utf8',
            help="Log files encoding (default: %(default)s)"
        )
        parser.add_argument(
            '--disable-bulk-tracking', dest='use_bulk_tracking',
            default=True, action='store_false',
            help="Disables use of bulk tracking so recorders record one hit at a time."
        )
        parser.add_argument(
            '--debug-force-one-hit-every-Ns', dest='force_one_action_interval', default=False, type=float,
            help="Debug option that will force each recorder to record one hit every N secs."
        )
        parser.add_argument(
            '--force-lowercase-path', dest='force_lowercase_path', default=False, action='store_true',
            help="Make URL path lowercase so paths with the same letters but different cases are "
                 "treated the same."
        )
        parser.add_argument(
            '--enable-testmode', dest='enable_testmode', default=False, action='store_true',
            help="If set, it will try to get the token_auth from the matomo_tests directory"
        )
        parser.add_argument(
            '--download-extensions', dest='download_extensions', default=None,
            help="By default Matomo tracks as Downloads the most popular file extensions. If you set this parameter (format: pdf,doc,...) then files with an extension found in the list will be imported as Downloads, other file extensions downloads will be skipped."
        )
        parser.add_argument(
            '--add-download-extensions', dest='extra_download_extensions', default=None,
            help="Add extensions that should be treated as downloads. See --download-extensions for more info."
        )
        parser.add_argument(
            '--w3c-map-field', action=StoreDictKeyPair, metavar='KEY=VAL', default={}, dest="custom_w3c_fields",
            help="Map a custom log entry field in your W3C log to a default one. Use this option to load custom log "
                 "files that use the W3C extended log format such as those from the Advanced Logging W3C module. Used "
                 "as, eg, --w3c-map-field my-date=date. Recognized default fields include: %s\n\n"
                 "Formats that extend the W3C extended log format (like the cloudfront RTMP log format) may define more "
                 "fields that can be mapped."
                     % (', '.join(list(W3cExtendedFormat.fields.keys())))
        )
        parser.add_argument(
            '--w3c-time-taken-millisecs', action='store_true', default=False, dest='w3c_time_taken_in_millisecs',
            help="If set, interprets the time-taken W3C log field as a number of milliseconds. This must be set for importing"
                 " IIS logs."
        )
        parser.add_argument(
            '--w3c-fields', dest='w3c_fields', default=None,
            help="Specify the '#Fields:' line for a log file in the W3C Extended log file format. Use this option if "
                 "your log file doesn't contain the '#Fields:' line which is required for parsing. This option must be used "
                 "in conjunction with --log-format-name=w3c_extended.\n"
                 "Example: --w3c-fields='#Fields: date time c-ip ...'"
        )
        parser.add_argument(
            '--w3c-field-regex', action=StoreDictKeyPair, metavar='KEY=VAL', default={}, dest="w3c_field_regexes", type=str,
            help="Specify a regex for a field in your W3C extended log file. You can use this option to parse fields the "
                 "importer does not natively recognize and then use one of the --regex-group-to-XXX-cvar options to track "
                 "the field in a custom variable. For example, specifying --w3c-field-regex=sc-win32-status=(?P<win32_status>\\S+) "
                 "--regex-group-to-page-cvar=\"win32_status=Windows Status Code\" will track the sc-win32-status IIS field "
                 "in the 'Windows Status Code' custom variable. Regexes must contain a named group."
        )
        parser.add_argument(
            '--title-category-delimiter', dest='title_category_delimiter', default='/',
            help="If --enable-http-errors is used, errors are shown in the page titles report. If you have "
            "changed General.action_title_category_delimiter in your Matomo configuration, you need to set this "
            "option to the same value in order to get a pretty page titles report."
        )
        parser.add_argument(
            '--dump-log-regex', dest='dump_log_regex', action='store_true', default=False,
            help="Prints out the regex string used to parse log lines and exists. Can be useful for using formats "
                 "in newer versions of the script in older versions of the script. The output regex can be used with "
                 "the --log-format-regex option."
        )

        parser.add_argument(
            '--ignore-groups', dest='regex_groups_to_ignore', default=None,
            help="Comma separated list of regex groups to ignore when parsing log lines. Can be used to, for example, "
                 "disable normal user id tracking. See documentation for --log-format-regex for list of available "
                 "regex groups."
        )

        parser.add_argument(
            '--regex-group-to-visit-cvar', action=StoreDictKeyPair, metavar='KEY=VAL',dest='regex_group_to_visit_cvars_map', default={},
            help="Track an attribute through a custom variable with visit scope instead of through Matomo's normal "
                 "approach. For example, to track usernames as a custom variable instead of through the uid tracking "
                 "parameter, supply --regex-group-to-visit-cvar=\"userid=User Name\". This will track usernames in a "
                 "custom variable named 'User Name'. The list of available regex groups can be found in the documentation "
                 "for --log-format-regex (additional regex groups you may have defined "
                 "in --log-format-regex can also be used)."
        )
        parser.add_argument(
            '--regex-group-to-page-cvar', action=StoreDictKeyPair, metavar='KEY=VAL', dest='regex_group_to_page_cvars_map', default={},
            help="Track an attribute through a custom variable with page scope instead of through Matomo's normal "
                 "approach. For example, to track usernames as a custom variable instead of through the uid tracking "
                 "parameter, supply --regex-group-to-page-cvar=\"userid=User Name\". This will track usernames in a "
                 "custom variable named 'User Name'. The list of available regex groups can be found in the documentation "
                 "for --log-format-regex (additional regex groups you may have defined "
                 "in --log-format-regex can also be used)."
        )
        parser.add_argument(
            '--track-http-method', dest='track_http_method', default=False,
            help="Enables tracking of http method as custom page variable if method group is available in log format."
        )
        parser.add_argument(
            '--retry-max-attempts', dest='max_attempts', default=MATOMO_DEFAULT_MAX_ATTEMPTS, type=int,
            help="The maximum number of times to retry a failed tracking request."
        )
        parser.add_argument(
            '--retry-delay', dest='delay_after_failure', default=MATOMO_DEFAULT_DELAY_AFTER_FAILURE, type=int,
            help="The number of seconds to wait before retrying a failed tracking request."
        )
        parser.add_argument(
            '--request-timeout', dest='request_timeout', default=DEFAULT_SOCKET_TIMEOUT, type=int,
            help="The maximum number of seconds to wait before terminating an HTTP request to Matomo."
        )
        parser.add_argument(
            '--include-host', action='append', type=str,
            help="Only import logs from the specified host(s)."
        )
        parser.add_argument(
            '--exclude-host', action='append', type=str,
            help="Only import logs that are not from the specified host(s)."
        )
        parser.add_argument(
            '--exclude-older-than', type=self._valid_date, default=None,
            help="Ignore logs older than the specified date. Exclusive. Date format must be YYYY-MM-DD hh:mm:ss +/-0000. The timezone offset is required."
        )
        parser.add_argument(
            '--exclude-newer-than', type=self._valid_date, default=None,
            help="Ignore logs newer than the specified date. Exclusive. Date format must be YYYY-MM-DD hh:mm:ss +/-0000. The timezone offset is required."
        )
        parser.add_argument(
            '--add-to-date', dest='seconds_to_add_to_date', default=0, type=int,
            help="A number of seconds to add to each date value in the log file."
        )
        parser.add_argument(
            '--request-suffix', dest='request_suffix', default=None, type=str, help="Extra parameters to append to tracker and API requests."
        )
        parser.add_argument(
            '--accept-invalid-ssl-certificate',
            dest='accept_invalid_ssl_certificate', action='store_true',
            default=False,
            help="Do not verify the SSL / TLS certificate when contacting the Matomo server."
        )
        parser.add_argument(
            '--php-binary', dest='php_binary', type=str, default='php',
            help="Specify the PHP binary to use.",
        )
        return parser

    def _valid_date(self, value):
        try:
            (date_str, timezone) = value.rsplit(' ', 1)
        except:
            raise argparse.ArgumentTypeError("Invalid date value '%s'." % value)

        if not re.match('[-+][0-9]{4}', timezone):
            raise argparse.ArgumentTypeError("Invalid date value '%s': expected valid timzeone like +0100 or -1200, got '%s'" % (value, timezone))

        date = datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        date -= TimeHelper.timedelta_from_timezone(timezone)

        return date

    def _parse_args(self, option_parser, argv = None):
        """
        Parse the command line args and create self.options and self.filenames.
        """
        if not argv:
            argv = sys.argv[1:]

        self.options = option_parser.parse_args(argv)
        self.filenames = self.options.file

        if self.options.output:
            sys.stdout = sys.stderr = open(self.options.output, 'a')

        all_filenames = []
        for self.filename in self.filenames:
            if self.filename == '-':
                all_filenames.append(self.filename)
            else:
                all_filenames = all_filenames + sorted(glob.glob(self.filename))
        self.filenames = all_filenames

        # Configure logging before calling logging.{debug,info}.
        logging.basicConfig(
            format='%(asctime)s: [%(levelname)s] %(message)s',
            level=logging.DEBUG if self.options.debug >= 1 else logging.INFO,
        )

        self.options.excluded_useragents = set([s.lower() for s in self.options.excluded_useragents])

        if self.options.exclude_path_from:
            paths = [path.strip() for path in open(self.options.exclude_path_from).readlines()]
            self.options.excluded_paths.extend(path for path in paths if len(path) > 0)
        if self.options.excluded_paths:
            self.options.excluded_paths = set(self.options.excluded_paths)
            logging.debug('Excluded paths: %s', ' '.join(self.options.excluded_paths))

        if self.options.include_path_from:
            paths = [path.strip() for path in open(self.options.include_path_from).readlines()]
            self.options.included_paths.extend(path for path in paths if len(path) > 0)
        if self.options.included_paths:
            self.options.included_paths = set(self.options.included_paths)
            logging.debug('Included paths: %s', ' '.join(self.options.included_paths))

        if self.options.hostnames:
            logging.debug('Accepted hostnames: %s', ', '.join(self.options.hostnames))
        else:
            logging.debug('Accepted hostnames: all')

        if self.options.log_format_regex:
            self.format = RegexFormat('custom', self.options.log_format_regex, self.options.log_date_format)
        elif self.options.log_format_name:
            try:
                self.format = FORMATS[self.options.log_format_name]
            except KeyError:
                fatal_error('invalid log format: %s' % self.options.log_format_name)
        else:
            self.format = None

        if not hasattr(self.options, 'custom_w3c_fields'):
            self.options.custom_w3c_fields = {}
        elif self.format is not None:
            # validate custom field mappings
            for dummy_custom_name, default_name in self.options.custom_w3c_fields.items():
                if default_name not in type(format).fields:
                    fatal_error("custom W3C field mapping error: don't know how to parse and use the '%s' field" % default_name)
                    return

        if hasattr(self.options, 'w3c_field_regexes'):
            # make sure each custom w3c field regex has a named group
            for field_name, field_regex in self.options.w3c_field_regexes.items():
                if '(?P<' not in field_regex:
                    fatal_error("cannot find named group in custom w3c field regex '%s' for field '%s'" % (field_regex, field_name))
                    return


        if not (self.options.matomo_url.startswith('http://') or self.options.matomo_url.startswith('https://')):
            self.options.matomo_url = 'http://' + self.options.matomo_url
        logging.debug('Matomo Tracker API URL is: %s', self.options.matomo_url)

        if not self.options.matomo_api_url:
            self.options.matomo_api_url = self.options.matomo_url

        if not (self.options.matomo_api_url.startswith('http://') or self.options.matomo_api_url.startswith('https://')):
            self.options.matomo_api_url = 'http://' + self.options.matomo_api_url
        logging.debug('Matomo Analytics API URL is: %s', self.options.matomo_api_url)

        if self.options.recorders < 1:
            self.options.recorders = 1

        download_extensions = DOWNLOAD_EXTENSIONS
        if self.options.download_extensions:
            download_extensions = set(self.options.download_extensions.split(','))

        if self.options.extra_download_extensions:
            download_extensions.update(self.options.extra_download_extensions.split(','))
        self.options.download_extensions = download_extensions

        if self.options.regex_groups_to_ignore:
            self.options.regex_groups_to_ignore = set(self.options.regex_groups_to_ignore.split(','))

    def __init__(self, argv = None):
        self._parse_args(self._create_parser(), argv)

    def _get_token_auth(self):
        """
        If the token auth is not specified in the options, get it from Matomo.
        """
        # Get superuser login/password from the options.
        logging.debug('No token-auth specified')

        if self.options.login and self.options.password:
            matomo_login = self.options.login
            matomo_password = self.options.password

            logging.debug('Using credentials: (login = %s, using password = %s)', matomo_login, 'YES' if matomo_password else 'NO')
            try:
                api_result = matomo.call_api('UsersManager.createAppSpecificTokenAuth',
                    userLogin=matomo_login,
                    passwordConfirmation=matomo_password,
                    description='Log importer',
                    expireHours='48',
                    _token_auth='',
                    _url=self.options.matomo_api_url,
                )
            except urllib.error.URLError as e:
                fatal_error('error when fetching token_auth from the API: %s' % e)

            try:
                return api_result['value']
            except KeyError:
                # Happens when the credentials are invalid.
                message = api_result.get('message')
                fatal_error(
                    'error fetching authentication token token_auth%s' % (
                    ': %s' % message if message else '')
                )
        else:
            # Fallback to the given (or default) configuration file, then
            # get the token from the API.
            logging.debug(
                'No credentials specified, reading them from "%s"',
                self.options.config_file,
            )
            config_file = configparser.RawConfigParser(strict=False)
            success = len(config_file.read(self.options.config_file)) > 0
            if not success:
                fatal_error(
                    "the configuration file" + self.options.config_file + " could not be read. Please check permission. This file must be readable by the user running this script to get the authentication token"
                )

            updatetokenfile = os.path.abspath(
                os.path.join(self.options.config_file,
                    '../../misc/cron/updatetoken.php'),
            )

            phpBinary = config.options.php_binary

            # Special handling for windows (only if given php binary does not differ from default)
            is_windows = sys.platform.startswith('win')
            if phpBinary == 'php' and is_windows:
                try:
                    processWin = subprocess.Popen('where php.exe', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    [stdout, stderr] = processWin.communicate()
                    if processWin.returncode == 0:
                        phpBinary = stdout.strip()
                    else:
                        fatal_error("We couldn't detect PHP. It might help to add your php.exe to the path or alternatively run the importer using the --login and --password option")
                except:
                    fatal_error("We couldn't detect PHP. You can run the importer using the --login and --password option to fix this issue")

            command = [phpBinary, updatetokenfile]
            if self.options.enable_testmode:
                command.append('--testmode')

            hostname = urllib.parse.urlparse( self.options.matomo_url ).hostname
            command.append('--matomo-domain=' + hostname )

            command = subprocess.list2cmdline(command)

#            logging.debug(command);

            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            [stdout, stderr] = process.communicate()
            stdout, stderr = stdout.decode(), stderr.decode()
            if process.returncode != 0:
                fatal_error("`" + command + "` failed with error: " + stderr + ".\nReponse code was: " + str(process.returncode) + ". You can alternatively run the importer using the --login and --password option")

            filename = stdout
            credentials = open(filename, 'r').readline()
            credentials = credentials.split('\t')
            return credentials[1]

    def get_resolver(self):
        if self.options.site_id:
            logging.debug('Resolver: static')
            return StaticResolver(self.options.site_id)
        else:
            logging.debug('Resolver: dynamic')
            return DynamicResolver()

    def init_token_auth(self):
        if not self.options.matomo_token_auth:
            try:
                self.options.matomo_token_auth = self._get_token_auth()
            except MatomoHttpBase.Error as e:
                fatal_error(e)
        logging.debug('Authentication token token_auth is: %s', self.options.matomo_token_auth)


class Statistics:
    """
    Store statistics about parsed logs and recorded entries.
    Can optionally print statistics on standard output every second.
    """

    class Counter:
        """
        Simple integers cannot be used by multithreaded programs. See:
        https://stackoverflow.com/questions/6320107/are-python-ints-thread-safe
        """
        def __init__(self):
            # itertools.count's implementation in C does not release the GIL and
            # therefore is thread-safe.
            self.counter = itertools.count(1)
            self.value = 0

        def increment(self):
            self.value = next(self.counter)

        def advance(self, n):
            for i in range(n):
                self.increment()

        def __str__(self):
            return str(int(self.value))

    def __init__(self):
        self.time_start = None
        self.time_stop = None

        self.matomo_sites = set()                # sites ID
        self.matomo_sites_created = []           # (hostname, site ID)
        self.matomo_sites_ignored = set()        # hostname

        self.count_lines_parsed = self.Counter()
        self.count_lines_recorded = self.Counter()

        # requests that the Matomo tracker considered invalid (or failed to track)
        self.invalid_lines = []

        # Do not match the regexp.
        self.count_lines_invalid = self.Counter()
        # Were filtered out.
        self.count_lines_filtered = self.Counter()
        # No site ID found by the resolver.
        self.count_lines_no_site = self.Counter()
        # Hostname filtered by config.options.hostnames
        self.count_lines_hostname_skipped = self.Counter()
        # Static files.
        self.count_lines_static = self.Counter()
        # Ignored user-agents.
        self.count_lines_skipped_user_agent = self.Counter()
        # Ignored HTTP errors.
        self.count_lines_skipped_http_errors = self.Counter()
        # Ignored HTTP redirects.
        self.count_lines_skipped_http_redirects = self.Counter()
        # Downloads
        self.count_lines_downloads = self.Counter()
        # Ignored downloads when --download-extensions is used
        self.count_lines_skipped_downloads = self.Counter()

        # Misc
        self.dates_recorded = set()
        self.monitor_stop = False

    def set_time_start(self):
        self.time_start = time.time()

    def set_time_stop(self):
        self.time_stop = time.time()

    def _compute_speed(self, value, start, end):
        delta_time = end - start
        if value == 0:
            return 0
        if delta_time == 0:
            return 'very high!'
        else:
            return value / delta_time

    def _round_value(self, value, base=100):
        return round(value * base) / base

    def _indent_text(self, lines, level=1):
        """
        Return an indented text. 'lines' can be a list of lines or a single
        line (as a string). One level of indentation is 4 spaces.
        """
        prefix = ' ' * (4 * level)
        if isinstance(lines, str):
            return prefix + lines
        else:
            return '\n'.join(
                prefix + line
                for line in lines
            )

    def print_summary(self):
        invalid_lines_summary = ''
        if self.invalid_lines:
            invalid_lines_summary = '''Invalid log lines
-----------------

The following lines were not tracked by Matomo, either due to a malformed tracker request or error in the tracker:

%s

''' % textwrap.fill(", ".join(self.invalid_lines), 80)

        print(('''
%(invalid_lines)sLogs import summary
-------------------

    %(count_lines_recorded)d requests imported successfully
    %(count_lines_downloads)d requests were downloads
    %(total_lines_ignored)d requests ignored:
        %(count_lines_skipped_http_errors)d HTTP errors
        %(count_lines_skipped_http_redirects)d HTTP redirects
        %(count_lines_invalid)d invalid log lines
        %(count_lines_filtered)d filtered log lines
        %(count_lines_no_site)d requests did not match any known site
        %(count_lines_hostname_skipped)d requests did not match any --hostname
        %(count_lines_skipped_user_agent)d requests done by bots, search engines...
        %(count_lines_static)d requests to static resources (css, js, images, ico, ttf...)
        %(count_lines_skipped_downloads)d requests to file downloads did not match any --download-extensions

Website import summary
----------------------

    %(count_lines_recorded)d requests imported to %(total_sites)d sites
        %(total_sites_existing)d sites already existed
        %(total_sites_created)d sites were created:
%(sites_created)s
    %(total_sites_ignored)d distinct hostnames did not match any existing site:
%(sites_ignored)s
%(sites_ignored_tips)s

Performance summary
-------------------

    Total time: %(total_time)d seconds
    Requests imported per second: %(speed_recording)s requests per second

Processing your log data
------------------------

    In order for your logs to be processed by Matomo, you may need to run the following command:
     ./console core:archive --force-all-websites --url='%(url)s'
''' % {

    'count_lines_recorded': self.count_lines_recorded.value,
    'count_lines_downloads': self.count_lines_downloads.value,
    'total_lines_ignored': sum([
            self.count_lines_invalid.value,
            self.count_lines_filtered.value,
            self.count_lines_skipped_user_agent.value,
            self.count_lines_skipped_http_errors.value,
            self.count_lines_skipped_http_redirects.value,
            self.count_lines_static.value,
            self.count_lines_skipped_downloads.value,
            self.count_lines_no_site.value,
            self.count_lines_hostname_skipped.value,
        ]),
    'count_lines_invalid': self.count_lines_invalid.value,
    'count_lines_filtered': self.count_lines_filtered.value,
    'count_lines_skipped_user_agent': self.count_lines_skipped_user_agent.value,
    'count_lines_skipped_http_errors': self.count_lines_skipped_http_errors.value,
    'count_lines_skipped_http_redirects': self.count_lines_skipped_http_redirects.value,
    'count_lines_static': self.count_lines_static.value,
    'count_lines_skipped_downloads': self.count_lines_skipped_downloads.value,
    'count_lines_no_site': self.count_lines_no_site.value,
    'count_lines_hostname_skipped': self.count_lines_hostname_skipped.value,
    'total_sites': len(self.matomo_sites),
    'total_sites_existing': len(self.matomo_sites - set(site_id for hostname, site_id in self.matomo_sites_created)),
    'total_sites_created': len(self.matomo_sites_created),
    'sites_created': self._indent_text(
            ['%s (ID: %d)' % (hostname, site_id) for hostname, site_id in self.matomo_sites_created],
            level=3,
        ),
    'total_sites_ignored': len(self.matomo_sites_ignored),
    'sites_ignored': self._indent_text(
            self.matomo_sites_ignored, level=3,
        ),
    'sites_ignored_tips': '''
        TIPs:
         - if one of these hosts is an alias host for one of the websites
           in Matomo, you can add this host as an "Alias URL" in Settings > Websites.
         - use --add-sites-new-hosts if you wish to automatically create
           one website for each of these hosts in Matomo rather than discarding
           these requests.
         - use --idsite-fallback to force all these log lines with a new hostname
           to be recorded in a specific idsite (for example for troubleshooting/visualizing the data)
         - use --idsite to force all lines in the specified log files
           to be all recorded in the specified idsite
         - or you can also manually create a new Website in Matomo with the URL set to this hostname
''' if self.matomo_sites_ignored else '',
    'total_time': self.time_stop - self.time_start,
    'speed_recording': self._round_value(self._compute_speed(
            self.count_lines_recorded.value,
            self.time_start, self.time_stop,
        )),
    'url': config.options.matomo_api_url,
    'invalid_lines': invalid_lines_summary
}))

    ##
    ## The monitor is a thread that prints a short summary each second.
    ##

    def _monitor(self):
        latest_total_recorded = 0
        while not self.monitor_stop:
            current_total = stats.count_lines_recorded.value
            time_elapsed = time.time() - self.time_start
            print(('%d lines parsed, %d lines recorded, %d records/sec (avg), %d records/sec (current)' % (
                stats.count_lines_parsed.value,
                current_total,
                current_total / time_elapsed if time_elapsed != 0 else 0,
                (current_total - latest_total_recorded) / config.options.show_progress_delay,
            )))
            latest_total_recorded = current_total
            time.sleep(config.options.show_progress_delay)

    def start_monitor(self):
        t = threading.Thread(target=self._monitor)
        t.daemon = True
        t.start()

    def stop_monitor(self):
        self.monitor_stop = True

class TimeHelper:

    @staticmethod
    def timedelta_from_timezone(timezone):
        timezone = int(timezone)
        sign = 1 if timezone >= 0 else -1
        n = abs(timezone)

        hours = int(n / 100) * sign
        minutes = n % 100 * sign

        return datetime.timedelta(hours=hours, minutes=minutes)

class UrlHelper:

    @staticmethod
    def convert_array_args(args):
        """
        Converts PHP deep query param arrays (eg, w/ names like hsr_ev[abc][0][]=value) into a nested list/dict
        structure that will convert correctly to JSON.
        """

        final_args = collections.OrderedDict()
        for key, value in args.items():
            indices = key.split('[')
            if '[' in key:
                # contains list of all indices, eg for abc[def][ghi][] = 123, indices would be ['abc', 'def', 'ghi', '']
                indices = [i.rstrip(']') for i in indices]

                # navigate the multidimensional array final_args, creating lists/dicts when needed, using indices
                element = final_args
                for i in range(0, len(indices) - 1):
                    idx = indices[i]

                    # if there's no next key, then this element is a list, otherwise a dict
                    element_type = list if not indices[i + 1] else dict
                    if idx not in element or not isinstance(element[idx], element_type):
                        element[idx] = element_type()

                    element = element[idx]

                # set the value in the final container we navigated to
                if not indices[-1]: # last indice is '[]'
                    element.append(value)
                else: # last indice has a key, eg, '[abc]'
                    element[indices[-1]] = value
            else:
                final_args[key] = value

        return UrlHelper._convert_dicts_to_arrays(final_args)

    @staticmethod
    def _convert_dicts_to_arrays(d):
        # convert dicts that have contiguous integer keys to arrays
        for key, value in d.items():
            if not isinstance(value, dict):
                continue

            if UrlHelper._has_contiguous_int_keys(value):
                d[key] = UrlHelper._convert_dict_to_array(value)
            else:
                d[key] = UrlHelper._convert_dicts_to_arrays(value)

        return d

    @staticmethod
    def _has_contiguous_int_keys(d):
        for i in range(0, len(d)):
            if str(i) not in d:
                return False
        return True

    @staticmethod
    def _convert_dict_to_array(d):
        result = []
        for i in range(0, len(d)):
            result.append(d[str(i)])
        return result

class MatomoHttpBase:
    class Error(Exception):

        def __init__(self, message, code = None):
            super(MatomoHttpBase.Error, self).__init__(message)

            self.code = code


class MatomoHttpUrllib(MatomoHttpBase):
    """
    Make requests to Matomo.
    """

    class RedirectHandlerWithLogging(urllib.request.HTTPRedirectHandler):
        """
        Special implementation of HTTPRedirectHandler that logs redirects in debug mode
        to help users debug system issues.
        """

        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            logging.debug("Request redirected (code: %s) to '%s'" % (code, newurl))

            return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, hdrs, newurl)

    def _call(self, path, args, headers=None, url=None, data=None):
        """
        Make a request to the Matomo site. It is up to the caller to format
        arguments, to embed authentication, etc.
        """
        if url is None:
            url = config.options.matomo_url
        headers = headers or {}

        if data is None:
            # If Content-Type isn't defined, PHP do not parse the request's body.
            headers['Content-type'] = 'application/x-www-form-urlencoded'
            data = urllib.parse.urlencode(args)
        elif not isinstance(data, str) and headers['Content-type'] == 'application/json':
            data = json.dumps(data)

            if args:
                path = path + '?' + urllib.parse.urlencode(args)

        if config.options.request_suffix:
            path = path + ('&' if '?' in path else '?') + config.options.request_suffix

        headers['User-Agent'] = 'Matomo/LogImport'

        try:
            timeout = config.options.request_timeout
        except:
            timeout = None # the config global object may not be created at this point

        request = urllib.request.Request(url + path, data.encode("utf-8"), headers)

        # Handle basic auth if auth_user set
        try:
            auth_user = config.options.auth_user
            auth_password = config.options.auth_password
        except:
            auth_user = None
            auth_password = None

        if auth_user is not None:
            base64string = base64.encodebytes('{}:{}'.format(auth_user, auth_password).encode()).decode().replace('\n', '')
            request.add_header("Authorization", "Basic %s" % base64string)

        # Use non-default SSL context if invalid certificates shall be
        # accepted.
        if config.options.accept_invalid_ssl_certificate and \
                sys.version_info >= (2, 7, 9):
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            https_handler_args = {'context': ssl_context}
        else:
            https_handler_args = {}
        opener = urllib.request.build_opener(
            self.RedirectHandlerWithLogging(),
            urllib.request.HTTPSHandler(**https_handler_args))
        response = opener.open(request, timeout = timeout)
        encoding = response.info().get_content_charset('utf-8')
        result = response.read()
        response.close()
        return result.decode(encoding)

    def _call_api(self, method, **kwargs):
        """
        Make a request to the Matomo API taking care of authentication, body
        formatting, etc.
        """
        args = {
            'module' : 'API',
            'format' : 'json',
            'method' : method,
            'filter_limit' : '-1',
        }
        # token_auth, by default, is taken from config.
        token_auth = kwargs.pop('_token_auth', None)
        if token_auth is None:
            token_auth = config.options.matomo_token_auth
        if token_auth:
            args['token_auth'] = token_auth

        url = kwargs.pop('_url', None)
        if url is None:
            url = config.options.matomo_api_url


        if kwargs:
            args.update(kwargs)

        # Convert lists into appropriate format.
        # See: https://developer.matomo.org/api-reference/reporting-api#passing-an-array-of-data-as-a-parameter
        # Warning: we have to pass the parameters in order: foo[0], foo[1], foo[2]
        # and not foo[1], foo[0], foo[2] (it will break Matomo otherwise.)
        final_args = []
        for key, value in args.items():
            if isinstance(value, (list, tuple)):
                for index, obj in enumerate(value):
                    final_args.append(('%s[%d]' % (key, index), obj))
            else:
                final_args.append((key, value))


#        logging.debug('%s' % final_args)
#        logging.debug('%s' % url)

        res = self._call('/', final_args, url=url)

        try:
            return json.loads(res)
        except ValueError:
            raise urllib.error.URLError('Matomo returned an invalid response: ' + res.decode("utf-8") )

    def _call_wrapper(self, func, expected_response, on_failure, *args, **kwargs):
        """
        Try to make requests to Matomo at most MATOMO_FAILURE_MAX_RETRY times.
        """
        errors = 0
        while True:
            try:
                response = func(*args, **kwargs)
                if expected_response is not None and response != expected_response:
                    if on_failure is not None:
                        error_message = on_failure(response, kwargs.get('data'))
                    else:
                        error_message = "didn't receive the expected response. Response was %s " % response

                    raise urllib.error.URLError(error_message)
                return response
            except (urllib.error.URLError, http.client.HTTPException, ValueError, socket.timeout) as e:
                logging.info('Error when connecting to Matomo: %s', e)

                code = None
                if isinstance(e, urllib.error.HTTPError):
                    # See Python issue 13211.
                    message = 'HTTP Error %s %s' % (e.code, e.msg)
                    code = e.code
                elif isinstance(e, urllib.error.URLError):
                    message = e.reason
                else:
                    message = str(e)

                # decorate message w/ HTTP response, if it can be retrieved
                if hasattr(e, 'read'):
                    message = message + ", response: " + e.read().decode()

                try:
                    delay_after_failure = config.options.delay_after_failure
                    max_attempts = config.options.max_attempts
                except NameError:
                    delay_after_failure = MATOMO_DEFAULT_DELAY_AFTER_FAILURE
                    max_attempts = MATOMO_DEFAULT_MAX_ATTEMPTS

                errors += 1
                if errors == max_attempts:
                    logging.info("Max number of attempts reached, server is unreachable!")

                    raise MatomoHttpBase.Error(message, code)
                else:
                    logging.info("Retrying request, attempt number %d" % (errors + 1))

                    time.sleep(delay_after_failure)

    def call(self, path, args, expected_content=None, headers=None, data=None, on_failure=None):
        return self._call_wrapper(self._call, expected_content, on_failure, path, args, headers,
                                    data=data)

    def call_api(self, method, **kwargs):
        return self._call_wrapper(self._call_api, None, None, method, **kwargs)

##
## Resolvers.
##
## A resolver is a class that turns a hostname into a Matomo site ID.
##

class StaticResolver:
    """
    Always return the same site ID, specified in the configuration.
    """

    def __init__(self, site_id):
        self.site_id = site_id
        # Go get the main URL
        site = matomo.call_api(
            'SitesManager.getSiteFromId', idSite=self.site_id
        )
        if site.get('result') == 'error':
            fatal_error(
                "cannot get the main URL of this site: %s" % site.get('message')
            )
        self._main_url = site['main_url']
        stats.matomo_sites.add(self.site_id)

    def resolve(self, hit):
        return (self.site_id, self._main_url)

    def check_format(self, format):
        pass

class DynamicResolver:
    """
    Use Matomo API to determine the site ID.
    """

    _add_site_lock = threading.Lock()

    def __init__(self):
        self._cache = {}
        if config.options.replay_tracking:
            # get existing sites
            self._cache['sites'] = matomo.call_api('SitesManager.getAllSites')

    def _get_site_id_from_hit_host(self, hit):
        return matomo.call_api(
            'SitesManager.getSitesIdFromSiteUrl',
            url=hit.host,
        )

    def _add_site(self, hit):
        main_url = 'http://' + hit.host
        DynamicResolver._add_site_lock.acquire()

        try:
            # After we obtain the lock, make sure the site hasn't already been created.
            res = self._get_site_id_from_hit_host(hit)
            if res:
                return res[0]['idsite']

            # The site doesn't exist.
            logging.debug('No Matomo site found for the hostname: %s', hit.host)
            if config.options.site_id_fallback is not None:
                logging.debug('Using default site for hostname: %s', hit.host)
                return config.options.site_id_fallback
            elif config.options.add_sites_new_hosts:
                if config.options.dry_run:
                    # Let's just return a fake ID.
                    return 0
                logging.debug('Creating a Matomo site for hostname %s', hit.host)
                result = matomo.call_api(
                    'SitesManager.addSite',
                    siteName=hit.host,
                    urls=[main_url],
                )
                if result.get('result') == 'error':
                    logging.error("Couldn't create a Matomo site for host %s: %s",
                        hit.host, result.get('message'),
                    )
                    return None
                else:
                    site_id = result['value']
                    stats.matomo_sites_created.append((hit.host, site_id))
                    return site_id
            else:
                # The site doesn't exist, we don't want to create new sites and
                # there's no default site ID. We thus have to ignore this hit.
                return None
        finally:
            DynamicResolver._add_site_lock.release()

    def _resolve(self, hit):
        res = self._get_site_id_from_hit_host(hit)
        if res:
            # The site already exists.
            site_id = res[0]['idsite']
        else:
            site_id = self._add_site(hit)
        if site_id is not None:
            stats.matomo_sites.add(site_id)
        return site_id

    def _resolve_when_replay_tracking(self, hit):
        """
        If parsed site ID found in the _cache['sites'] return site ID and main_url,
        otherwise return (None, None) tuple.
        """
        site_id = hit.args['idsite']
        if site_id in self._cache['sites']:
            stats.matomo_sites.add(site_id)
            return (site_id, self._cache['sites'][site_id]['main_url'])
        else:
            return (None, None)

    def _resolve_by_host(self, hit):
        """
        Returns the site ID and site URL for a hit based on the hostname.
        """
        try:
            site_id = self._cache[hit.host]
        except KeyError:
            logging.debug(
                'Site ID for hostname %s not in cache', hit.host
            )
            site_id = self._resolve(hit)
            logging.debug('Site ID for hostname %s: %s', hit.host, site_id)
            self._cache[hit.host] = site_id
        return (site_id, 'http://' + hit.host)

    def resolve(self, hit):
        """
        Return the site ID from the cache if found, otherwise call _resolve.
        If replay_tracking option is enabled, call _resolve_when_replay_tracking.
        """
        if config.options.replay_tracking:
            # We only consider requests with piwik.php which don't need host to be imported
            return self._resolve_when_replay_tracking(hit)
        else:
            # Workaround for empty Host bug issue #126
            if hit.host.strip() == '':
                hit.host = 'no-hostname-found-in-log'
            return self._resolve_by_host(hit)

    def check_format(self, format):
        if config.options.replay_tracking:
            pass
        elif format.regex is not None and 'host' not in format.regex.groupindex and not config.options.log_hostname:
            fatal_error(
                "the selected log format doesn't include the hostname: you must "
                "specify the Matomo site ID with the --idsite argument"
            )

class Recorder:
    """
    A Recorder fetches hits from the Queue and inserts them into Matomo using
    the API.
    """

    recorders = []

    def __init__(self):
        self.queue = queue.Queue(maxsize=2)

        # if bulk tracking disabled, make sure we can store hits outside of the Queue
        if not config.options.use_bulk_tracking:
            self.unrecorded_hits = []

    @classmethod
    def launch(cls, recorder_count):
        """
        Launch a bunch of Recorder objects in a separate thread.
        """
        for i in range(recorder_count):
            recorder = Recorder()
            cls.recorders.append(recorder)

            run = recorder._run_bulk if config.options.use_bulk_tracking else recorder._run_single
            t = threading.Thread(target=run)

            t.daemon = True
            t.start()
            logging.debug('Launched recorder')

    @classmethod
    def add_hits(cls, all_hits):
        """
        Add a set of hits to the recorders queue.
        """
        # Organize hits so that one client IP will always use the same queue.
        # We have to do this so visits from the same IP will be added in the right order.
        hits_by_client = [[] for r in cls.recorders]
        for hit in all_hits:
            hits_by_client[hit.get_visitor_id_hash() % len(cls.recorders)].append(hit)

        for i, recorder in enumerate(cls.recorders):
            recorder.queue.put(hits_by_client[i])

    @classmethod
    def wait_empty(cls):
        """
        Wait until all recorders have an empty queue.
        """
        for recorder in cls.recorders:
            recorder._wait_empty()

    def _run_bulk(self):
        while True:
            try:
                hits = self.queue.get()
            except:
                # TODO: we should log something here, however when this happens, logging.etc will throw
                return

            if len(hits) > 0:
                try:
                    self._record_hits(hits)
                except MatomoHttpBase.Error as e:
                    fatal_error(e, hits[0].filename, hits[0].lineno) # approximate location of error
            self.queue.task_done()

    def _run_single(self):
        while True:
            if config.options.force_one_action_interval != False:
                time.sleep(config.options.force_one_action_interval)

            if len(self.unrecorded_hits) > 0:
                hit = self.unrecorded_hits.pop(0)

                try:
                    self._record_hits([hit])
                except MatomoHttpBase.Error as e:
                    fatal_error(e, hit.filename, hit.lineno)
            else:
                self.unrecorded_hits = self.queue.get()
                self.queue.task_done()

    def _wait_empty(self):
        """
        Wait until the queue is empty.
        """
        while True:
            if self.queue.empty():
                # We still have to wait for the last queue item being processed
                # (queue.empty() returns True before queue.task_done() is
                # called).
                self.queue.join()
                return
            time.sleep(1)

    def date_to_matomo(self, date):
        date, time = date.isoformat(sep=' ').split()
        return '%s %s' % (date, time.replace('-', ':'))

    def _get_hit_args(self, hit):
        """
        Returns the args used in tracking a hit, without the token_auth.
        """
        site_id, main_url = resolver.resolve(hit)
        if site_id is None:
            # This hit doesn't match any known Matomo site.
            if config.options.replay_tracking:
                stats.matomo_sites_ignored.add('unrecognized site ID %s' % hit.args.get('idsite'))
            else:
                stats.matomo_sites_ignored.add(hit.host)
            stats.count_lines_no_site.increment()
            return

        stats.dates_recorded.add(hit.date.date())

        path = hit.path
        if hit.query_string and not config.options.strip_query_string:
            path += config.options.query_string_delimiter + hit.query_string

        # only prepend main url / host if it's a path
        url_prefix = self._get_host_with_protocol(hit.host, main_url) if hasattr(hit, 'host') else main_url
        url = (url_prefix if path.startswith('/') else '') + path[:1024]

        # handle custom variables before generating args dict
        if config.options.enable_bots:
            if hit.is_robot:
                hit.add_visit_custom_var("Bot", hit.user_agent)
            else:
                hit.add_visit_custom_var("Not-Bot", hit.user_agent)

        hit.add_page_custom_var("HTTP-code", hit.status)

        args = {
            'rec': '1',
            'apiv': '1',
            'url': url,
            'urlref': hit.referrer[:1024],
            'cip': hit.ip,
            'cdt': self.date_to_matomo(hit.date),
            'idsite': site_id,
            'queuedtracking': '0',
            'dp': '0' if config.options.reverse_dns else '1',
            'ua': hit.user_agent
        }

        if config.options.replay_tracking:
            # prevent request to be force recorded when option replay-tracking
            args['rec'] = '0'

        # idsite is already determined by resolver
        if 'idsite' in hit.args:
            del hit.args['idsite']

        args.update(hit.args)

        if hit.is_download:
            args['download'] = args['url']

        if config.options.enable_bots:
            args['bots'] = '1'

        if hit.is_error or hit.is_redirect:
            args['action_name'] = '%s%sURL = %s%s' % (
                hit.status,
                config.options.title_category_delimiter,
                urllib.parse.quote(args['url'], ''),
                ("%sFrom = %s" % (
                    config.options.title_category_delimiter,
                    urllib.parse.quote(args['urlref'], '')
                ) if args['urlref'] != ''  else '')
            )

        if hit.generation_time_milli > 0:
            args['pf_srv'] = int(hit.generation_time_milli)

        if hit.event_category and hit.event_action:
            args['e_c'] = hit.event_category
            args['e_a'] = hit.event_action

            if hit.event_name:
                args['e_n'] = hit.event_name

        if hit.length:
            args['bw_bytes'] = hit.length

        # convert custom variable args to JSON
        if 'cvar' in args and not isinstance(args['cvar'], str):
            args['cvar'] = json.dumps(args['cvar'])

        if '_cvar' in args and not isinstance(args['_cvar'], str):
            args['_cvar'] = json.dumps(args['_cvar'])

        return UrlHelper.convert_array_args(args)

    def _get_host_with_protocol(self, host, main_url):
        if '://' not in host:
            parts = urllib.parse.urlparse(main_url)
            host = parts.scheme + '://' + host
        return host

    def _record_hits(self, hits):
        """
        Inserts several hits into Matomo.
        """
        if not config.options.dry_run:
            data = {
                'token_auth': config.options.matomo_token_auth,
                'requests': [self._get_hit_args(hit) for hit in hits]
            }
            try:
                args = {
                    'queuedtracking': '0'
                }

                if config.options.debug_tracker:
                    args['debug'] = '1'

                response = matomo.call(
                    config.options.matomo_tracker_endpoint_path, args=args,
                    expected_content=None,
                    headers={'Content-type': 'application/json'},
                    data=data,
                    on_failure=self._on_tracking_failure
                )

                if config.options.debug_tracker:
                    logging.debug('tracker response:\n%s' % response)

                # check for invalid requests
                try:
                    response = json.loads(response)
                except:
                    logging.info("bulk tracking returned invalid JSON")

                    # don't display the tracker response if we're debugging the tracker.
                    # debug tracker output will always break the normal JSON output.
                    if not config.options.debug_tracker:
                        logging.info("tracker response:\n%s" % response)

                    response = {}

                if ('invalid_indices' in response and isinstance(response['invalid_indices'], list) and
                    response['invalid_indices']):
                    invalid_count = len(response['invalid_indices'])

                    invalid_lines = [str(hits[index].lineno) for index in response['invalid_indices']]
                    invalid_lines_str = ", ".join(invalid_lines)

                    stats.invalid_lines.extend(invalid_lines)

                    logging.info("The Matomo tracker identified %s invalid requests on lines: %s" % (invalid_count, invalid_lines_str))
                elif 'invalid' in response and response['invalid'] > 0:
                    logging.info("The Matomo tracker identified %s invalid requests." % response['invalid'])
            except MatomoHttpBase.Error as e:
                # if the server returned 400 code, BulkTracking may not be enabled
                if e.code == 400:
                    fatal_error("Server returned status 400 (Bad Request).\nIs the BulkTracking plugin disabled?", hits[0].filename, hits[0].lineno)

                raise

        stats.count_lines_recorded.advance(len(hits))

    def _is_json(self, result):
        try:
            json.loads(result)
            return True
        except ValueError:
            return False

    def _on_tracking_failure(self, response, data):
        """
        Removes the successfully tracked hits from the request payload so
        they are not logged twice.
        """
        try:
            response = json.loads(response)
        except:
            # the response should be in JSON, but in case it can't be parsed just try another attempt
            logging.debug("cannot parse tracker response, should be valid JSON")
            return response

        # remove the successfully tracked hits from payload
        tracked = response['tracked']
        data['requests'] = data['requests'][tracked:]

        return response['message']

class Hit:
    """
    It's a simple container.
    """
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        super(Hit, self).__init__()

        if config.options.force_lowercase_path:
            self.full_path = self.full_path.lower()

    def get_visitor_id_hash(self):
        visitor_id = self.ip

        if config.options.replay_tracking:
            for param_name_to_use in ['uid', 'cid', '_id', 'cip']:
                if param_name_to_use in self.args:
                    visitor_id = self.args[param_name_to_use]
                    break

        return abs(hash(visitor_id))

    def add_page_custom_var(self, key, value):
        """
        Adds a page custom variable to this Hit.
        """
        self._add_custom_var(key, value, 'cvar')

    def add_visit_custom_var(self, key, value):
        """
        Adds a visit custom variable to this Hit.
        """
        self._add_custom_var(key, value, '_cvar')

    def _add_custom_var(self, key, value, api_arg_name):
        if api_arg_name not in self.args:
            self.args[api_arg_name] = {}

        if isinstance(self.args[api_arg_name], str):
            logging.debug("Ignoring custom %s variable addition [ %s = %s ], custom var already set to string." % (api_arg_name, key, value))
            return

        index = len(self.args[api_arg_name]) + 1
        self.args[api_arg_name][index] = [key, value]

class Parser:
    """
    The Parser parses the lines in a specified file and inserts them into
    a Queue.
    """

    def __init__(self):
        self.check_methods = [method for name, method
                              in inspect.getmembers(self, predicate=inspect.ismethod)
                              if name.startswith('check_')]

    ## All check_* methods are called for each hit and must return True if the
    ## hit can be imported, False otherwise.

    def check_hostname(self, hit):
        # Check against config.hostnames.
        if not hasattr(hit, 'host') or not config.options.hostnames:
            return True

        # Accept the hostname only if it matches one pattern in the list.
        result = any(
            fnmatch.fnmatch(hit.host, pattern)
            for pattern in config.options.hostnames
        )
        if not result:
            stats.count_lines_hostname_skipped.increment()
        return result

    def check_static(self, hit):
        filename = hit.path.split('/')[-1]

        if hit.extension in STATIC_EXTENSIONS or filename in STATIC_FILES:
            if config.options.enable_static:
                hit.is_download = True
                return True
            else:
                stats.count_lines_static.increment()
                return False
        return True

    def check_download(self, hit):
        if hit.extension in config.options.download_extensions:
            stats.count_lines_downloads.increment()
            hit.is_download = True
            return True
        # the file is not in the white-listed downloads
        # if it's a know download file, we shall skip it
        elif hit.extension in DOWNLOAD_EXTENSIONS:
            stats.count_lines_skipped_downloads.increment()
            return False
        return True

    def check_user_agent(self, hit):
        user_agent = hit.user_agent.lower()
        for s in itertools.chain(EXCLUDED_USER_AGENTS, config.options.excluded_useragents):
            if s in user_agent:
                if config.options.enable_bots:
                    hit.is_robot = True
                    return True
                else:
                    stats.count_lines_skipped_user_agent.increment()
                    return False
        return True

    def check_http_error(self, hit):
        if hit.status[0] in ('4', '5'):
            if config.options.replay_tracking:
                # process error logs for replay tracking, since we don't care if matomo error-ed the first time
                return True
            elif config.options.enable_http_errors:
                hit.is_error = True
                return True
            else:
                stats.count_lines_skipped_http_errors.increment()
                return False
        return True

    def check_http_redirect(self, hit):
        if hit.status[0] == '3' and hit.status != '304':
            if config.options.enable_http_redirects:
                hit.is_redirect = True
                return True
            else:
                stats.count_lines_skipped_http_redirects.increment()
                return False
        return True

    def check_path(self, hit):
        for excluded_path in config.options.excluded_paths:
            if fnmatch.fnmatch(hit.path, excluded_path):
                return False
        # By default, all paths are included.
        if config.options.included_paths:
           for included_path in config.options.included_paths:
               if fnmatch.fnmatch(hit.path, included_path):
                   return True
           return False
        return True

    @staticmethod
    def check_format(lineOrFile):
        format = False
        format_groups = 0
        for name, candidate_format in FORMATS.items():
            logging.debug("Check format %s", name)

            # skip auto detection for formats that can't be detected automatically
            if name == 'ovh':
                continue

            match = None
            try:
                if isinstance(lineOrFile, str):
                    match = candidate_format.check_format_line(lineOrFile)
                else:
                    match = candidate_format.check_format(lineOrFile)
            except Exception:
                logging.debug('Error in format checking: %s', traceback.format_exc())
                pass

            if match:
                logging.debug('Format %s matches', name)

                # compare format groups if this *BaseFormat has groups() method
                try:
                    # if there's more info in this match, use this format
                    match_groups = len(match.groups())

                    logging.debug('Format match contains %d groups' % match_groups)

                    if format_groups < match_groups:
                        format = candidate_format
                        format_groups = match_groups
                except AttributeError:
                    format = candidate_format

            else:
                logging.debug('Format %s does not match', name)

        # if the format is W3cExtendedFormat, check if the logs are from IIS and if so, issue a warning if the
        # --w3c-time-taken-milli option isn't set
        if isinstance(format, W3cExtendedFormat):
            format.check_for_iis_option()

        return format

    @staticmethod
    def detect_format(file):
        """
        Return the best matching format for this file, or None if none was found.
        """
        logging.debug('Detecting the log format')

        format = False

        # check the format using the file (for formats like the W3cExtendedFormat one)
        format = Parser.check_format(file)

        # check the format using the first N lines (to avoid irregular ones)
        lineno = 0
        limit = 100000
        while not format and lineno < limit:
            line = file.readline()
            if not line: # if at eof, don't keep looping
                break

            lineno = lineno + 1

            logging.debug("Detecting format against line %i" % lineno)
            format = Parser.check_format(line)

        try:
            file.seek(0)
        except IOError:
            pass

        if not format:
            fatal_error("cannot automatically determine the log format using the first %d lines of the log file. " % limit +
                        "\nMaybe try specifying the format with the --log-format-name command line argument." )
            return

        logging.debug('Format %s is the best match', format.name)
        return format

    def is_filtered(self, hit):
        host = None
        if hasattr(hit, 'host'):
            host = hit.host
        else:
            try:
                host = urllib.parse.urlparse(hit.path).hostname
            except:
                pass

        if host:
            if config.options.exclude_host and len(config.options.exclude_host) > 0 and host in config.options.exclude_host:
                return (True, 'host matched --exclude-host')

            if config.options.include_host and len(config.options.include_host) > 0 and host not in config.options.include_host:
                return (True, 'host did not match --include-host')

        if config.options.exclude_older_than and hit.date < config.options.exclude_older_than:
            return (True, 'date is older than --exclude-older-than')

        if config.options.exclude_newer_than and hit.date > config.options.exclude_newer_than:
            return (True, 'date is newer than --exclude-newer-than')

        return (False, None)

    def parse(self, filename):
        """
        Parse the specified filename and insert hits in the queue.
        """
        def invalid_line(line, reason):
            stats.count_lines_invalid.increment()
            if config.options.debug >= 2:
                logging.debug('Invalid line detected (%s): %s' % (reason, line))

        def filtered_line(line, reason):
            stats.count_lines_filtered.increment()
            if config.options.debug >= 2:
                logging.debug('Filtered line out (%s): %s' % (reason, line))

        if filename == '-':
            filename = '(stdin)'
            file = sys.stdin
        else:
            if not os.path.exists(filename):
                print("\n=====> Warning: File %s does not exist <=====" % filename, file=sys.stderr)
                return
            else:
                if filename.endswith('.bz2'):
                    open_func = bz2.open
                elif filename.endswith('.gz'):
                    open_func = gzip.open
                else:
                    open_func = open

                file = open_func(filename, mode='rt', encoding=config.options.encoding, errors="surrogateescape")

        if config.options.show_progress:
            print(('Parsing log %s...' % filename))

        if config.format:
            # The format was explicitly specified.
            format = config.format

            if isinstance(format, W3cExtendedFormat):
                format.create_regex(file)

                if format.regex is None:
                    return fatal_error(
                        "File is not in the correct format, is there a '#Fields:' line? "
                        "If not, use the --w3c-fields option."
                    )
        else:
            # If the file is empty, don't bother.
            data = file.read(100)
            if len(data.strip()) == 0:
                return
            try:
                file.seek(0)
            except IOError:
                pass

            format = self.detect_format(file)
            if format is None:
                return fatal_error(
                    'Cannot guess the logs format. Please give one using '
                    'either the --log-format-name or --log-format-regex option'
                )
        # Make sure the format is compatible with the resolver.
        resolver.check_format(format)

        if config.options.dump_log_regex:
            logging.info("Using format '%s'." % format.name)
            if format.regex:
                logging.info("Regex being used: %s" % format.regex.pattern)
            else:
                logging.info("Format %s does not use a regex to parse log lines." % format.name)
            logging.info("--dump-log-regex option used, aborting log import.")
            os._exit(0)

        valid_lines_count = 0

        hits = []
        lineno = -1
        while True:
            line = file.readline()
            if not line: break
            lineno = lineno + 1

            stats.count_lines_parsed.increment()
            if stats.count_lines_parsed.value <= config.options.skip:
                continue

            match = format.match(line)
            if not match:
                invalid_line(line, 'line did not match')
                continue

            valid_lines_count = valid_lines_count + 1
            if config.options.debug_request_limit and valid_lines_count >= config.options.debug_request_limit:
                if len(hits) > 0:
                    Recorder.add_hits(hits)
                logging.info("Exceeded limit specified in --debug-request-limit, exiting.")
                return

            hit = Hit(
                filename=filename,
                lineno=lineno,
                status=format.get('status'),
                full_path=format.get('path'),
                is_download=False,
                is_robot=False,
                is_error=False,
                is_redirect=False,
                args={},
            )

            if config.options.regex_group_to_page_cvars_map:
                self._add_custom_vars_from_regex_groups(hit, format, config.options.regex_group_to_page_cvars_map, True)

            if config.options.regex_group_to_visit_cvars_map:
                self._add_custom_vars_from_regex_groups(hit, format, config.options.regex_group_to_visit_cvars_map, False)

            if config.options.regex_groups_to_ignore:
                format.remove_ignored_groups(config.options.regex_groups_to_ignore)

            # Add http method page cvar
            try:
                httpmethod = format.get('method')
                if config.options.track_http_method and httpmethod != '-':
                    hit.add_page_custom_var('HTTP-method', httpmethod)
            except:
                pass

            try:
                hit.query_string = format.get('query_string')
                hit.path = hit.full_path
            except BaseFormatException:
                hit.path, _, hit.query_string = hit.full_path.partition(config.options.query_string_delimiter)

            # W3cExtendedFormat detaults to - when there is no query string, but we want empty string
            if hit.query_string == '-':
                hit.query_string = ''

            hit.extension = hit.path.rsplit('.')[-1].lower()

            try:
                hit.referrer = format.get('referrer')

                if hit.referrer is None:
                    hit.referrer = ''
                if hit.referrer.startswith('"'):
                    hit.referrer = hit.referrer[1:-1]
            except BaseFormatException:
                hit.referrer = ''
            if hit.referrer == '-':
                hit.referrer = ''

            try:
                hit.user_agent = format.get('user_agent')

                # in case a format parser included enclosing quotes, remove them so they are not
                # sent to Matomo
                if hit.user_agent.startswith('"'):
                    hit.user_agent = hit.user_agent[1:-1]
            except BaseFormatException:
                hit.user_agent = ''

            hit.ip = format.get('ip')
            try:
                hit.length = int(format.get('length'))
            except (ValueError, BaseFormatException):
                # Some lines or formats don't have a length (e.g. 304 redirects, W3C logs)
                hit.length = 0

            try:
                hit.generation_time_milli = float(format.get('generation_time_milli'))
            except (ValueError, BaseFormatException):
                try:
                    hit.generation_time_milli = float(format.get('generation_time_micro')) / 1000
                except (ValueError, BaseFormatException):
                    try:
                        hit.generation_time_milli = float(format.get('generation_time_secs')) * 1000
                    except (ValueError, BaseFormatException):
                        hit.generation_time_milli = 0

            if config.options.log_hostname:
                hit.host = config.options.log_hostname
            else:
                try:
                    hit.host = format.get('host').lower().strip('.')

                    if hit.host.startswith('"'):
                        hit.host = hit.host[1:-1]
                except BaseFormatException:
                    # Some formats have no host.
                    pass

            # Add userid
            try:
                hit.userid = None

                userid = format.get('userid')
                if userid != '-':
                    hit.args['uid'] = hit.userid = userid
            except:
                pass

            # add event info
            try:
                hit.event_category = hit.event_action = hit.event_name = None

                hit.event_category = format.get('event_category')
                hit.event_action = format.get('event_action')

                hit.event_name = format.get('event_name')
                if hit.event_name == '-':
                    hit.event_name = None
            except:
                pass

            # Check if the hit must be excluded.
            if not all((method(hit) for method in self.check_methods)):
                continue

            # Parse date.
            # We parse it after calling check_methods as it's quite CPU hungry, and
            # we want to avoid that cost for excluded hits.
            date_string = format.get('date')
            try:
                hit.date = datetime.datetime.strptime(date_string, format.date_format)
                hit.date += datetime.timedelta(seconds = config.options.seconds_to_add_to_date)
            except ValueError as e:
                invalid_line(line, 'invalid date or invalid format: %s' % str(e))
                continue

            # Parse timezone and subtract its value from the date
            try:
                timezone = format.get('timezone').replace(':', '')
                if timezone:
                    hit.date -= TimeHelper.timedelta_from_timezone(timezone)
            except BaseFormatException:
                pass
            except ValueError:
                invalid_line(line, 'invalid timezone')
                continue

            if config.options.replay_tracking:
                # we need a query string and we only consider requests with piwik.php
                if not hit.query_string or not self.is_hit_for_tracker(hit):
                    invalid_line(line, 'no query string, or ' + hit.path.lower() + ' does not end with piwik.php/matomo.php')
                    continue

                query_arguments = urllib.parse.parse_qs(hit.query_string)
                if not "idsite" in query_arguments:
                    invalid_line(line, 'missing idsite')
                    continue

                hit.args.update((k, v.pop()) for k, v in query_arguments.items())

                if config.options.seconds_to_add_to_date:
                    for param in ['_idts', '_viewts', '_ects', '_refts']:
                        if param in hit.args:
                            hit.args[param] = int(hit.args[param]) + config.options.seconds_to_add_to_date

            (is_filtered, reason) = self.is_filtered(hit)
            if is_filtered:
                filtered_line(line, reason)
                continue

            hits.append(hit)

            if len(hits) >= config.options.recorder_max_payload_size * len(Recorder.recorders):
                Recorder.add_hits(hits)
                hits = []

        # add last chunk of hits
        if len(hits) > 0:
            Recorder.add_hits(hits)

    def is_hit_for_tracker(self, hit):
        filesToCheck = ['piwik.php', 'matomo.php']
        if config.options.replay_tracking_expected_tracker_file:
            filesToCheck = [config.options.replay_tracking_expected_tracker_file]

        lowerPath = hit.path.lower()
        for file in filesToCheck:
            if lowerPath.endswith(file):
                return True
        return False

    def _add_custom_vars_from_regex_groups(self, hit, format, groups, is_page_var):
        for group_name, custom_var_name in groups.items():
            if group_name in format.get_all():
                value = format.get(group_name)

                # don't track the '-' empty placeholder value
                if value == '-':
                    continue

                if is_page_var:
                    hit.add_page_custom_var(custom_var_name, value)
                else:
                    hit.add_visit_custom_var(custom_var_name, value)

def main():
    """
    Start the importing process.
    """
    stats.set_time_start()

    if config.options.show_progress:
        stats.start_monitor()

    recorders = Recorder.launch(config.options.recorders)

    try:
        for filename in config.filenames:
            parser.parse(filename)

        Recorder.wait_empty()
    except KeyboardInterrupt:
        pass

    stats.set_time_stop()

    if config.options.show_progress:
        stats.stop_monitor()

    stats.print_summary()

def fatal_error(error, filename=None, lineno=None):
    print('Fatal error: %s' % error, file=sys.stderr)
    if filename and lineno is not None:
        print((
            'You can restart the import of "%s" from the point it failed by '
            'specifying --skip=%d on the command line.\n' % (filename, lineno)
        ), file=sys.stderr)
    os._exit(1)

if __name__ == '__main__':
    try:
        config = Configuration()
        # The matomo object depends on the config object, so we have to create
        # it after creating the configuration.
        matomo = MatomoHttpUrllib()
        # The init_token_auth method may need the matomo option, so we must call
        # it after creating the matomo object.
        config.init_token_auth()
        stats = Statistics()
        resolver = config.get_resolver()
        parser = Parser()
        main()
        sys.exit(0)
    except KeyboardInterrupt:
        pass
