""" A Google Domains DDNS Client

API Docs: https://support.google.com/domains/answer/6147083?hl=en
TODO: Add check to make sure config file is editable by current user.
"""

import ConfigParser
import logging
import re
import requests
import socket
import sys

CHECK_IP_URL = 'https://domains.google.com/checkip'
GDDDNS_API_URL = 'https://domains.google.com/nic/update'
CONFIG_FILE_PATH = '/etc/gdddns.conf'

VERSION = '0.0.1'

log = logging.getLogger('gdddns')
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
console_handler.setFormatter(formatter)
log.addHandler(console_handler)

Config_file = ConfigParser.SafeConfigParser()
Config_file.read(CONFIG_FILE_PATH)


def main():
    # Verify config file.
    try:
        username = Config_file.get('gdddns_conf', 'username')
        password = Config_file.get('gdddns_conf', 'password')
        fqdn = Config_file.get('gdddns_conf', 'fqdn')
        cached_ip = Config_file.get('gdddns_cache', 'cached_ip')
        locked = Config_file.getboolean('gdddns_cache', 'locked')
        locked_reason = Config_file.get('gdddns_cache', 'locked_reason')

    except ConfigParser.NoSectionError:
        log.exception('Config file: %s missing or malformed. See included sample config file.', CONFIG_FILE_PATH)
        sys.exit(1)

    # Check current IP.
    curr_ip = requests.get(CHECK_IP_URL).text

    fqdn_resolved_ip = resolve_fqdn_ip(fqdn):

    log.debug('username: %s', username)
    log.debug('password: %s', password)
    log.debug('fqdn: %s', fqdn)
    log.debug('cached_ip: %s', cached_ip)
    log.debug('curr_ip: %s', curr_ip)
    log.debug('fqdn_resolved_ip: %s', fqdn_resolved_ip)
    log.debug('locked: %s', locked)
    log.debug('locked_reason: %s', locked_reason)

    if locked:
        log.critical(
            'Config file is locked, resolve issue and set "locked = True" in the config file: %s\nIssue: %s',
            CONFIG_FILE_PATH,
            locked_reason
        )
        sys.exit(1)

    # Don't update if the currently resolving IP is the same as the current IP.
    if fqdn_resolved_ip == curr_ip:
        log.info('%s currently resolves to the current IP: %s, nothing to update.', fqdn, curr_ip)
        sys.exit()

    # Check if we neeed to update.
    if cached_ip == curr_ip:
        log.info('Current IP matches cached IP: %s Not sending an update.', curr_ip)
        sys.exit()

    # Add requested useragent per docs.
    headers = requests.utils.default_headers()
    headers.update({'User-Agent': 'Chrome/41.0'})
    # Issue update request.
    gdddns_resp = requests.post(GDDDNS_API_URL, auth=(username, password), data={'hostname': fqdn, 'myip': curr_ip}, headers=headers)

    log.debug('Response: %s', gdddns_resp.text)

    # Parse response
    response_keyword = re.search(r'(\w+)', gdddns_resp.text).groups()[0]
    success_indicators = {
        'good': 'The update was successful. You should not attempt another update until your IP address changes.',
        'nochg': 'The supplied IP address is already set for this host. You should not attempt another update until your IP address changes.'
    }
    failure_indicators = {
        'nohost': 'The hostname does not exist, or does not have Dynamic DNS enabled.',
        'badauth': 'The username / password combination is not valid for the specified host.',
        'notfqdn': 'The supplied hostname is not a valid fully-qualified domain name.',
        'badagent': "Your Dynamic DNS client is making bad requests. Ensure the user agent is set in the request, and that you're only attempting to automatically set an IPv4 address. IPv6 must be set explicitly.",
        'abuse': 'Dynamic DNS access for the hostname has been blocked due to failure to interpret previous responses correctly.',
        '911': "An error happened on Google's end. Waiting 5 minutes to retry."
    }
    if response_keyword in success_indicators.iterkeys():
        log.debug('Success!')
        log.info(success_indicators.get(response_keyword))
        Config_file.set('gdddns_cache', 'cached_ip', curr_ip)
        Config_file.set('gdddns_cache', 'locked', 'False')
        with open(CONFIG_FILE_PATH, 'wb') as opened_config_file:
            Config_file.write(opened_config_file)
    elif response_keyword in failure_indicators.iterkeys():
        log.debug('Failure!')
        failure_err = failure_indicators.get(response_keyword)
        log.error(failure_err)
        if response_keyword == '911':
            # This is the only recoverable failure, not setting conf lock.
            sys.exit(1)
        elif response_keyword == 'badagent':
            # This is likely a programming-related or API error indicator.
            file_a_bug(fqdn, cached_ip, curr_ip, locked, locked_reason, gdddns_resp)
            lock_config(failure_err)
            sys.exit(1)
        else:
            lock_config(failure_err)
            sys.exit(1)
    else:
        log.error("Didn't understand response.")
        file_a_bug(fqdn, cached_ip, curr_ip, locked, locked_reason, gdddns_resp)
        lock_config(failure_err)
        sys.exit(1)


def resolve_fqdn_ip(fqdn):
    """Attempt to retrieve the IPv4 or IPv6 address to a given hostname."""
    try:
        return socket.inet_ntop(socket.AF_INET, socket.inet_pton(socket.AF_INET, socket.gethostbyname(fqdn)))
    except Exception:
        # Probably using ipv6
        pass
    try:
        return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, socket.getaddrinfo(fqdn, None, socket.AF_INET6)[0][4][0]))
    except Exception:
        return ''


def lock_config(failure_err):
    log.error('Something went wrong, locking config file.')
    Config_file.set('gdddns_cache', 'locked', 'True')
    Config_file.set('gdddns_cache', 'locked_reason', failure_err)
    with open(CONFIG_FILE_PATH, 'wb') as opened_config_file:
        Config_file.write(opened_config_file)


def file_a_bug(fqdn, cached_ip, curr_ip, locked, locked_reason, gdddns_resp):
    log.critical(
        'UNRECOVERABLE ERROR - Please file a issue ticket with the author and include the following '
        'information:\nversion: %s\nfqdn: %s\ncached_ip: %s\ncurr_ip: %s\nlocked: %s\nlocked_reason: %s'
        '\nresp.text: %s\nresp.headers: %s\n',
        VERSION,
        fqdn,
        cached_ip,
        curr_ip,
        locked,
        locked_reason,
        gdddns_resp.text,
        gdddns_resp.headers
    )


if __name__ == '__main__':
    main()
