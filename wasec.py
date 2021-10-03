#!/usr/bin/env python3
from collections import defaultdict
from contextlib import suppress
from html import unescape
from random import choices
from re import MULTILINE, findall
from socket import gethostbyaddr, gethostbyname, setdefaulttimeout, socket
from ssl import _create_unverified_context
from string import ascii_lowercase
from sys import argv
from urllib.parse import urlparse

from colorama import Fore, init as colorama_init
from requests import Session

INTERESTING_HEADERS = ('access-control-allow-origin', 'server', 'set-cookie',
                       'via', 'x-backend-server', 'x-powered-by')

analytics_res = {
    'adsense': r'pub-\d+',
    'google_analytics': r'ua-[0-9-]+',
    'googleTagManager': r'gtm-[^&\'"%]+',
    'mailru_counter': r'top.mail.ru[^\'"]+from=(\d+)',
    'yandexMetrika': r'metrika.yandex[^\'"]+?id=(\d+)',
    'vk_retarget': r'vk-[^&"\'%]+',
}

contact_res = {
    'Facebook': r'facebook\.com[-.A-Za-z0-9/]+',
    'Facebook2': r'fb\.me[-.A-Za-z0-9/]+',
    'Github': r'github\.com/[^"\'/]+',
    'Instagram': r'instagram\.com/[^"\'/]+',
    'Linkedin': r'linkedin.com[-._A-Za-z0-9/]+',
    'Mails': r'[\w.-]+@[\w\.-]+\.\w{2,5}',
    'OK': r'ok\.ru/[^"\'/]+',
    'Phones': r'\+\d{0,3}\s?0?\d{7,10}',
    'Phones2': r'\+?\d{0,3}?\s?0?\d{3}\s\d{3}\s\d{3}',
    'Phones3': r'\+?\(?\d{0,3}\)?\s?0?\d{3}\s\d{4}',
    'Telegram': r't\.me/[-._A-Za-z0-9/]+',
    'Twitter': r'twitter\.com[-._A-Za-z0-9/]+',
    'VK': r'vk\.com/[^"\'/]+',
    'Whatsapp': r'api\.whatsapp\.com/send\?phone=([\d]+)',
    'Whatsapp2': r'web\.whatsapp\.com/send\?phone=([\d]+)',
    'Whatsapp3': r'wa\.me/([\d]+)',
    'YouTube': r'youtube\.\w+?/channel/[^"\']+',
}

D_RE = r'^Disallow: (.*)$'

RANDOM_PATH = '/' + ''.join(choices(ascii_lowercase, k=12))
PATHS = ('/admin', '/phpinfo.php', '/.env', '/.htaccess', '/.git/HEAD',
         '/../../../../../etc/passwd')

STATUS_COLORS = [
    Fore.WHITE, Fore.GREEN, Fore.GREEN, Fore.BLUE, Fore.WHITE, Fore.RED
]

BANNER = r"""
__      ____ _ ___  ___  ___ 
\ \ /\ / / _` / __|/ _ \/ __|
 \ V  V / (_| \__ \  __/ (__ 
  \_/\_/ \__,_|___/\___|\___| by fagci""".lstrip()

session = Session()
session.headers['User-Agent'] = 'Mozilla/5.0'

unverified_context = _create_unverified_context()


def check(target, path='/', res={}):
    uri = f'{target}{path}'
    print(f'{Fore.BLUE}[*]', path, end=' ')

    r = session.get(uri)
    s_c = STATUS_COLORS[r.status_code // 100]

    print(f'\r{s_c}[i]', r.status_code, f'{path:<17}',
          f'{len(r.content):>8,}'.replace(',', ' '), 'bytes',
          f'{round(r.elapsed.total_seconds() * 1000):>4}', 'ms', Fore.RESET)

    res_results = {}
    for k, re in res.items():
        items = set(findall(re, unescape(r.text), MULTILINE))
        if items:
            res_results[k] = items

    return r, res_results


def get_domains(target):
    pu = urlparse(target)
    ip = gethostbyname(pu.hostname or '')

    with suppress(Exception):
        yield gethostbyaddr(ip)[0]

    with suppress(Exception):
        with unverified_context.wrap_socket(socket()) as c:
            c.connect((pu.hostname, pu.port or 443))
            for _, d in c.getpeercert().get('subjectAltName', []):
                yield d


def main(target):
    colorama_init()
    print('=' * 40, BANNER, '=' * 40, sep='\n')
    print('Target:', target)
    disallow_res = {'Disallows': D_RE}
    loot = []

    domains = set()
    d_new = set(get_domains(target))
    while d_new:
        domains |= d_new
        d_new = {dn for d in d_new for dn in get_domains('https://%s' % d)}
        d_new ^= domains
    loot.append({'Domains': domains})

    check(target, '/', {**contact_res, **analytics_res})
    check(target, RANDOM_PATH, contact_res)

    print('Disallows:', '-' * 29)

    response, res = check(target, '/robots.txt', disallow_res)
    for hk, hv in response.headers.lower_items():
        if hk in INTERESTING_HEADERS:
            loot.append({'Headers': {f'{hk}: {hv}'}})
    loot.append(res)

    for path in res.get('Disallows', []):
        _, res = check(target, path, contact_res)
        loot.append(res)

    print('Vulns:', '-' * 33)

    for path in PATHS:
        response, _ = check(target, path)
        if response.ok:
            loot.append({'Vulns': {path}})

    loot_all = defaultdict(set)

    print('Loot:', '=' * 34)

    for part in loot:
        for k, v in part.items():
            loot_all[k] |= v

    for k, v in loot_all.items():
        if v:
            items = ", ".join(v)
            print(f'{Fore.GREEN}[+]{Fore.WHITE} {k}:{Fore.RESET} {items}')


if __name__ == '__main__':
    setdefaulttimeout(2)
    main(argv[1])
