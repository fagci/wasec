#!/usr/bin/env python3
from collections import defaultdict
from html import unescape
from random import choices
from re import MULTILINE, findall
from string import ascii_lowercase
from sys import argv

from colorama import Fore, init as colorama_init
from requests import Session

INTERESTING_HEADERS = ('server', 'x-powered-by')

M_RE = r'[\w\.-]+@[\w\.-]+\.\w+'
P_RE = r'\+?\d{1,4}?[-\s]?\(?\d{1,3}?\)?[-\s]?\d{1,4}[-\s]?\d{1,4}[-\s]?\d{1,9}'
D_RE = r'^Disallow: (.*)$'

FAKE_PATH = '/' + ''.join(choices(ascii_lowercase, k=12))
PATHS = (FAKE_PATH, '/.htaccess', '/.git/HEAD', '/../../../../../etc/passwd')

STATUS_COLORS = [
    Fore.WHITE, Fore.GREEN, Fore.GREEN, Fore.BLUE, Fore.WHITE, Fore.RED
]

BANNER = r"""
__      ____ _ ___  ___  ___ 
\ \ /\ / / _` / __|/ _ \/ __|
 \ V  V / (_| \__ \  __/ (__ 
  \_/\_/ \__,_|___/\___|\___| by fagci
                             
""".strip()

session = Session()
session.headers['User-Agent'] = 'Mozilla/5.0'


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


def main(target):
    colorama_init()
    print('=' * 40)
    print(BANNER)
    print('=' * 40)
    contact_res = {'Mails': M_RE, 'Phones': P_RE}
    loot = []

    check(target, '/', contact_res)
    response, res = check(target, '/robots.txt', {'Disallows': D_RE})
    for hk, hv in response.headers.lower_items():
        if hk in INTERESTING_HEADERS:
            loot.append({'Headers': {f'{hk}: {hv}'}})
    loot.append(res)

    print('Disallows:', '-' * 29)

    for path in res.get('Disallows', []):
        _, res = check(target, path, contact_res)
        loot.append(res)

    print('Vulns:', '-' * 33)

    for path in PATHS:
        _, res = check(target, path)
        loot.append(res)

    loot_all = defaultdict(set)

    for part in loot:
        for k, v in part.items():
            loot_all[k] |= v

    print('Loot:', '=' * 34)
    for k, v in loot_all.items():
        print(f'{Fore.GREEN}[+]{Fore.WHITE} {k}:{Fore.RESET} {", ".join(v)}')


if __name__ == '__main__':
    main(argv[1])
