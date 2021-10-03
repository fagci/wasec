#!/usr/bin/env python3
from collections import defaultdict
from html import unescape
from random import choices
from re import MULTILINE, findall
from string import ascii_lowercase
from sys import argv

from colorama import Fore, init as colorama_init
from requests import Session

M_RE = r'[\w\.-]+@[\w\.-]+\.\w+'
P_RE = r'\+?\d{1,4}?[-\s]?\(?\d{1,3}?\)?[-\s]?\d{1,4}[-\s]?\d{1,4}[-\s]?\d{1,9}'
D_RE = r'^Disallow: (.*)$'

FAKE_PATH = '/' + ''.join(choices(ascii_lowercase, k=12))
PATHS = (FAKE_PATH, '/.htaccess', '/.git/HEAD', '/../../../../../etc/passwd')

session = Session()
session.headers['User-Agent'] = 'Mozilla/5.0'


def check(uri, res={}):
    print(f'{Fore.BLUE}[*]', uri)

    r = session.get(uri)
    s_c = Fore.GREEN
    if 300 <= r.status_code < 400:
        s_c = Fore.YELLOW
    elif 400 <= r.status_code < 500:
        s_c = Fore.WHITE
    elif r.status_code >= 500:
        s_c = Fore.RED
    print(f'{s_c}{r.status_code}{Fore.RESET} {len(r.content)} bytes')

    res_results = {}
    for k, re in res.items():
        items = set(findall(re, unescape(r.text), MULTILINE))
        if items:
            res_results[k] = items

    return r, res_results


def main(target):
    colorama_init()
    contact_res = {'Mails': M_RE, 'Phones': P_RE}
    loot = []

    check(target, contact_res)
    _, res = check('%s/robots.txt' % target, {'Disallows': D_RE})
    loot.append(res)

    for path in res.get('Disallows', []):
        uri = f'{target}{path}'
        _, res = check(uri, contact_res)
        loot.append(res)

    for path in PATHS:
        uri = f'{target}{path}'
        _, res = check(uri)
        loot.append(res)

    loot_all = defaultdict(set)
    for part in loot:
        for k, v in part.items():
            loot_all[k] |= v

    print(*[f'{Fore.GREEN}[+]{Fore.WHITE} {k}:{Fore.RESET} {", ".join(v)}' for k,v in loot_all.items()], sep='\n')


if __name__ == '__main__':
    main(argv[1])
