#!/usr/bin/env python3
from html import unescape
from random import sample
from re import findall, MULTILINE
from string import ascii_lowercase
from sys import argv

from colorama import init as colorama_init, Fore
from requests import Session

M_RE = r'[\w\.-]+@[\w\.-]+\.\w+'
P_RE = r'(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})'
D_RE = r'^Disallow: (.*)$'
FAKE_PATH = '/' + ''.join(sample(ascii_lowercase, 12))
session = Session()


def check(uri, res={}):
    print(f'{Fore.BLUE}[*]{Fore.WHITE}', uri)
    r = session.get(uri)
    print(f'  {Fore.YELLOW}{r.status_code}{Fore.RESET} {len(r.content)} bytes')

    res_results = {}
    for k, re in res.items():
        items = set(findall(re, unescape(r.text), MULTILINE))
        if items:
            res_results[k] = items
            print(f'  {Fore.GREEN}[+] {k}:{Fore.RESET}', *items)

    return r, res_results


def main(target):
    colorama_init()
    session.headers['User-Agent'] = 'Mozilla/5.0'

    paths = (FAKE_PATH, '/.htaccess', '/.git/HEAD',
             '/../../../../../etc/passwd')

    check(target, {'Mails': M_RE, 'Phones': P_RE})
    _, res = check('%s/robots.txt' % target, {'Disallows': D_RE})

    for path in res.get('Disallows', []):
        uri = f'{target}{path}'
        check(uri, {'Mails': M_RE, 'Phones': P_RE})


    for path in paths:
        uri = f'{target}{path}'
        check(uri)


if __name__ == '__main__':
    main(argv[1])
