#!/usr/bin/env python3
from html import unescape
from random import sample
from re import findall, MULTILINE
from string import ascii_lowercase
from sys import argv

from requests import Session

M_RE = r'[\w\.-]+@[\w\.-]+\.\w+'
D_RE = r'^Disallow: (.*)$'
FAKE_PATH = '/' + ''.join(sample(ascii_lowercase, 12))
session = Session()


def check(uri, res={}):
    print(uri)
    r = session.get(uri)
    print(f'  [{r.status_code}] {len(r.content)} bytes')

    for k, re in res.items():
        html = unescape(r.text)
        print('  %s:' % k, *set(findall(re, html, MULTILINE)))

    return r


def main(target):
    session.headers['User-Agent'] = 'Mozilla/5.0'

    paths = (FAKE_PATH, '/.htaccess', '/.git/HEAD',
             '/../../../../../etc/passwd')

    check(target, {'mails': M_RE})
    check('%s/robots.txt' % target, {'disaallows': D_RE})

    for path in paths:
        uri = f'{target}{path}'
        check(uri)


if __name__ == '__main__':
    main(argv[1])
