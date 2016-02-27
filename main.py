#!/usr/bin/env python
# -*- coding: utf-8 -*-

import web_client.web_client

def main():
    wc = web_client.web_client.web_client()
    print(wc.login('username', 'password'))

if __name__ == '__main__':
    main()
