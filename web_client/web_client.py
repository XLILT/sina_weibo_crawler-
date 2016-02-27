#!/usr/bin/env python
# -*- coding: utf-8 -*-
# create time: 2016-2-26

import urllib
import urllib2
import cookielib
import base64
import time
import re
import json
import rsa
import binascii

class web_client:
    def __init__(self):
        self.cj = cookielib.LWPCookieJar()
        self.cookie_support = urllib2.HTTPCookieProcessor(self.cj)
        self.opener = urllib2.build_opener(self.cookie_support, urllib2.HTTPHandler)
        urllib2.install_opener(self.opener)

    '''
    def post(self):
        try:
            req = urllib2.Request(
                url = self.url,
                data = urllib.urlencode(self.post_data),
                headers = self.headers
            )

            res = urllib2.urlopen(req)
            print res.readlines()
        except Exception as e:
            print e
    '''
    def get_secret_user(self, username):
        username_ = urllib.quote(username)
        username = base64.encodestring(username_)[:-1]
        return username

    def get_secret_pwd(self, pwd, servertime, nonce, pubkey):
        rsaPublickey = int(pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537) #创建公钥
        #key = rsa.PublicKey(rsaPublickey, 10001) #创建公钥
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(pwd)
        sp = rsa.encrypt(message, key) #加密
        return binascii.b2a_hex(sp) #将加密信息转换为16进制。


    def get_servertime_nonce_pubkey_rsakv(self, su):
        url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su='\
              + self.get_secret_user(su)\
              + '&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_='\
              + str(int(time.time()))
        data = urllib2.urlopen(url).read()
        #print "data: " + data + "\n"
        p = re.compile(r'\((.*)\)')
        try:
            json_data = p.search(data).group(1)
            #print "json_data: " + json_data + "\n"
            data = json.loads(json_data)
            return str(data['servertime']), str(data['nonce']), str(data['pubkey']), str(data['rsakv'])
        except:
            print 'Get severtime error!'
            return None

    def login(self, user, passwd):
        login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        headers = {'User-Agent':'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0 Chrome/20.0.1132.57 Safari/536.11'}
        server_time, nonce, pubkey, rsakv = self.get_servertime_nonce_pubkey_rsakv(user)
        post_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'userticket': '1',
            'ssosimplelogin': '1',
            'vsnf': '1',
            'su': self.get_secret_user(user),
            'service': 'miniblog',
            'servertime': server_time,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv' : rsakv,
            'sp': self.get_secret_pwd(passwd, server_time, nonce, pubkey),
            'encoding': 'UTF-8',
            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }

        req  = urllib2.Request(
            url = login_url,
            data = urllib.urlencode(post_data),
            headers = headers
        )

        result = urllib2.urlopen(req)

        return result.readlines()
