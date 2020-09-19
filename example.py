#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example for use of cookies from the Safari cookie jar.
"""

import requests
import safari_cookie_jar

URL = "lobste.rs"

cookies = {}
safari_cookies = safari_cookie_jar.get_cookies()[URL]["/"]
for cookie in safari_cookies:
    cookies[cookie] = safari_cookies[cookie]["value"]

r = requests.get("https://" + URL, cookies=cookies)
print(r.text)
