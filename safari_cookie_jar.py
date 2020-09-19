#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Safari Cookies.binarycookies parser."""

# Built based on the work by:
#
# Satishb3 (http://www.securitylearn.net):
# - http://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py
#
# Locutus (https://it.toolbox.com/users/content/Locutus)
# - https://it.toolbox.com/blogs/locutus/understanding-the-safari-cookiesbinarycookies-file-format-010712

from struct import unpack
from io import BytesIO
from pathlib import Path
from datetime import datetime

BINARYCOOKIES = str(Path.home()) + "/Library/Cookies/Cookies.binarycookies"


def get_cookies():
    """Reads the binary cookies file and returns a nested dict."""

    cookie_jar = {}

    with open(BINARYCOOKIES, "rb") as cookies_file:
        # Field 1: 4 byte magic number = 'cook'
        file_header = cookies_file.read(4)
        if file_header != b"cook":
            print("Not a Cookies.binarycookies file.")

        # Field 2: 4 byte int = number of pages
        num_pages = unpack(">i", cookies_file.read(4))[0]
        # Field 3: 4 byte int (one for each page) = page length
        page_sizes = [unpack(">i", cookies_file.read(4))[0] for n in range(num_pages)]

        for page in [cookies_file.read(ps) for ps in page_sizes]:
            # Convert the string to a file with
            page = BytesIO(page)

            # Field 1: 4 byte header: '\x00\x00\x01\x00'
            page.read(4)

            # Field 2: 4 byte int: number of cookies
            num_cookies = unpack("<i", page.read(4))[0]

            # Field 3: 4 byte int (one for each cookie) = cookie offset
            cookie_offsets = [unpack("<i", page.read(4))[0] for n in range(num_cookies)]

            # Field 4: 4 byte footer: '\x00\x00\x00\x00'
            _page_footer = unpack(">i", page.read(4))[0]

            for offset in cookie_offsets:
                cookie = {}

                # seek to the cookie position in the page
                page.seek(offset)

                # Field 1: 4 byte int: cookie size
                # get the cookie length and then the binary cookie content
                cookie_bytes = BytesIO(page.read(unpack("<i", page.read(4))[0]))
                # Field 2: 4 byte: '\x00\x00\x00\x00'
                cookie_bytes.read(4)

                # Field 3: 4 byte: cookie flags
                cookie["flags"] = unpack("<i", cookie_bytes.read(4))[0]
                # Field 4: 4 byte: '\x00\x00\x00\x00'
                cookie_bytes.read(4)

                # Field 5: 4 byte int: url field offset from cookie start
                # Field 6: 4 byte int: name field offset from cookie start
                # Field 7: 4 byte int: path field offset from cookie start
                # Field 8: 4 byte int: value field offset from cookie start
                offset_values = ["url", "name", "path", "value"]
                content_offsets = dict(
                    zip(
                        offset_values,
                        [unpack("<i", cookie_bytes.read(4))[0] for n in offset_values],
                    )
                )

                # Field 9: 8 byte footer: '\x00\x00\x00\x00\x00\x00\x00\x00'
                _cookie_offset_footer = cookie_bytes.read(8)

                # Seconds between Mac Epoch and Unix Epoch
                mac_epoch = int(datetime(2001, 1, 1).strftime("%s"))

                # Field 10: 8 byte double: expiry time of cookie
                # Field 11: 8 byte double: last access time of cookie
                # time is in Mac Epoch - we change to Unix Epoch
                cookie["expiry_time"] = (
                    unpack("<d", cookie_bytes.read(8))[0] + mac_epoch
                )
                cookie["last_access_time"] = (
                    unpack("<d", cookie_bytes.read(8))[0] + mac_epoch
                )

                # Field 12: variable length, null-terminated: cookie name
                # Field 13: variable length, null-terminated: cookie value
                # Field 14: variable length, null-terminated: cookie url
                # Field 15: variable length, null-terminated: cookie path
                for k in content_offsets.keys():
                    # seek to the offset (-4 because .. ?) and read until we
                    # hit the null-termination
                    cookie_bytes.seek(content_offsets[k] - 4)
                    _byte = cookie_bytes.read(1)
                    _value = ""
                    while unpack("<b", _byte)[0] != 0:
                        _value = _value + _byte.decode("ascii")
                        _byte = cookie_bytes.read(1)
                    cookie[k] = _value

                # put the cookie in the jar
                url = cookie.pop("url")
                path = cookie.pop("path")
                name = cookie.pop("name")
                if url in cookie_jar:
                    if path in cookie_jar[url]:
                        cookie_jar[url][path][name] = cookie
                    else:
                        cookie_jar[url][path] = {name: cookie}
                else:
                    cookie_jar[url] = {path: {name: cookie}}

    return cookie_jar
