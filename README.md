# safari-cookie-jar

safari_cookie_jar.get_cookies() returns a nested dict:
```
{ 'url': { 'path': { 'name': { 'expiry_time': '', 'flags': '', 'last_access_time': '', 'value': '', } } } }
```

```sh
$ python3 -c "import safari_cookie_jar, pprint; pprint.pprint(safari_cookie_jar.get_cookies())"
{'lobste.rs': {'/': {'lobster_trap': {'expiry_time': 1519203368.0,
                                      'flags': 5,
                                      'last_access_time': 1516524969.0,
                                      'value': 'Nis1TU9vK0FTTWtsVzI1anIwNGY2elFvNjB1ZEEzdktHaXhucVA5ZkxxM2szL2dXbU9OcEJ6empmQkNRMnk1dFJERTFYa09oTDVQdXFhVThMTW9jY0lrcGhpbnN2YUJIdmtPMWl5U3E2RVRtM2lsM1dJSlZjSVBkekF2bDFJSnZSMHhUTWN4emZpeElPZWE1Wkg1dGpnPT0tLW1tdE0yTHFIV1V4azUxU2p4VVBhR2c9PQ%3D%3D--8c532a7d1bf000c204907701e894f606f6fb0b47'}}}}
```

An example using the cookies with `requests` can be found in `example.py`.
