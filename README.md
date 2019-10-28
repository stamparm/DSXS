Damn Small XSS Scanner [![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-Public_domain-red.svg)](https://wiki.creativecommons.org/wiki/Public_domain)
=========

**Damn Small XSS Scanner** (DSXS) is a fully functional [Cross-site scripting](https://en.wikipedia.org/wiki/Cross-site_scripting) vulnerability scanner (supporting GET and POST parameters) written in under 100 lines of code.

![Vulnerable](http://i.imgur.com/hadlgS0.png)

As of optional settings it supports HTTP proxy together with HTTP header values `User-Agent`, `Referer` and `Cookie`.

Sample runs
----

```
$ python3 dsxs.py -h
Damn Small XSS Scanner (DSXS) < 100 LoC (Lines of Code) #v0.3a
 by: Miroslav Stampar (@stamparm)

Usage: dsxs.py [options]

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.htm?id=1")
  --data=DATA        POST data (e.g. "query=test")
  --cookie=COOKIE    HTTP Cookie header value
  --user-agent=UA    HTTP User-Agent header value
  --referer=REFERER  HTTP Referer header value
  --proxy=PROXY      HTTP proxy address (e.g. "http://127.0.0.1:8080")
```

```
$ python3 dsxs.py -u "http://testphp.vulnweb.com/search.php?test=query" --data="s
earchFor=foobar"
Damn Small XSS Scanner (DSXS) < 100 LoC (Lines of Code) #v0.3a
 by: Miroslav Stampar (@stamparm)

* scanning GET parameter 'test'
* scanning POST parameter 'searchFor'
 (i) POST parameter 'searchFor' appears to be XSS vulnerable (">.xss.<", outside
 of tags, no filtering)

scan results: possible vulnerabilities found
```

```
$ python3 dsxs.py -u "http://public-firing-range.appspot.com/address/location.has
h/replace"
Damn Small XSS Scanner (DSXS) < 100 LoC (Lines of Code) #v0.3a
 by: Miroslav Stampar (@stamparm)

 (i) page itself appears to be XSS vulnerable (DOM)
  (o) ...<script>
      var payload = window.location.hash.substr(1);location.replace(payload); 

    </script>...
 (x) no usable GET/POST parameters found

scan results: possible vulnerabilities found
```

Requirements
----

[Python](http://www.python.org/download/) version **3.x** is required for running this program.
