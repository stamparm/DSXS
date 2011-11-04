#!/usr/bin/env python

import cookielib, optparse, random, re, string, urllib2, urlparse

NAME    = "Damn Small XSS Scanner (DSXS) < 100 LOC (Lines of Code)"
VERSION = "0.1a"
AUTHOR  = "Miroslav Stampar (http://unconciousmind.blogspot.com | @stamparm)"
LICENSE = "Public domain (FREE)"

SPECIAL_CHAR_POOL    = ['\'', '"', '>', '<']            # characters used for XSS tampering of parameter values
GET, POST = "GET", "POST"                               # enumerator-like values used for marking current phase
PREFIX_SUFFIX_LENGTH = 5                                # length of random prefix/suffix used in XSS tampering
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer" # optional HTTP headers

XSS_PATTERNS = (
    (r'\A[^<>]*%s[^<>]*\Z', ('<', '>')),                # first item represents contextual regex while the second
    (r'<script[^>]*>.*%s.*</script>', ()),              #  one represents character(s) that need to be returned
    (r'>[^<]*%s[^<]*(<|\Z)', ('<', '>')),               #  in original (unfiltered/non-encoded) for it to be XSS
    (r"<[^>]*'[^>']*%s[^>']*'[^>]*>", ('\'',)),         #  exploitable in the first place
    (r'<[^>]*"[^>"]*%s[^>"]*"[^>]*>', ('"',)),          # testing order of "patterns" is important (!)
    (r'<[^>]*%s[^>]*>', ())
)

_headers = None                                         # used for storing dictionary with optional header values

def retrieve_content(url, data=None):
    global _headers
    try:
        req = urllib2.Request("".join([url[i].replace(' ', '%20') if i > url.find('?') else url[i] for i in xrange(len(url))]), data, _headers)
        retval = urllib2.urlopen(req).read()
    except Exception, ex:
        retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    return retval or ""

def scan_page(url, data=None):
    retval = False
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>\w+)=)(?P<value>[^&]+)", current):
                print "* scanning %s parameter '%s'" % (phase, match.group("parameter"))
                prefix, suffix = ["".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in xrange(2)]
                tampered = current.replace(match.group(0), "%s%s%s%s" % (match.group(1), prefix, "".join(random.sample(SPECIAL_CHAR_POOL, len(SPECIAL_CHAR_POOL))), suffix))
                content = retrieve_content(tampered, data) if phase is GET else retrieve_content(url, tampered)
                sample = reduce(lambda x,y: x or y, [re.search(regex, content, re.I | re.S) for regex in ("%s(.*)%s" % (prefix, suffix), "%s([^\s]+)" % prefix, "([^\s]+)%s" % suffix)])
                if sample:
                    for regex, condition in XSS_PATTERNS:
                        if re.search(regex % sample.group(1), content, re.I | re.S):
                            if all([char in sample.group(1) for char in condition]):
                                print " (i) %s parameter '%s' appears to be XSS vulnerable! (%s filtering)" % (phase, match.group("parameter"), "no" if all([char in sample.group(1) for char in SPECIAL_CHAR_POOL]) else "some")
                                retval = True
                            break
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    if proxy:
        urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})))
    _headers = {COOKIE: cookie, UA: ua, REFERER: referer}
    for empty in filter(None, [name if _headers[name] is None else None for name in _headers.keys()]):
        del _headers[empty]

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.htm?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP user-agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy to be used (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
        print "\nscan results: %s vulnerabilities found" % ("possible" if result else "no")
    else:
        parser.print_help()