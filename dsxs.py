#!/usr/bin/python3
import optparse, random, re, string, urllib, urllib.parse, urllib.request  # Python 3 required

NAME, VERSION, AUTHOR, LICENSE = "Damn Small XSS Scanner (DSXS) < 100 LoC (Lines of Code)", "0.3a", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

SMALLER_CHAR_POOL    = ('<', '>')                                                           # characters used for XSS tampering of parameter values (smaller set - for avoiding possible SQLi errors)
LARGER_CHAR_POOL     = ('\'', '"', '>', '<', ';')                                           # characters used for XSS tampering of parameter values (larger set)
GET, POST            = "GET", "POST"                                                        # enumerator-like values used for marking current phase
PREFIX_SUFFIX_LENGTH = 5                                                                    # length of random prefix/suffix used in XSS tampering
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                                     # optional HTTP header names
TIMEOUT = 30                                                                                # connection timeout in seconds
DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"  # filtering regex used before DOM XSS search

REGULAR_PATTERNS = (                                                                        # each (regular pattern) item consists of (r"context regex", (prerequisite unfiltered characters), "info text", r"content removal regex")
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'), "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", r"\\'"),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", r'\\"'),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", None),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',), "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',), "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
)

DOM_PATTERNS = (                                                                            # each (dom pattern) item consists of r"recognition regex"
    r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
    r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>",
)

_headers = {}                                                                               # used for storing dictionary with optional header values

def _retrieve_content(url, data=None):
    try:
        req = urllib.request.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url))), data.encode("utf-8", "ignore") if data else None, _headers)
        retval = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        retval = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
    return (retval.decode("utf-8", "ignore") if hasattr(retval, "decode") else "") or ""

def _contains(content, chars):
    content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
    return all(char in content for char in chars)

def scan_page(url, data=None):
    retval, usable = False, False
    url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>", data) if data else data
    original = re.sub(DOM_FILTER_REGEX, "", _retrieve_content(url, data))
    dom = next(filter(None, (re.search(_, original) for _ in DOM_PATTERNS)), None)
    if dom:
        print(" (i) page itself appears to be XSS vulnerable (DOM)")
        print("  (o) ...%s..." % dom.group(0))
        retval = True
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                found, usable = False, True
                print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in range(2))
                for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                    if not found:
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote("%s%s%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix, "".join(random.sample(pool, len(pool))), suffix))))
                        content = (_retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)).replace("%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)
                        for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                            filtered = re.sub(content_removal_regex or "", "", content)
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)
                                if context and not found and sample.group(1).strip():
                                    if _contains(sample.group(1), condition):
                                        print(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                        found = retval = True
                                    break
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None)

if __name__ == "__main__":
    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
        print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    else:
        parser.print_help()