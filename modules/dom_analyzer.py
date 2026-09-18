#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
وحدة تحليل DOM-based XSS
تفحص الأكواد التي تُنفّذ JavaScript.
"""

import re


def find_dom_sinks(html):
    """
    البحث عن الأماكن التي قد تُنفّذ JavaScript (DOM Sinks).
    
    الإرجاع:
        list: قائمة من القواميس، كل قاموس يمثل sink محتملاً.
    """
    sinks = []
    
    # أنماط JavaScript خطيرة (DOM Sinks)
    patterns = [
        # innerHTML
        (r'\.innerHTML\s*=\s*([^;]+)', 'innerHTML'),
        # document.write
        (r'document\.write\s*\(([^)]+)\)', 'document.write'),
        # eval
        (r'\beval\s*\(([^)]+)\)', 'eval'),
        # setTimeout / setInterval
        (r'set(?:Timeout|Interval)\s*\(([^,]+)', 'setTimeout/setInterval'),
        # location.href
        (r'location\.href\s*=\s*([^;]+)', 'location.href'),
        # location.assign
        (r'location\.assign\s*\(([^)]+)\)', 'location.assign'),
        # location.replace
        (r'location\.replace\s*\(([^)]+)\)', 'location.replace'),
        # javascript: URI
        (r'javascript:\s*([^"\'<>]+)', 'javascript: URI'),
        # src attribute
        (r'\.src\s*=\s*([^;]+)', 'src attribute'),
    ]
    
    for pattern, sink_type in patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            sinks.append({
                'type': sink_type,
                'code': match.group(0)[:100],
                'context': html[max(0, match.start() - 50):match.end() + 50]
            })
    
    return sinks


def find_user_input_sources(html):
    """
    البحث عن مصادر إدخال المستخدم (DOM Sources).
    هذه هي المدخلات التي قد تصل إلى JavaScript.
    
    الإرجاع:
        list: قائمة بالمصادر المحتملة.
    """
    sources = []
    
    patterns = [
        (r'location\.search', 'location.search'),
        (r'location\.hash', 'location.hash'),
        (r'location\.href', 'location.href'),
        (r'document\.URL', 'document.URL'),
        (r'document\.referrer', 'document.referrer'),
        (r'window\.name', 'window.name'),
    ]
    
    for pattern, source_type in patterns:
        if re.search(pattern, html, re.IGNORECASE):
            sources.append(source_type)
    
    return sources


def analyze_dom(html):
    """
    تحليل صفحة HTML بحثاً عن DOM-based XSS.
    
    الإرجاع:
        dict: يحتوي على:
              - sinks (list): الأماكن التي قد تُنفّذ JavaScript.
              - sources (list): مصادر إدخال المستخدم.
              - vulnerable (bool): هل هناك ثغرة محتملة؟
    """
    sinks = find_dom_sinks(html)
    sources = find_user_input_sources(html)
    
    # الثغرة موجودة إذا كان هناك sink + source معاً
    vulnerable = len(sinks) > 0 and len(sources) > 0
    
    return {
        'sinks': sinks,
        'sources': sources,
        'vulnerable': vulnerable
    }


# ==================== اختبار ====================
if __name__ == "__main__":
    # HTML تجريبي
    test_html = """
    <html>
    <body>
        <script>
            var name = location.hash.substring(1);
            document.getElementById('output').innerHTML = name;
        </script>
        <div id="output"></div>
    </body>
    </html>
    """
    
    print("🧪 اختبار تحليل DOM...")
    result = analyze_dom(test_html)
    
    print(f"\n📊 النتائج:")
    print(f"  Sinks: {len(result['sinks'])}")
    for sink in result['sinks']:
        print(f"    - {sink['type']}: {sink['code']}")
    
    print(f"\n  Sources: {len(result['sources'])}")
    for source in result['sources']:
        print(f"    - {source}")
    
    print(f"\n  🚨 Vulnerable: {result['vulnerable']}")