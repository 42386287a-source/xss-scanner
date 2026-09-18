#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""وحدة الكاشف - فحص الردود."""

import re
import html


def is_payload_reflected(payload, response_html):
    """التحقق من انعكاس الحمولة."""
    result = {'reflected': False, 'encoded': False, 'context': 'غير موجودة'}
    
    if payload in response_html:
        result['reflected'] = True
        result['context'] = detect_context(payload, response_html)
        return result
    
    encoded = html.escape(payload)
    if encoded != payload and encoded in response_html:
        result['reflected'] = True
        result['encoded'] = True
        result['context'] = 'مُرمزة (آمنة)'
        return result
    
    return result


def detect_context(payload, response_html):
    """تحديد السياق."""
    idx = response_html.find(payload)
    if idx == -1:
        return 'غير معروف'
    before = response_html[max(0, idx - 200):idx]
    
    if '<script' in before.lower() and '</script>' not in before.lower():
        return 'داخل <script> (خطير جداً!)'
    if re.search(r'=\s*["\'][^"\']*$', before):
        return 'داخل خاصية HTML (خطير!)'
    if '<!--' in before and '-->' not in before:
        return 'داخل تعليق HTML (خطير!)'
    return 'نص عادي (قد يكون آمناً)'


def analyze_result(result):
    """تحليل النتيجة."""
    payload = result.get('payload', '')
    response = result.get('response', '')
    
    if not response:
        return {'vulnerable': False, 'severity': 'غير معروف', 'message': 'لا رد'}
    
    reflection = is_payload_reflected(payload, response)
    
    if not reflection['reflected']:
        return {'vulnerable': False, 'severity': 'لا يوجد', 'message': 'لم تنعكس'}
    
    if reflection['encoded']:
        return {'vulnerable': False, 'severity': 'منخفضة',
                'message': f"مُرمزة ({reflection['context']})", 'reflection': reflection}
    
    severity = 'حرجة' if ('<script>' in reflection['context'] or 'خاصية' in reflection['context']) else 'عالية'
    return {'vulnerable': True, 'severity': severity,
            'message': f"ثغرة! {reflection['context']}", 'reflection': reflection}


def scan_results(results):
    """فحص كل النتائج."""
    vulnerabilities = []
    for i, result in enumerate(results, 1):
        print(f"  [{i}/{len(results)}] تحليل: {result['payload'][:40]}...")
        analysis = analyze_result(result)
        if analysis['vulnerable']:
            print(f"      🚨 ثغرة! ({analysis['severity']})")
            vulnerabilities.append({
                'payload': result['payload'],
                'status': result['status'],
                'response': result.get('response', ''),
                'analysis': analysis
            })
        else:
            print(f"      ✅ آمن")
    return vulnerabilities