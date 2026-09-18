#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""وحدة الحاقن - إرسال الحمولات."""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import time

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def send_request(url, method='GET', params=None, cookies=None, timeout=10):
    """إرسال طلب HTTP."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)'}
        if cookies:
            headers['Cookie'] = '; '.join([f"{k}={v}" for k, v in cookies.items()])
        
        if method.upper() == 'POST':
            data = urllib.parse.urlencode(params).encode('utf-8')
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            request = urllib.request.Request(url, data=data, headers=headers, method='POST')
        else:
            if params:
                sep = '&' if '?' in url else '?'
                url = f"{url}{sep}{urllib.parse.urlencode(params)}"
            request = urllib.request.Request(url, headers=headers, method='GET')
        
        with urllib.request.urlopen(request, timeout=timeout, context=SSL_CONTEXT) as response:
            html_bytes = response.read()
            try:
                return response.status, html_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return response.status, html_bytes.decode('latin-1')
    except urllib.error.HTTPError as e:
        html_bytes = e.read()
        try:
            return e.code, html_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return e.code, html_bytes.decode('latin-1')
    except urllib.error.URLError as e:
        raise ConnectionError(f"تعذر الوصول: {e.reason}")


def inject_payloads(url, param_name, payloads, method='GET', cookies=None, delay=0.5):
    """إرسال كل الحمولات."""
    results = []
    total = len(payloads)
    
    for i, payload in enumerate(payloads, 1):
        print(f"  [{i}/{total}] إرسال: {payload[:50]}...")
        try:
            status, response = send_request(url, method, {param_name: payload}, cookies)
            results.append({'payload': payload, 'status': status, 'response': response})
            print(f"      ✅ الحالة: {status} | حجم الرد: {len(response)}")
        except Exception as e:
            print(f"      ❌ فشل: {e}")
            results.append({'payload': payload, 'status': 0, 'response': '', 'error': str(e)})
        time.sleep(delay)
    return results


def load_payloads(file_path):
    """قراءة الحمولات."""
    payloads = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                payloads.append(line)
    return payloads