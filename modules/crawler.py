#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""وحدة الزاحف - استخراج النماذج والمدخلات."""

import urllib.request
import urllib.parse
import urllib.error
import re
import ssl

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def fetch_page(url, timeout=10, cookies=None):
    """جلب صفحة HTML."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)'}
        if cookies:
            headers['Cookie'] = '; '.join([f"{k}={v}" for k, v in cookies.items()])
        
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout, context=SSL_CONTEXT) as response:
            html_bytes = response.read()
            try:
                return html_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return html_bytes.decode('latin-1')
    except urllib.error.HTTPError as e:
        raise ConnectionError(f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise ConnectionError(f"تعذر الوصول: {e.reason}")


def extract_forms(html):
    """استخراج النماذج من HTML."""
    forms = []
    form_pattern = re.compile(r'<form\b[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    attr_pattern = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    
    for form_match in form_pattern.finditer(html):
        form_tag_and_content = form_match.group(0)
        form_content = form_match.group(1)
        form_tag_match = re.search(r'<form\b[^>]*>', form_tag_and_content, re.IGNORECASE)
        form_tag = form_tag_match.group(0) if form_tag_match else ''
        attributes = dict(attr_pattern.findall(form_tag))
        
        form_data = {
            'action': attributes.get('action', '').strip(),
            'method': attributes.get('method', 'GET').upper().strip(),
            'inputs': extract_inputs(form_content)
        }
        if form_data['inputs']:
            forms.append(form_data)
    return forms


def extract_inputs(form_content):
    """استخراج المدخلات."""
    inputs = []
    input_pattern = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
    textarea_pattern = re.compile(r'<textarea\b[^>]*>(.*?)</textarea>', re.IGNORECASE | re.DOTALL)
    attr_pattern = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    
    for match in input_pattern.finditer(form_content):
        tag = match.group(0)
        attrs = dict(attr_pattern.findall(tag))
        input_data = {
            'name': attrs.get('name', '').strip(),
            'type': attrs.get('type', 'text').lower().strip(),
            'value': attrs.get('value', '').strip()
        }
        if input_data['name'] and input_data['type'] not in ('submit', 'button', 'reset', 'image'):
            inputs.append(input_data)
    
    for match in textarea_pattern.finditer(form_content):
        tag = match.group(0)
        attrs = dict(attr_pattern.findall(tag))
        input_data = {
            'name': attrs.get('name', '').strip(),
            'type': 'textarea',
            'value': attrs.get('value', '').strip()
        }
        if input_data['name']:
            inputs.append(input_data)
    return inputs