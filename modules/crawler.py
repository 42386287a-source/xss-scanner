#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
وحدة الزاحف (Crawler)
تستخرج النماذج والمدخلات من صفحة HTML.
Pure Python: تستخدم urllib و re فقط.
"""

import urllib.request
import urllib.parse
import urllib.error
import re
import ssl


# ==================== إعدادات SSL ====================
# تعطيل التحقق من شهادات SSL (للاختبار المحلي على DVWA)
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


# ==================== دوال مساعدة ====================
def fetch_page(url, timeout=10, cookies=None):
    """
    جلب صفحة HTML من رابط معين.
    
    المعاملات:
        url (str): الرابط المستهدف.
        timeout (int): مهلة الاتصال بالثواني.
        cookies (dict): قاموس يحتوي على الكوكيز.
    
    الإرجاع:
        str: محتوى الصفحة (HTML) أو None في حالة الفشل.
    """
    try:
        # تجهيز الهيدرات
        headers = {
            'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)'
        }
        
        # إضافة الكوكيز إذا وُجدت
        if cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])
            headers['Cookie'] = cookie_str
        
        # إنشاء الطلب
        request = urllib.request.Request(url, headers=headers)
        
        # تنفيذ الطلب
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=SSL_CONTEXT
        ) as response:
            # قراءة المحتوى وفك ترميزه
            html_bytes = response.read()
            try:
                html = html_bytes.decode('utf-8')
            except UnicodeDecodeError:
                html = html_bytes.decode('latin-1')
            
            return html
    
    except urllib.error.HTTPError as e:
        raise ConnectionError(f"الخادم أرجع خطأ HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise ConnectionError(f"تعذر الوصول إلى {url}: {e.reason}")
    except TimeoutError:
        raise TimeoutError(f"انتهت مهلة الاتصال بـ {url}")


def login(login_url, username, password, timeout=10, check_url=None):
    """
    تسجيل الدخول إلى DVWA باستخدام http.cookiejar.
    """
    import http.cookiejar
    
    try:
        # إنشاء Cookie Jar لحفظ الكوكيز تلقائياً
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar)
        )
        
        # الخطوة 1: جلب صفحة تسجيل الدخول
        print("  🔍 جلب صفحة تسجيل الدخول...")
        
        login_page_request = urllib.request.Request(
            login_url,
            headers={'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)'}
        )
        
        with opener.open(login_page_request, timeout=timeout) as response:
            html = response.read().decode('utf-8')
        
        # استخراج user_token
        token_match = re.search(
            r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if not token_match:
            token_match = re.search(
                r'value=["\']([^"\']+)["\']\s+name=["\']user_token["\']',
                html, re.IGNORECASE
            )
        
        user_token = token_match.group(1) if token_match else ''
        print(f"  ✅ user_token: {user_token[:20]}...")
        
        # الخطوة 2: إرسال بيانات تسجيل الدخول
        login_data = urllib.parse.urlencode({
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': user_token
        }).encode('utf-8')
        
        login_request = urllib.request.Request(
            login_url,
            data=login_data,
            headers={
                'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            method='POST'
        )
        
        with opener.open(login_request, timeout=timeout) as response:
            after_login_html = response.read().decode('utf-8')
        
        print(f"  ✅ تم إرسال بيانات الدخول")
        
        # الخطوة 3: زيارة index.php للتحقق
        index_url = login_url.replace('login.php', 'index.php')
        print(f"  🔄 زيارة {index_url}...")
        
        index_request = urllib.request.Request(
            index_url,
            headers={'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)'}
        )
        
        with opener.open(index_request, timeout=timeout) as response:
            index_html = response.read().decode('utf-8')
        
        # التحقق
        if 'Welcome to Damn Vulnerable' not in index_html and 'login.php' in index_html:
            raise ValueError("فشل تسجيل الدخول: index.php أعاد صفحة تسجيل الدخول.")
        
        print("  ✅ تم تأكيد تسجيل الدخول")
        
        # الخطوة 4: تعيين security=low
        print("  🔧 تعيين security=low...")
        security_url = login_url.replace('login.php', 'security.php')
        security_data = urllib.parse.urlencode({
            'security': 'low',
            'seclev_submit': 'Submit'
        }).encode('utf-8')
        
        security_request = urllib.request.Request(
            security_url,
            data=security_data,
            headers={
                'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            method='POST'
        )
        
        with opener.open(security_request, timeout=timeout) as response:
            response.read()
        
        print("  ✅ تم تعيين security=low")
        
        # استخراج الكوكيز من Cookie Jar
        cookies = {}
        for cookie in cookie_jar:
            cookies[cookie.name] = cookie.value
        
        # تعيين security=low محلياً
        cookies['security'] = 'low'
        
        # الخطوة 5: التحقق النهائي من الصفحة المحمية (مرن)
        if check_url:
            print(f"  🔍 التحقق النهائي: {check_url}")
            check_request = urllib.request.Request(
                check_url,
                headers={'User-Agent': 'Mozilla/5.0 (XSStrike-Lite Scanner)'}
            )
            
            with opener.open(check_request, timeout=timeout) as response:
                check_html = response.read().decode('utf-8')
                final_url = response.geturl()
            
            # التحقق المرن: إذا لم نُعَد إلى login.php، فالتسجيل ناجح
            if 'login.php' in final_url.lower() and 'login' not in check_url.lower():
                raise ValueError("فشل تسجيل الدخول: الصفحة المحمية أعادت صفحة تسجيل الدخول.")
            
            # التحقق من وجود عناصر DVWA
            if 'DVWA' in check_html or 'Vulnerability' in check_html:
                print("  ✅ التحقق نجح: الصفحة المحمية متاحة!")
            else:
                print("  ⚠️ تحذير: الصفحة المحمية قد لا تكون متاحة، لكن التسجيل يبدو ناجحاً.")
        
        return cookies
    
    except urllib.error.HTTPError as e:
        raise ConnectionError(f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise ConnectionError(f"تعذر الوصول: {e.reason}")




def extract_forms(html):
    """
    استخراج كل النماذج (Forms) من HTML.
    
    الإرجاع:
        list: قائمة من القواميس، كل قاموس يمثل نموذجاً.
    """
    forms = []
    
    # نمط للبحث عن وسم <form> كاملاً
    form_pattern = re.compile(
        r'<form\b[^>]*>(.*?)</form>',
        re.IGNORECASE | re.DOTALL
    )
    
    # نمط لاستخراج الخصائص (action, method)
    attr_pattern = re.compile(
        r'(\w+)\s*=\s*["\']([^"\']*)["\']',
        re.IGNORECASE
    )
    
    # البحث عن كل النماذج
    for form_match in form_pattern.finditer(html):
        form_tag_and_content = form_match.group(0)
        form_content = form_match.group(1)
        
        # استخراج وسم <form> نفسه (بدون المحتوى)
        form_tag_match = re.search(
            r'<form\b[^>]*>',
            form_tag_and_content,
            re.IGNORECASE
        )
        form_tag = form_tag_match.group(0) if form_tag_match else ''
        
        # استخراج الخصائص
        attributes = dict(attr_pattern.findall(form_tag))
        
        form_data = {
            'action': attributes.get('action', '').strip(),
            'method': attributes.get('method', 'GET').upper().strip(),
            'inputs': extract_inputs(form_content)
        }
        
        # إضافة النموذج فقط إذا كان يحتوي على مدخلات
        if form_data['inputs']:
            forms.append(form_data)
    
    return forms


def extract_inputs(form_content):
    """
    استخراج كل المدخلات (Inputs, Textarea) من داخل نموذج.
    
    الإرجاع:
        list: قائمة من القواميس، كل قاموس يمثل مدخلاً.
    """
    inputs = []
    
    # النمط 1: <input ...>
    input_pattern = re.compile(
        r'<input\b[^>]*>',
        re.IGNORECASE
    )
    
    # النمط 2: <textarea ...>...</textarea>
    textarea_pattern = re.compile(
        r'<textarea\b[^>]*>(.*?)</textarea>',
        re.IGNORECASE | re.DOTALL
    )
    
    # النمط لاستخراج الخصائص
    attr_pattern = re.compile(
        r'(\w+)\s*=\s*["\']([^"\']*)["\']',
        re.IGNORECASE
    )
    
    # معالجة <input>
    for match in input_pattern.finditer(form_content):
        tag = match.group(0)
        attrs = dict(attr_pattern.findall(tag))
        
        input_data = {
            'tag': 'input',
            'name': attrs.get('name', '').strip(),
            'type': attrs.get('type', 'text').lower().strip(),
            'value': attrs.get('value', '').strip()
        }
        
        # تجاهل المدخلات بدون اسم، أو مدخلات الإرسال
        if input_data['name'] and input_data['type'] not in ('submit', 'button', 'reset', 'image'):
            inputs.append(input_data)
    
    # معالجة <textarea>
    for match in textarea_pattern.finditer(form_content):
        tag = match.group(0)
        attrs = dict(attr_pattern.findall(tag))
        
        input_data = {
            'tag': 'textarea',
            'name': attrs.get('name', '').strip(),
            'type': 'textarea',
            'value': attrs.get('value', '').strip()
        }
        
        if input_data['name']:
            inputs.append(input_data)
    
    return inputs


# ==================== دالة اختبار ====================
def test_crawler(url, cookies=None):
    """
    دالة اختبار للزاحف: تجلب الصفحة وتطبع النماذج والمدخلات.
    """
    print(f"🔍 جلب الصفحة: {url}")
    html = fetch_page(url, cookies=cookies)
    
    if not html:
        print("❌ لم يتم الحصول على محتوى")
        return
    
    print(f"✅ تم جلب {len(html)} حرفاً من HTML")
    print()
    
    forms = extract_forms(html)
    print(f"📋 عدد النماذج المكتشفة: {len(forms)}")
    print()
    
    for i, form in enumerate(forms, 1):
        print(f"--- النموذج رقم {i} ---")
        print(f"  🎯 Action: {form['action'] or '(الصفحة الحالية)'}")
        print(f"  📤 Method: {form['method']}")
        print(f"  📝 عدد المدخلات: {len(form['inputs'])}")
        
        for inp in form['inputs']:
            print(f"      • name='{inp['name']}' | type='{inp['type']}' | value='{inp['value']}'")
        print()


# ==================== تشغيل مباشر للاختبار ====================
if __name__ == "__main__":
    # اختبار دالة login
    print("=" * 60)
    print("🧪 اختبار دالة المصادقة (Login)")
    print("=" * 60)
    
    try:
        cookies = login(
            login_url="http://localhost/dvwa/login.php",
            username="admin",
            password="password"
        )
        print(f"✅ تم تسجيل الدخول بنجاح!")
        print(f"🔐 الكوكيز: {cookies}")
        
        # اختبار الزاحف بعد تسجيل الدخول
        print()
        print("=" * 60)
        print("🧪 اختبار الزاحف بعد تسجيل الدخول")
        print("=" * 60)
        test_crawler(
            "http://localhost/dvwa/vulnerabilities/xss_r/",
            cookies=cookies
        )
    except Exception as e:
        print(f"❌ خطأ: {e}")