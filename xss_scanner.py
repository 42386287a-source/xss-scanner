#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSStrike-Lite: أداة كشف ثغرات XSS
مشروع تخرج - Pure Python
"""

import argparse
import sys
import os
import json
import logging
from pathlib import Path
from datetime import datetime

# ==================== استيراد الوحدات ====================
from modules.reporter import generate_report


# ==================== إعدادات ثابتة ====================
VERSION = "1.1.0"
TOOL_NAME = "XSStrike-Lite"
DEFAULT_LOG_DIR = "logs"
DEFAULT_PAYLOAD_FILE = "payloads/xss_payloads.txt"


# ==================== نظام السجلات (Logging) ====================
def setup_logger(log_level="INFO"):
    """إعداد نظام السجلات."""
    if not os.path.exists(DEFAULT_LOG_DIR):
        os.makedirs(DEFAULT_LOG_DIR)
    
    log_file = os.path.join(
        DEFAULT_LOG_DIR,
        f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    
    logger = logging.getLogger(TOOL_NAME)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    if logger.handlers:
        logger.handlers.clear()
    
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


# ==================== تحميل الإعدادات ====================
def load_config(config_path):
    """تحميل الإعدادات من ملف JSON."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"ملف الإعدادات غير موجود: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except json.JSONDecodeError as e:
        raise ValueError(f"ملف الإعدادات تالف (JSON غير صالح): {e}")


# ==================== واجهة سطر الأوامر ====================
def build_parser():
    """بناء محلل الأوامر."""
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{VERSION} - أداة كشف ثغرات XSS",
        epilog="مثال: python xss_scanner.py scan --url http://localhost/dvwa/"
    )
    
    parser.add_argument('--version', action='version', version=f'{TOOL_NAME} v{VERSION}')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='مستوى السجلات')
    parser.add_argument('--config', default=None, help='مسار ملف الإعدادات (JSON)')
    
    subparsers = parser.add_subparsers(dest='command', help='الأوامر الفرعية')
    
    # ----- أمر scan -----
    scan_parser = subparsers.add_parser('scan', help='فحص موقع كامل')
    scan_parser.add_argument('--url', required=True, help='رابط الموقع')
    scan_parser.add_argument('--payload-file', default=DEFAULT_PAYLOAD_FILE,
                             help='ملف الحمولات')
    scan_parser.add_argument('--output', default='report.html',
                             help='ملف التقرير')
    scan_parser.add_argument('--login-url', default=None,
                             help='رابط تسجيل الدخول (لتسجيل الدخول تلقائياً)')
    scan_parser.add_argument('--username', default=None,
                             help='اسم المستخدم')
    scan_parser.add_argument('--password', default=None,
                             help='كلمة المرور')
    scan_parser.add_argument('--type', choices=['reflected', 'stored', 'dom'],
                             default='reflected', help='نوع XSS')
    scan_parser.add_argument('--detect-waf', action='store_true',
                             help='كشف WAF')
    
    # ----- أمر check -----
    check_parser = subparsers.add_parser('check', help='فحص مدخل واحد')
    check_parser.add_argument('--url', required=True, help='رابط الصفحة')
    check_parser.add_argument('--param', required=True, help='اسم المعامل')
    check_parser.add_argument('--method', choices=['GET', 'POST'], default='GET',
                              help='طريقة الإرسال')
    
    return parser


# ==================== معالجة الأخطاء ====================
def handle_error(error, logger):
    """معالجة الأخطاء بشكل موحد."""
    if isinstance(error, FileNotFoundError):
        msg = str(error)
        if msg.startswith("الملف غير موجود: "):
            msg = msg.replace("الملف غير موجود: ", "", 1)
        logger.error(f"❌ {msg}")
    elif isinstance(error, PermissionError):
        logger.error(f"❌ لا توجد صلاحيات: {error}")
    elif isinstance(error, ConnectionError):
        logger.error(f"❌ فشل الاتصال: {error}")
    elif isinstance(error, TimeoutError):
        logger.error(f"❌ انتهت المهلة: {error}")
    elif isinstance(error, ValueError):
        logger.error(f"❌ قيمة غير صالحة: {error}")
    elif isinstance(error, KeyboardInterrupt):
        logger.warning("\n⚠️  تم الإيقاف بواسطة المستخدم")
    else:
        logger.error(f"❌ خطأ غير متوقع: {type(error).__name__}: {error}")
    
    sys.exit(1)


# ==================== أوامر التشغيل ====================
def run_scan(args, logger):
    """تنفيذ أمر الفحص الكامل."""
    logger.info(f"🔍 بدء الفحص على: {args.url}")
    logger.info(f"📄 ملف الحمولات: {args.payload_file}")
    logger.info(f"📊 ملف التقرير: {args.output}")
    logger.info(f"🔧 النوع: {args.type}")
    
    if not os.path.exists(args.payload_file):
        raise FileNotFoundError(f"ملف الحمولات غير موجود: {args.payload_file}")
    
    from modules.crawler import fetch_page, extract_forms, login
    from modules.injector import inject_payloads, load_payloads
    from modules.detector import scan_results
    
    # إعدادات افتراضية
    cookies = {}
    delay = 0.2
    timeout = 10
    
    # تسجيل الدخول التلقائي
    if hasattr(args, 'login_url') and args.login_url:
        logger.info(f"🔐 تسجيل الدخول تلقائياً إلى: {args.login_url}")
        cookies = login(
            login_url=args.login_url,
            username=args.username,
            password=args.password,
            timeout=timeout,
            check_url=args.url
        )
        logger.info(f"✅ تم تسجيل الدخول. الكوكيز: {list(cookies.keys())}")
    elif hasattr(args, 'config') and args.config:
        config = load_config(args.config)
        if 'cookies' in config:
            cookies = config['cookies']
        if 'delay' in config:
            delay = config['delay']
        if 'timeout' in config:
            timeout = config['timeout']
    
    # كشف WAF إذا طُلب
    if hasattr(args, 'detect_waf') and args.detect_waf:
        logger.info("🛡️ كشف WAF...")
        from modules.waf_detector import detect_waf
    
        waf_result = detect_waf(args.url, timeout=timeout, cookies=cookies)
    
        if waf_result['detected']:
            logger.warning(f"🚨 WAF مكتشف: {waf_result['name']}")
            for evidence in waf_result['evidence']:
                logger.warning(f"  - {evidence}")
        else:
            logger.info("✅ لا يوجد WAF")
        print()


    # المرحلة 1: جلب الصفحة
    logger.info("🌐 [1/4] جلب الصفحة...")
    html = fetch_page(args.url, timeout=timeout, cookies=cookies)
    logger.info(f"✅ تم جلب الصفحة ({len(html)} حرف)")
    
    # المرحلة 2: استخراج النماذج
    logger.info("📋 [2/4] استخراج النماذج...")
    forms = extract_forms(html)
    logger.info(f"✅ تم اكتشاف {len(forms)} نموذجاً")
    
    if not forms and args.type != 'dom':
        logger.warning("⚠️ لم يتم اكتشاف أي نماذج")
        return
    
    # المرحلة 3: تحميل الحمولات
    logger.info(f"📦 [3/4] تحميل الحمولات...")
    payloads = load_payloads(args.payload_file)
    logger.info(f"✅ تم تحميل {len(payloads)} حمولة")
    
    # المرحلة 4: حسب النوع
    all_results = []
    
    if args.type == 'dom':
        # ========== DOM-based XSS ==========
        logger.info("💉 [4/4] تحليل DOM-based XSS...")
        from modules.dom_analyzer import analyze_dom
        
        dom_result = analyze_dom(html)
        
        if dom_result['vulnerable']:
            logger.warning(f"🚨 تم اكتشاف {len(dom_result['sinks'])} DOM Sink!")
            for sink in dom_result['sinks']:
                logger.warning(f"  - {sink['type']}: {sink['code'][:50]}")
                all_results.append({
                    'payload': sink['code'][:100],
                    'status': 'N/A',
                    'response': sink['context'],
                    'analysis': {
                        'vulnerable': True,
                        'severity': 'عالية',
                        'message': f"DOM Sink: {sink['type']}",
                        'reflection': {'context': sink['type']}
                    }
                })
        else:
            logger.info("✅ لا توجد ثغرات DOM محتملة")
    
    elif args.type == 'stored':
    # ========== Stored XSS ==========
        logger.info("💉 [4/4] فحص Stored XSS...")
    
    # اختبار كل مدخل
        for i, form in enumerate(forms, 1):
            logger.info(f"  📝 النموذج {i}: {len(form['inputs'])} مدخل")
        
        # أرسل حمولة اختبارية
            test_payload = "<script>alert('StoredXSS_TEST')</script>"
        
        # تجهيز بيانات النموذج (كل الحقول معاً)
            form_data = {}
            for inp in form['inputs']:
                if inp['name'] == 'btnSign':
                # زر الإرسال
                    continue
                form_data[inp['name']] = test_payload
            form_data['btnSign'] = 'Sign Guestbook'
        
        # إرسال النموذج (POST)
            logger.info(f"    💉 إرسال حمولة اختبارية...")
        
            from modules.injector import send_request
        
            try:
                status, response = send_request(
                    url=args.url,
                    method='POST',
                    params=form_data,
                    cookies=cookies
                )
                logger.info(f"    ✅ تم الإرسال. الحالة: {status}")
            except Exception as e:
                logger.error(f"    ❌ فشل الإرسال: {e}")
                continue
        
        # إعادة تحميل الصفحة (GET) للتحقق
            logger.info(f"    🔄 إعادة تحميل الصفحة للتحقق...")
            import time
            time.sleep(1)  # انتظر ثانية
        
            try:
                reloaded_html = fetch_page(args.url, timeout=timeout, cookies=cookies)
            
            # تحقق إذا كانت الحمولة موجودة
                if test_payload in reloaded_html or 'StoredXSS_TEST' in reloaded_html:
                    logger.warning(f"    🚨 ثغرة Stored XSS مؤكدة!")
                
                # إضافة النتائج لكل الحمولات
                    for payload in payloads:
                        all_results.append({
                            'payload': payload,
                            'status': 200,
                            'response': reloaded_html[:500],
                            'analysis': {
                                'vulnerable': True,
                                'severity': 'حرجة',
                                'message': 'Stored XSS مؤكدة (الحمولة تُخزّن في قاعدة البيانات)',
                                'reflection': {'context': 'Stored (مخزنة)'}
                            }
                        })
                else:
                    logger.info(f"    ✅ لا توجد ثغرة Stored")
            except Exception as e:
                logger.error(f"    ❌ فشل التحقق: {e}")
    
    else:
        # ========== Reflected XSS (الافتراضي) ==========
        logger.info("💉 [4/4] فحص Reflected XSS...")
        
        for i, form in enumerate(forms, 1):
            logger.info(f"  📝 النموذج {i}: {len(form['inputs'])} مدخل")
            
            for inp in form['inputs']:
                logger.info(f"    💉 حقن في: {inp['name']}")
                
                results = inject_payloads(
                    url=args.url,
                    param_name=inp['name'],
                    payloads=payloads,
                    method=form['method'],
                    cookies=cookies,
                    delay=delay
                )
                
                vulns = scan_results(results)
                all_results.extend(vulns)
    
    # الملخص
    print()
    print("=" * 60)
    print("📊 ملخص الفحص:")
    print("=" * 60)
    if all_results:
        logger.warning(f"🚨 تم اكتشاف {len(all_results)} ثغرة XSS!")
    else:
        logger.info("✅ لم يتم اكتشاف أي ثغرات")
    
    # إنشاء التقرير
    report_path = generate_report(
        target_url=args.url,
        vulnerabilities=all_results,
        output_file=args.output,
        forms_count=len(forms),
        payloads_count=len(payloads),
        version=VERSION
    )
    
    report_abs_path = Path(report_path).resolve()
    logger.info(f"✅ التقرير: {report_abs_path}")
    logger.info(f"🌐 افتحه: {report_abs_path.as_uri()}")

def run_check(args, logger):
    """تنفيذ أمر الفحص الفردي."""
    from modules.injector import inject_payloads, load_payloads
    from modules.detector import scan_results
    
    cookies = {}
    delay = 0.2
    
    if hasattr(args, 'config') and args.config:
        config = load_config(args.config)
        if 'cookies' in config:
            cookies = config['cookies']
        if 'delay' in config:
            delay = config['delay']
    
    payloads = load_payloads(DEFAULT_PAYLOAD_FILE)
    results = inject_payloads(args.url, args.param, payloads,
                             args.method, cookies, delay)
    vulns = scan_results(results)
    
    print()
    print("=" * 60)
    if vulns:
        logger.warning(f"🚨 تم اكتشاف {len(vulns)} ثغرة!")
    else:
        logger.info("✅ لا توجد ثغرات")


# ==================== نقطة الدخول ====================
def main():
    parser = build_parser()
    args = parser.parse_args()
    logger = setup_logger(args.log_level)
    
    print("=" * 60)
    print(f"  {TOOL_NAME} v{VERSION}")
    print("=" * 60)
    print()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    try:
        if args.command == 'scan':
            run_scan(args, logger)
        elif args.command == 'check':
            run_check(args, logger)
    except Exception as e:
        handle_error(e, logger)
    
    logger.info("✅ انتهى التنفيذ بنجاح")


if __name__ == "__main__":
    main()