"""
XSStrike-Lite
Browser Validator

الوظيفة:
- تشغيل Google Chrome بواسطة Playwright.
- تسجيل الدخول إلى DVWA.
- ضبط مستوى الأمان إلى low.
- اختبار Reflected XSS.
- التحقق من تنفيذ JavaScript فعليًا داخل المتصفح.
- استخدام DOM Marker و Window Marker.
- عدم اعتبار Reflection وحده XSS مؤكدة.

مخصص للاختبارات التعليمية المحلية مثل DVWA.
"""

from __future__ import annotations

import time
from typing import Optional
from urllib.parse import (
    urlencode,
    urlsplit,
    urlunsplit,
    parse_qsl,
)

from playwright.sync_api import (
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError,
)


class BrowserValidator:
    """
    مسؤول عن التحقق من تنفيذ XSS
    باستخدام متصفح Google Chrome حقيقي.
    """

    def __init__(
        self,
        headless: bool = False,
        timeout: int = 10000,
        keep_browser_open: bool = True,
    ):
        self.headless = headless
        self.timeout = timeout
        self.keep_browser_open = keep_browser_open

    # ============================================================
    # بناء URL الاختبار
    # ============================================================

    @staticmethod
    def build_test_url(
        url: str,
        parameter: str,
        payload: str,
    ) -> str:
        """
        إضافة Payload إلى GET parameter.
        """

        parts = urlsplit(url)

        query_items = parse_qsl(
            parts.query,
            keep_blank_values=True,
        )

        query = dict(query_items)

        query[parameter] = payload

        new_query = urlencode(
            query,
            doseq=True,
        )

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                new_query,
                parts.fragment,
            )
        )

    # ============================================================
    # تجهيز Cookies
    # ============================================================

    @staticmethod
    def prepare_cookies(
        base_url: str,
        cookies: Optional[dict],
    ) -> list:
        """
        تحويل Cookies من dict إلى صيغة Playwright.
        """

        if not cookies:
            return []

        prepared = []

        for name, value in cookies.items():

            prepared.append(
                {
                    "name": str(name),
                    "value": str(value),
                    "url": base_url,
                }
            )

        return prepared

    # ============================================================
    # تسجيل الدخول إلى DVWA
    # ============================================================

    def login_to_dvwa(
        self,
        page,
        username: str,
        password: str,
        base_url: str,
    ) -> bool:
        """
        تسجيل الدخول إلى DVWA.
        """

        login_url = (
            base_url.rstrip("/")
            + "/login.php"
        )

        print()
        print("🔐 تسجيل الدخول إلى DVWA...")
        print(f"👤 Username: {username}")

        try:

            # ----------------------------------------------------
            # فتح صفحة Login
            # ----------------------------------------------------

            page.goto(
                login_url,
                wait_until="domcontentloaded",
                timeout=self.timeout,
            )

            print(
                "✅ تم فتح صفحة تسجيل الدخول."
            )

            # ----------------------------------------------------
            # اسم المستخدم
            # ----------------------------------------------------

            username_input = page.locator(
                'input[name="username"]'
            )

            username_input.fill(
                username
            )

            # ----------------------------------------------------
            # كلمة المرور
            # ----------------------------------------------------

            password_input = page.locator(
                'input[name="password"]'
            )

            password_input.fill(
                password
            )

            print(
                "📝 تم إدخال بيانات الدخول."
            )

            # ----------------------------------------------------
            # الضغط على Login
            # ----------------------------------------------------

            page.locator(
                'input[type="submit"]'
            ).click()

            page.wait_for_load_state(
                "domcontentloaded",
                timeout=self.timeout,
            )

            print(
                "🔄 تم إرسال بيانات الدخول."
            )

            # ----------------------------------------------------
            # التحقق من نجاح Login
            # ----------------------------------------------------

            current_url = page.url.lower()

            if "login.php" not in current_url:

                print(
                    "✅ تم تسجيل الدخول إلى DVWA بنجاح."
                )

                return True

            # ----------------------------------------------------
            # فحص وجود Logout
            # ----------------------------------------------------

            try:

                logout_count = page.locator(
                    'a[href*="logout"]'
                ).count()

                if logout_count > 0:

                    print(
                        "✅ تم تسجيل الدخول إلى DVWA بنجاح."
                    )

                    return True

            except Exception:
                pass

            print(
                "❌ فشل تسجيل الدخول إلى DVWA."
            )

            return False

        except PlaywrightTimeoutError:

            print(
                "❌ انتهت مهلة تسجيل الدخول."
            )

            return False

        except Exception as exc:

            print(
                f"❌ خطأ أثناء تسجيل الدخول: {exc}"
            )

            return False

    # ============================================================
    # اختبار GET
    # ============================================================

    def validate_get(
        self,
        url: str,
        parameter: str,
        username: str = "admin",
        password: str = "password",
        base_url: Optional[str] = None,
    ) -> dict:
        """
        اختبار Reflected XSS باستخدام Google Chrome.

        يتم إنشاء Marker فريد.
        إذا قام JavaScript بتنفيذ Payload،
        يتم تسجيل Marker في DOM و window.
        """

        # --------------------------------------------------------
        # Marker فريد
        # --------------------------------------------------------

        marker = (
            "XSSTRIKE_CONFIRMED_"
            f"{int(time.time() * 1000)}"
        )

        # --------------------------------------------------------
        # Payload اختبار آمن
        #
        # لا يستخدم alert().
        #
        # يقوم عند التنفيذ بـ:
        #
        # 1. وضع Marker داخل window
        # 2. وضع Marker داخل DOM
        #
        # وهذا يسمح لنا بإثبات التنفيذ.
        # --------------------------------------------------------

        payload = (
            "<script>"
            f"window.__XSSTRIKE_CONFIRMED__="
            f"'{marker}';"
            f"document.body.setAttribute("
            f"'data-xsstrike-confirmed',"
            f"'{marker}'"
            f");"
            "</script>"
        )

        # --------------------------------------------------------
        # إنشاء URL
        # --------------------------------------------------------

        test_url = self.build_test_url(
            url=url,
            parameter=parameter,
            payload=payload,
        )

        # --------------------------------------------------------
        # تحديد Base URL
        # --------------------------------------------------------

        if base_url is None:

            parts = urlsplit(url)

            base_url = (
                f"{parts.scheme}://"
                f"{parts.netloc}"
            )

            if "/dvwa" in parts.path.lower():

                base_url += "/dvwa"

        # --------------------------------------------------------
        # النتيجة
        # --------------------------------------------------------

        result = {
            "confirmed": False,
            "marker": marker,
            "url": test_url,
            "parameter": parameter,
            "payload": payload,
            "browser": "Google Chrome",
            "login_success": False,
            "security_level": "low",
            "dom_marker": None,
            "window_marker": None,
            "page_title": "",
            "console_messages": [],
            "javascript_errors": [],
            "error": None,
        }

        # ========================================================
        # معلومات الاختبار
        # ========================================================

        print()
        print("=" * 70)
        print("🧪 XSStrike-Lite Browser Validator")
        print("=" * 70)

        print(
            f"🎯 الهدف       : {url}"
        )

        print(
            f"📝 المعامل     : {parameter}"
        )

        print(
            "🌐 المتصفح     : Google Chrome"
        )

        print(
            "🔐 DVWA        : admin / password"
        )

        print(
            "🛡️ Security    : low"
        )

        print(
            f"🔑 Marker      : {marker}"
        )

        print(
            f"🌐 Base URL    : {base_url}"
        )

        try:

            with sync_playwright() as playwright:

                # =================================================
                # تشغيل Google Chrome
                # =================================================

                print()
                print(
                    "🚀 تشغيل Google Chrome..."
                )

                browser = playwright.chromium.launch(
                    channel="chrome",
                    headless=self.headless,
                )

                # =================================================
                # إنشاء Context
                # =================================================

                context = browser.new_context()

                context.set_default_timeout(
                    self.timeout
                )

                # =================================================
                # إضافة security=low
                # =================================================

                print()
                print(
                    "🛡️ ضبط DVWA Security = low..."
                )

                context.add_cookies(
                    [
                        {
                            "name": "security",
                            "value": "low",
                            "url": base_url,
                        }
                    ]
                )

                print(
                    "✅ تم ضبط Security = low."
                )

                # =================================================
                # إنشاء Page
                # =================================================

                page = context.new_page()

                page.set_default_timeout(
                    self.timeout
                )

                # =================================================
                # مراقبة Console
                # =================================================

                console_messages = []

                def handle_console(message):

                    console_messages.append(
                        {
                            "type": message.type,
                            "text": message.text,
                        }
                    )

                page.on(
                    "console",
                    handle_console,
                )

                # =================================================
                # مراقبة أخطاء JavaScript
                # =================================================

                javascript_errors = []

                def handle_page_error(error):

                    javascript_errors.append(
                        str(error)
                    )

                page.on(
                    "pageerror",
                    handle_page_error,
                )

                # =================================================
                # تسجيل الدخول
                # =================================================

                login_success = self.login_to_dvwa(
                    page=page,
                    username=username,
                    password=password,
                    base_url=base_url,
                )

                result["login_success"] = (
                    login_success
                )

                if not login_success:

                    result["error"] = (
                        "فشل تسجيل الدخول إلى DVWA."
                    )

                    print()
                    print(
                        "🛑 تم إيقاف الاختبار."
                    )

                    if self.keep_browser_open:

                        print()
                        input(
                            "اضغط Enter لإغلاق Google Chrome..."
                        )

                    browser.close()

                    return result

                # =================================================
                # التأكد من security cookie
                # =================================================

                print()
                print(
                    "🔎 التحقق من DVWA Security..."
                )

                try:

                    cookies_now = (
                        context.cookies()
                    )

                    security_value = None

                    for cookie in cookies_now:

                        if (
                            cookie["name"]
                            == "security"
                        ):

                            security_value = (
                                cookie["value"]
                            )

                    if security_value:

                        print(
                            f"✅ Security Cookie = "
                            f"{security_value}"
                        )

                    else:

                        print(
                            "⚠️ لم يتم العثور على "
                            "Security Cookie."
                        )

                except Exception:

                    print(
                        "⚠️ تعذر قراءة Security Cookie."
                    )

                # =================================================
                # فتح صفحة XSS
                # =================================================

                print()
                print(
                    "📄 فتح صفحة XSS..."
                )

                print(
                    f"🔗 {test_url}"
                )

                page.goto(
                    test_url,
                    wait_until="domcontentloaded",
                    timeout=self.timeout,
                )

                print(
                    "✅ تم فتح صفحة XSS."
                )

                # =================================================
                # انتظار تنفيذ JavaScript
                # =================================================

                print()
                print(
                    "⏳ انتظار تنفيذ JavaScript..."
                )

                page.wait_for_timeout(
                    1500
                )

                # =================================================
                # فحص DOM Marker
                # =================================================

                print()
                print(
                    "🔎 فحص DOM Marker..."
                )

                try:

                    dom_marker = page.locator(
                        "body"
                    ).get_attribute(
                        "data-xsstrike-confirmed"
                    )

                except Exception:

                    dom_marker = None

                result["dom_marker"] = (
                    dom_marker
                )

                if dom_marker == marker:

                    print(
                        "✅ DOM Marker موجود."
                    )

                else:

                    print(
                        "❌ DOM Marker غير موجود."
                    )

                # =================================================
                # فحص Window Marker
                # =================================================

                print()
                print(
                    "🔎 فحص Window Marker..."
                )

                try:

                    window_marker = page.evaluate(
                        """
                        () => window.__XSSTRIKE_CONFIRMED__ || null
                        """
                    )

                except Exception:

                    window_marker = None

                result["window_marker"] = (
                    window_marker
                )

                if window_marker == marker:

                    print(
                        "✅ Window Marker موجود."
                    )

                else:

                    print(
                        "❌ Window Marker غير موجود."
                    )

                # =================================================
                # تحديد Confirmed XSS
                # =================================================

                if (
                    dom_marker == marker
                    and window_marker == marker
                ):

                    result["confirmed"] = True

                    print()
                    print("=" * 70)
                    print("🔥 CONFIRMED XSS")
                    print("=" * 70)

                    print(
                        "✅ تم تنفيذ JavaScript فعليًا."
                    )

                    print(
                        "✅ DOM Marker = صحيح"
                    )

                    print(
                        "✅ Window Marker = صحيح"
                    )

                    print("=" * 70)

                else:

                    result["confirmed"] = False

                    print()
                    print("=" * 70)
                    print("⚠️ XSS غير مؤكدة")
                    print("=" * 70)

                    print(
                        "❌ لم يتم إثبات تنفيذ JavaScript."
                    )

                    print(
                        "ℹ️ Reflection وحده لا يكفي."
                    )

                    print("=" * 70)

                # =================================================
                # معلومات إضافية
                # =================================================

                try:

                    result["page_title"] = (
                        page.title()
                    )

                except Exception:

                    result["page_title"] = ""

                result[
                    "console_messages"
                ] = console_messages

                result[
                    "javascript_errors"
                ] = javascript_errors

                # =================================================
                # إبقاء Chrome مفتوحًا
                # =================================================

                if self.keep_browser_open:

                    print()
                    print("=" * 70)
                    print(
                        "👀 Google Chrome ما زال مفتوحًا."
                    )
                    print("=" * 70)

                    print(
                        "يمكنك الآن فحص صفحة DVWA يدويًا."
                    )

                    print()

                    input(
                        "اضغط Enter لإغلاق Google Chrome..."
                    )

                # =================================================
                # إغلاق Chrome
                # =================================================

                print()
                print(
                    "🛑 إغلاق Google Chrome..."
                )

                browser.close()

        except PlaywrightTimeoutError as exc:

            result["error"] = (
                f"انتهت مهلة المتصفح: {exc}"
            )

            print()
            print(
                "❌ Browser Timeout"
            )

            print(
                result["error"]
            )

        except Exception as exc:

            result["error"] = str(exc)

            print()
            print(
                "❌ Browser Error"
            )

            print(
                result["error"]
            )

        return result


# =================================================================
# واجهة عامة
# =================================================================

def validate_xss(
    url: str,
    parameter: str,
    username: str = "admin",
    password: str = "password",
    base_url: Optional[str] = None,
    headless: bool = False,
    keep_browser_open: bool = True,
) -> dict:

    validator = BrowserValidator(
        headless=headless,
        timeout=10000,
        keep_browser_open=keep_browser_open,
    )

    return validator.validate_get(
        url=url,
        parameter=parameter,
        username=username,
        password=password,
        base_url=base_url,
    )


# =================================================================
# اختبار مستقل على DVWA
# =================================================================

def test_browser_validator():

    url = (
        "http://localhost/"
        "dvwa/vulnerabilities/xss_r/"
    )

    parameter = "name"

    print()
    print("=" * 70)
    print(
        "🧪 اختبار Browser Validator على DVWA"
    )
    print("=" * 70)

    result = validate_xss(
        url=url,
        parameter=parameter,
        username="admin",
        password="password",
        base_url="http://localhost/dvwa",
        headless=False,
        keep_browser_open=True,
    )

    print()
    print("=" * 70)
    print("📊 النتيجة النهائية")
    print("=" * 70)

    print(
        f"🔐 Login Success : "
        f"{result['login_success']}"
    )

    print(
        f"🛡️ Security      : "
        f"{result['security_level']}"
    )

    print(
        f"🔥 Confirmed XSS : "
        f"{result['confirmed']}"
    )

    print(
        f"🔎 DOM Marker     : "
        f"{result['dom_marker']}"
    )

    print(
        f"🔎 Window Marker  : "
        f"{result['window_marker']}"
    )

    if result["error"]:

        print()
        print(
            "❌ Error:"
        )

        print(
            result["error"]
        )

    print("=" * 70)


# =================================================================
# Main
# =================================================================

if __name__ == "__main__":
    test_browser_validator()