
"""
Unauthorize
Burp Suite Python/Jython extension using the legacy Extender API.

Features
--------
1. Burp Scanner active-scan integration.
2. Right-click "Unauthoize" in Proxy/Repeater.
3. Removes configurable authentication/session headers.
4. Replays the request without those headers.
5. Compares authenticated and unauthenticated responses.
6. Detects sensitive information:
   - PCI/card-like data
   - PII
   - passwords
   - secrets/API keys/tokens
   - private keys
   - cloud credentials
7. File exposure is reported as Medium unless sensitive content makes it High.
8. Adds findings to Burp Scanner.

Designed for authorized testing only.

Requires:
- Burp Suite Professional/Community with Python/Jython extension support.
- Jython 2.7.x configured under Extender > Options.
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import IScanIssue

from javax.swing import JMenuItem
from java.util import ArrayList
from java.net import URL

import threading
import hashlib
import re
import difflib


class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory):

    EXTENSION_NAME = "Unauthorize"

    # Headers that are normally used for authentication/session state.
    # CSRF headers are deliberately NOT removed by default because they are
    # request-integrity controls rather than authentication credentials.
    AUTH_HEADER_PATTERNS = [
        r"^authorization$",
        r"^proxy-authorization$",
        r"^cookie$",
        r"^x-api-key$",
        r"^x-api-token$",
        r"^x-auth-token$",
        r"^x-access-token$",
        r"^x-session-token$",
        r"^x-session-id$",
        r"^x-authentication-token$",
        r"^x-api-auth$",
        r"^api-key$",
        r"^api-token$",
        r"^access-token$",
        r"^id-token$",
        r"^session$",
        r"^sessionid$",
        r"^session-id$",
        r"^auth-token$",
        r"^auth-token$",
        r"^authentication$",
        r"^x-authorization$",
        r"^x-api-authentication$",
        r"^x-csrf-token$"  # configurable: enabled here only when explicitly listed
    ]

    # Remove this entry if CSRF tokens are required by the application and
    # should not be removed during the unauthenticated replay.
    REMOVE_CSRF_HEADER = False

    SENSITIVE_PATTERNS = [
        # Payment card / PCI-like data
        ("PCI/card number", re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        )),
        ("CVV-like field", re.compile(
            r'(?i)"?(?:cvv|cvc|securityCode|cardSecurityCode)"?\s*[:=]\s*"?\d{3,4}"?'
        )),

        # Password / authentication secrets
        ("Password", re.compile(
            r'(?i)"?(?:password|passwd|pwd|passcode)"?\s*[:=]\s*"?[^",\s}]{4,}"?'
        )),
        ("Secret", re.compile(
            r'(?i)"?(?:secret|client_secret|app_secret|private_secret)"?\s*[:=]\s*"?[^",\s}]{8,}"?'
        )),
        ("API key/token", re.compile(
            r'(?i)"?(?:api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|auth[_-]?token)"?\s*[:=]\s*"?[A-Za-z0-9_\-\.=+/]{12,}"?'
        )),
        ("JWT", re.compile(
            r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b'
        )),
        ("AWS access key", re.compile(
            r'\bAKIA[0-9A-Z]{16}\b'
        )),
        ("Private key", re.compile(
            r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
        )),

        # PII
        ("Email address", re.compile(
            r'\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b', re.I
        )),
        ("Indian PAN", re.compile(
            r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', re.I
        )),
        ("Indian Aadhaar-like number", re.compile(
            r'(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)'
        )),
        ("Phone number", re.compile(
            r'(?<!\d)(?:\+91[\s\-]?)?[6-9]\d{9}(?!\d)'
        )),
        ("US SSN-like number", re.compile(
            r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)'
        )),
        ("DOB/date of birth field", re.compile(
            r'(?i)"?(?:dob|dateOfBirth|date_of_birth|birthDate)"?\s*[:=]\s*"?[^",}]{4,}"?'
        )),
    ]

    # Frontend static resources are excluded from unauthenticated-access testing.
    EXCLUDED_EXTENSIONS = (".js", ".mjs", ".css")
    EXCLUDED_CONTENT_TYPES = (
        "text/javascript", "application/javascript",
        "application/x-javascript", "text/css"
    )

    FILE_EXTENSIONS = (
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".csv", ".txt", ".log", ".zip", ".tar", ".gz", ".7z",
        ".xml", ".json", ".yaml", ".yml", ".sql", ".bak", ".backup",
        ".conf", ".config", ".ini", ".env", ".pem", ".key", ".crt",
        ".cer", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"
    )

    BINARY_CONTENT_TYPES = (
        "application/pdf",
        "application/octet-stream",
        "application/zip",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-gzip",
        "application/msword",
        "application/vnd.",
        "image/",
        "audio/",
        "video/"
    )

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.lock = threading.RLock()

        # Prevent Burp Scanner from sending the same base request repeatedly
        # because doActiveScan is called for many insertion points.
        self.seen = set()

        # Findings already registered in Burp. Keyed by normalized URL and
        # finding category so the same endpoint is not added twice.
        self.registered_issues = set()

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        callbacks.printOutput("[+] %s loaded" % self.EXTENSION_NAME)
        callbacks.printOutput("[+] Active Scanner check registered")
        callbacks.printOutput("[+] Proxy/Repeater context menu registered")
        callbacks.printOutput("[+] Authentication headers removed: %s" %
                              ", ".join(self._display_auth_headers()))

    def _display_auth_headers(self):
        return [
            "Authorization", "Proxy-Authorization", "Cookie",
            "X-API-Key", "X-API-Token", "X-Auth-Token",
            "X-Access-Token", "X-Session-Token", "X-Session-ID",
            "X-Authentication-Token", "X-API-Auth", "API-Key",
            "API-Token", "Access-Token", "ID-Token", "Session",
            "SessionID", "Session-ID", "Auth-Token", "Authentication",
            "X-Authorization", "X-API-Authentication"
        ]

    # ------------------------------------------------------------------
    # Scanner integration
    # ------------------------------------------------------------------

    def doPassiveScan(self, baseRequestResponse):
        # This check requires an additional unauthenticated request, so
        # passive scanning intentionally does nothing.
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        try:
            request = baseRequestResponse.getRequest()
            if request is None:
                return None

            try:
                active_url = self.helpers.analyzeRequest(baseRequestResponse).getUrl()
                if self._is_excluded_resource(active_url, baseRequestResponse):
                    return None
            except Exception:
                pass

            key = self._request_key(baseRequestResponse)
            with self.lock:
                if key in self.seen:
                    return None
                self.seen.add(key)

            issue = self._check(baseRequestResponse)
            if issue is not None:
                return [issue]
        except Exception as e:
            self.callbacks.printError("[active] %s" % str(e))

        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # Burp calls this when it detects potentially duplicate issues.
        # Treat the same issue type on the same endpoint as one finding.
        try:
            old_key = self._issue_key_from_issue(existingIssue)
            new_key = self._issue_key_from_issue(newIssue)

            if old_key == new_key:
                return -1  # keep existing issue

            # Same endpoint but a more specific classification should not
            # create a second issue. For example, if the generic issue and
            # sensitive-data issue are generated for the same URL, keep the
            # first issue registered by this extension.
            if old_key[0] == new_key[0]:
                return -1
        except Exception:
            pass

        return 0

    def _issue_key_from_issue(self, issue):
        url = issue.getUrl().toString().split("#", 1)[0]
        name = issue.getIssueName()

        if "Sensitive Data" in name:
            category = "sensitive"
        elif "File Exposure" in name:
            category = "file"
        else:
            category = "generic"

        return (url, category)

    def _issue_key(self, issue):
        return self._issue_key_from_issue(issue)

    def _register_issue_once(self, issue):
        if issue is None:
            return False

        key = self._issue_key(issue)

        with self.lock:
            if key in self.registered_issues:
                self.callbacks.printOutput(
                    "[i] Duplicate finding suppressed: %s" %
                    issue.getUrl().toString()
                )
                return False

            self.registered_issues.add(key)

        self.callbacks.addScanIssue(issue)
        return True

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def createMenuItems(self, invocation):
        items = ArrayList()

        # Request-level action for Proxy/Repeater and individual Site-map items.
        item = JMenuItem("Check Unauthenticated Access")
        item.addActionListener(lambda event: self._run_context_check(invocation))
        items.add(item)

        # When a host/domain is selected in Target -> Site map, Burp may only
        # return the node's own message from getSelectedMessages(). Therefore
        # do NOT use message-count as the indication that an entire target was
        # selected. Use Burp's invocation context instead.
        try:
            context = invocation.getInvocationContext()
            if context in (
                    IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE,
                    IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE):
                scan_item = JMenuItem(
                    "Check Unauthenticated Access - Entire Target"
                )
                scan_item.addActionListener(
                    lambda event: self._run_target_scan(invocation)
                )
                items.add(scan_item)
        except Exception as e:
            self.callbacks.printError(
                "[menu] Could not determine Target context: %s" % str(e)
            )

        return items

    def _target_prefix_from_message(self, message):
        """Build a host/port prefix suitable for callbacks.getSiteMap()."""
        service = message.getHttpService()
        protocol = service.getProtocol()
        host = service.getHost()
        port = service.getPort()

        default_port = 443 if protocol.lower() == "https" else 80
        if port == default_port:
            return "%s://%s/" % (protocol, host)
        return "%s://%s:%d/" % (protocol, host, port)

    def _enumerate_target_endpoints(self, invocation):
        """
        Enumerate the complete Site map subtree for the selected host/domain.

        The previous implementation used invocation.getSelectedMessages(),
        which is insufficient when a single Target host node is selected:
        Burp can return only the node's own request. getSiteMap(prefix) is the
        important part here; it asks Burp for all Site-map entries below the
        selected host prefix.
        """
        selected = invocation.getSelectedMessages()
        if selected is None or len(selected) == 0:
            return []

        # The selected host/domain node is normally represented by one or
        # more messages. Use the first usable HTTP service as the target root.
        seed = None
        for message in selected:
            try:
                if message is not None and message.getRequest() is not None:
                    seed = message
                    break
            except Exception:
                pass

        if seed is None:
            return []

        prefix = self._target_prefix_from_message(seed)
        self.callbacks.printOutput(
            "[+] Enumerating Burp Site map for target: %s" % prefix
        )

        # Burp legacy API: getSiteMap(urlPrefix) returns Site-map entries whose
        # URLs fall under that prefix. This is what makes the scan recursive.
        try:
            site_items = self.callbacks.getSiteMap(prefix)
        except Exception as e:
            self.callbacks.printError(
                "[target] getSiteMap failed for %s: %s" % (prefix, str(e))
            )
            site_items = None

        if site_items is None:
            site_items = []

        # Include the selected message as a fallback, but never rely on it as
        # the complete target enumeration.
        all_items = list(site_items)
        for message in selected:
            if message is not None:
                all_items.append(message)

        endpoints = []
        seen = set()

        seed_service = seed.getHttpService()
        seed_protocol = seed_service.getProtocol().lower()
        seed_host = seed_service.getHost().lower()
        seed_port = seed_service.getPort()

        for message in all_items:
            try:
                if message is None or message.getRequest() is None:
                    continue

                service = message.getHttpService()
                if service.getProtocol().lower() != seed_protocol:
                    continue
                if service.getHost().lower() != seed_host:
                    continue
                if service.getPort() != seed_port:
                    continue

                url = self.helpers.analyzeRequest(message).getUrl()
                if self._is_excluded_resource(url, message):
                    continue

                key = self._normalize_endpoint_url(url)
                if key in seen:
                    continue

                seen.add(key)
                endpoints.append(message)
            except Exception as e:
                self.callbacks.printError(
                    "[target] Could not process Site-map item: %s" % str(e)
                )

        return endpoints

    def _run_target_scan(self, invocation):
        endpoints = self._enumerate_target_endpoints(invocation)

        if not endpoints:
            self.callbacks.printOutput(
                "[-] No eligible endpoints found in the selected target. "
                "JavaScript and CSS resources are excluded."
            )
            return

        self.callbacks.printOutput(
            "[+] Found %d eligible endpoint(s) in the entire target" %
            len(endpoints)
        )

        def worker():
            findings = 0
            errors = 0

            for i, message in enumerate(endpoints):
                try:
                    url = self.helpers.analyzeRequest(message).getUrl()

                    # Re-check immediately before sending in case the Site-map
                    # response was populated/updated after enumeration.
                    if self._is_excluded_resource(url, message):
                        continue

                    issue = self._check(
                        message,
                        force_original_request=(message.getResponse() is None)
                    )

                    if issue is not None and self._register_issue_once(issue):
                        findings += 1
                        self.callbacks.printOutput(
                            "[+] [%d/%d] Finding: %s" %
                            (i + 1, len(endpoints), issue.getUrl().toString())
                        )
                    else:
                        self.callbacks.printOutput(
                            "[i] [%d/%d] Checked: %s" %
                            (i + 1, len(endpoints), url.toString())
                        )

                except Exception as e:
                    errors += 1
                    self.callbacks.printError(
                        "[target] [%d/%d] Scan failed: %s" %
                        (i + 1, len(endpoints), str(e))
                    )

            self.callbacks.printOutput(
                "[+] Entire target scan complete: %d endpoint(s), "
                "%d finding(s), %d error(s)" %
                (len(endpoints), findings, errors)
            )

        threading.Thread(target=worker).start()

    def _run_context_check(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages is None or len(messages) == 0:
            return

        # Use the first selected request. This keeps the context action
        # predictable and avoids generating a burst of requests.
        base = messages[0]

        def worker():
            try:
                # If Repeater has not been sent, base.getResponse() is None.
                # _check() will first send the original authenticated request
                # to establish the baseline, then perform the unauthenticated
                # replay.
                issue = self._check(base, force_original_request=True)

                if issue is not None:
                    # Burp renders this issue in Target -> Issues.
                    self._register_issue_once(issue)
                    self.callbacks.printOutput(
                        "[+] Unauthenticated access reported to Target -> Issues: %s"
                        % issue.getUrl().toString()
                    )
                else:
                    self.callbacks.printOutput(
                        "[-] No unauthenticated access confirmed: %s" %
                        self.helpers.analyzeRequest(base).getUrl().toString()
                    )
            except Exception as e:
                self.callbacks.printError("[context] %s" % str(e))

        threading.Thread(target=worker).start()

    # ------------------------------------------------------------------
    # Core check
    # ------------------------------------------------------------------

    def _normalize_endpoint_url(self, url):
        try:
            value = url.toString()
        except Exception:
            value = str(url)
        return value.split("#", 1)[0]

    def _is_excluded_resource(self, url, message=None):
        try:
            url_text = self._normalize_endpoint_url(url)
        except Exception:
            url_text = str(url)
        path = url_text.split("?", 1)[0].lower()
        if any(path.endswith(ext) for ext in self.EXCLUDED_EXTENSIONS):
            return True

        if message is not None:
            try:
                response = message.getResponse()
                if response is not None:
                    info = self.helpers.analyzeResponse(response)
                    ct = self._content_type(info)
                    if any(ct.startswith(x) for x in self.EXCLUDED_CONTENT_TYPES):
                        return True
            except Exception:
                pass
        return False

    def _check(self, base, force_original_request=False):
        request = base.getRequest()
        if request is None:
            return None

        try:
            endpoint_url = self.helpers.analyzeRequest(base).getUrl()
            if self._is_excluded_resource(endpoint_url, base):
                self.callbacks.printOutput("[i] Skipping JavaScript/CSS resource: %s" % endpoint_url.toString())
                return None
        except Exception:
            pass

        # Repeater requests that have not been sent have no response.
        # Proxy history can also contain a request without a response.
        # Establish an authenticated baseline before stripping credentials.
        if force_original_request or base.getResponse() is None:
            try:
                baseline = self.callbacks.makeHttpRequest(
                    base.getHttpService(), request
                )
                if baseline is None or baseline.getResponse() is None:
                    self.callbacks.printError(
                        "[check] Could not obtain authenticated baseline response"
                    )
                    return None
                base = baseline
            except Exception as e:
                self.callbacks.printError(
                    "[check] Authenticated baseline request failed: %s" % str(e)
                )
                return None

        # Re-read the request/headers from the baseline message.
        request = base.getRequest()
        request_info = self.helpers.analyzeRequest(base)
        original_headers = request_info.getHeaders()

        if not self._has_auth_material(original_headers):
            self.callbacks.printOutput(
                "[i] Skipping request without recognizable auth/session headers: %s"
                % base.getHttpService().getHost()
            )
            return None

        modified = self._remove_auth_headers(request, original_headers)
        if modified is None:
            return None

        # Send unauthenticated replay.
        unauth = self.callbacks.makeHttpRequest(
            base.getHttpService(), modified
        )

        if unauth is None or unauth.getResponse() is None:
            return None

        original_response = base.getResponse()
        unauth_response = unauth.getResponse()

        if original_response is None:
            return None

        original_info = self.helpers.analyzeResponse(original_response)
        unauth_info = self.helpers.analyzeResponse(unauth_response)

        original_status = original_info.getStatusCode()
        unauth_status = unauth_info.getStatusCode()

        # If the authenticated request itself was not successful, response
        # comparison is much less meaningful.
        if original_status < 200 or original_status >= 400:
            return None

        # A redirect to a login page is not evidence of unauthenticated access.
        if self._looks_like_auth_failure(unauth_status, unauth_response):
            return None

        original_body = self._body(original_response, original_info)
        unauth_body = self._body(unauth_response, unauth_info)

        sensitive_hits = self._find_sensitive(unauth_body)

        similarity = self._response_similarity(
            original_status,
            unauth_status,
            original_response,
            unauth_response,
            original_body,
            unauth_body
        )

        file_exposure = self._looks_like_file(base, unauth_info, unauth_body)

        # Confirmation logic:
        # A) Same successful status + strong body similarity
        # B) Same successful status + same content type + sensitive data
        # C) Same successful status + identifiable file response
        same_success_status = (
            200 <= original_status < 300 and
            200 <= unauth_status < 300 and
            original_status == unauth_status
        )

        content_type_same = self._content_type(original_info) == \
                            self._content_type(unauth_info)

        confirmed = False

        if same_success_status and similarity >= 0.80:
            confirmed = True

        if same_success_status and content_type_same and sensitive_hits:
            confirmed = True

        if same_success_status and file_exposure:
            # Require at least a plausible amount of response data.
            if len(unauth_body) >= 20:
                confirmed = True

        # Also catch applications that return 200 for both auth and unauth
        # but replace only a small part of a dynamic response.
        if (200 <= unauth_status < 300 and
                200 <= original_status < 300 and
                sensitive_hits and similarity >= 0.55):
            confirmed = True

        if not confirmed:
            return None

        severity = self._severity(sensitive_hits, file_exposure)

        evidence = []
        if sensitive_hits:
            evidence.append(
                "Sensitive indicators: %s" %
                ", ".join(sorted(set(sensitive_hits)))
            )
        if file_exposure:
            evidence.append("Response appears to expose a file/resource")
        evidence.append("Authenticated status: %d" % original_status)
        evidence.append("Unauthenticated status: %d" % unauth_status)
        evidence.append("Response similarity: %.1f%%" % (similarity * 100.0))
        evidence.append(
            "Removed headers: %s" %
            ", ".join(self._removed_header_names(original_headers))
        )

        detail = (
            "<p>The endpoint returned a successful response after "
            "authentication/session headers were removed.</p>"
            "<p><b>Evidence</b><br>%s</p>"
            "<p><b>Test method</b><br>"
            "The original request was replayed after removing common "
            "authentication/session headers. The response was compared "
            "with the original authenticated response.</p>"
            "<p><b>Important</b><br>"
            "Dynamic applications can produce similar responses without "
            "actually exposing the protected resource. Validate the finding "
            "manually before remediation.</p>"
        ) % "<br>".join(self._html_escape(x) for x in evidence)

        name = "Unauthenticated Access"
        if sensitive_hits:
            name += " - Sensitive Data"
        elif file_exposure:
            name += " - File Exposure"

        return CustomScanIssue(
            base.getHttpService(),
            self.helpers.analyzeRequest(base).getUrl(),
            [base, unauth],
            name,
            detail,
            severity,
            "Certain"
        )

    # ------------------------------------------------------------------
    # Request manipulation
    # ------------------------------------------------------------------

    def _has_auth_material(self, headers):
        for h in headers:
            if ":" not in h:
                continue
            name = h.split(":", 1)[0].strip()
            if self._is_auth_header(name):
                if self.REMOVE_CSRF_HEADER or name.lower() != "x-csrf-token":
                    return True
        return False

    def _is_auth_header(self, name):
        lname = name.lower().strip()

        if lname == "x-csrf-token" and not self.REMOVE_CSRF_HEADER:
            return False

        for pattern in self.AUTH_HEADER_PATTERNS:
            if re.match(pattern, lname):
                return True

        # Catch common custom authentication headers while avoiding broad
        # matches on unrelated headers.
        if (lname.startswith("x-auth-") or
                lname.startswith("x-session-") or
                lname.endswith("-auth-token") or
                lname.endswith("-access-token")):
            return True

        return False

    def _remove_auth_headers(self, request, headers):
        new_headers = ArrayList()
        removed = False

        for h in headers:
            if ":" not in h:
                new_headers.add(h)
                continue

            name = h.split(":", 1)[0].strip()
            if self._is_auth_header(name):
                removed = True
                continue

            new_headers.add(h)

        if not removed:
            return None

        info = self.helpers.analyzeRequest(request)
        body_offset = info.getBodyOffset()
        body = request[body_offset:]

        return self.helpers.buildHttpMessage(new_headers, body)

    def _removed_header_names(self, headers):
        names = []
        for h in headers:
            if ":" not in h:
                continue
            name = h.split(":", 1)[0].strip()
            if self._is_auth_header(name):
                names.append(name)
        return names

    # ------------------------------------------------------------------
    # Response comparison / classification
    # ------------------------------------------------------------------

    def _response_similarity(self, status1, status2,
                             response1, response2, body1, body2):
        if status1 != status2:
            return 0.0

        if not body1 and not body2:
            return 1.0

        if not body1 or not body2:
            return 0.0

        # Compare a bounded body to avoid expensive SequenceMatcher calls
        # against very large downloads.
        a = self._normalize_dynamic(body1[:200000])
        b = self._normalize_dynamic(body2[:200000])

        try:
            return difflib.SequenceMatcher(None, a, b).ratio()
        except Exception:
            # Fallback for unusual Jython string behavior.
            return 1.0 if a == b else 0.0

    def _normalize_dynamic(self, body):
        s = self._to_text(body)

        # Remove values that commonly change between requests.
        s = re.sub(r'(?i)(csrf|nonce|timestamp|requestid|request_id|traceid|trace_id)'
                   r'(["\']?\s*[:=]\s*["\']?)[^,"\'}\s]+',
                   r'\1<DYNAMIC>', s)

        s = re.sub(
            r'\b\d{10,}\b', '<NUMBER>',
            s
        )

        s = re.sub(
            r'\b[0-9a-f]{16,}\b', '<HEX>', s, flags=re.I
        )

        return s

    def _looks_like_auth_failure(self, status, response):
        if status in (401, 403):
            return True

        info = self.helpers.analyzeResponse(response)
        body = self._body(response, info)
        text = self._to_text(body).lower()[:20000]

        indicators = [
            "unauthorized",
            "not authorized",
            "access denied",
            "authentication required",
            "login required",
            "please log in",
            "please login",
            "sign in required",
            "session expired"
        ]

        return any(x in text for x in indicators) and status in (200, 302, 303)

    def _find_sensitive(self, body):
        text = self._to_text(body)
        hits = []

        for label, pattern in self.SENSITIVE_PATTERNS:
            try:
                if pattern.search(text):
                    hits.append(label)
            except Exception:
                pass

        # Additional JSON-ish field names that are often sensitive.
        field_patterns = [
            ("PII field", r'(?i)"(?:ssn|socialSecurityNumber|passport|nationalId)"\s*:'),
            ("Credential field", r'(?i)"(?:username|user_name|credential|credentials)"\s*:'),
            ("Database credential", r'(?i)"(?:db_password|database_password|connectionString)"\s*:'),
            ("Cloud secret field", r'(?i)"(?:aws_secret|azure_secret|gcp_key|privateKey)"\s*:'),
        ]

        for label, expr in field_patterns:
            if re.search(expr, text):
                hits.append(label)

        return hits

    def _looks_like_file(self, base, response_info, body):
        headers = response_info.getHeaders()
        content_type = self._content_type(response_info).lower()

        if "content-disposition:" in "\n".join(headers).lower():
            if re.search(r'(?i)attachment\s*;', "\n".join(headers)):
                return True

        for h in headers:
            if h.lower().startswith("content-disposition:") and \
                    re.search(r'(?i)(filename|attachment)', h):
                return True

        for ct in self.BINARY_CONTENT_TYPES:
            if content_type.startswith(ct):
                return True

        url = self.helpers.analyzeRequest(base).getUrl().toString().lower()
        path = url.split("?", 1)[0]

        for ext in self.FILE_EXTENSIONS:
            if path.endswith(ext):
                return True

        # Common file-download API hints.
        if any(x in path for x in (
                "/download", "/export", "/attachment", "/attachments/",
                "/document", "/documents/", "/file", "/files/")):
            return True

        return False

    def _severity(self, sensitive_hits, file_exposure):
        # User-requested classification:
        # sensitive PCI/PII/secrets/passwords => High
        # file accessible without auth => Medium
        # other confirmed unauthenticated access => Low
        if sensitive_hits:
            return "High"
        if file_exposure:
            return "Medium"
        return "Low"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _body(self, response, info):
        return response[info.getBodyOffset():]

    def _content_type(self, response_info):
        for h in response_info.getHeaders():
            if h.lower().startswith("content-type:"):
                return h.split(":", 1)[1].strip().split(";", 1)[0].lower()
        return ""

    def _to_text(self, data):
        if data is None:
            return ""
        try:
            return self.helpers.bytesToString(data)
        except Exception:
            try:
                return str(data)
            except Exception:
                return ""

    def _request_key(self, base):
        req = base.getRequest()
        service = base.getHttpService()
        url = self.helpers.analyzeRequest(base).getUrl().toString()

        try:
            digest = hashlib.sha1(self._to_text(req).encode("utf-8")).hexdigest()
        except Exception:
            digest = str(len(req))

        return "%s://%s:%d|%s|%s" % (
            service.getProtocol(),
            service.getHost(),
            service.getPort(),
            url,
            digest
        )

    def _html_escape(self, value):
        value = str(value)
        return (value.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))


class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages,
                 name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        # Custom issue type. Burp accepts custom extension issue types.
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return (
            "<p><b>Unauthenticated Access Checker</b></p>"
            "<p>The endpoint remained accessible after authentication/session "
            "credentials were removed from the request.</p>"
        )

    def getRemediationBackground(self):
        return (
            "<p>Enforce authorization on the server side for every protected "
            "resource. Do not rely on client-side checks or the presence of "
            "a particular UI flow to enforce access control.</p>"
        )

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return (
            "<p>Apply authentication and authorization middleware to the "
            "affected route/resource. Verify authorization at the resource "
            "layer and add regression tests for anonymous access.</p>"
        )

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
