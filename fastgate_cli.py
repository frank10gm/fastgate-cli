#!/usr/bin/env python3
"""
fastgate-cli — command-line client for the Fastweb FASTGate (Technicolor FGA2130FWB
and other Technicolor Homeware gateways).

What works and what you must verify
-----------------------------------
- LOGIN (SRP-6a, SHA-256, 2048-bit group): implemented and self-contained. This is
  the hard part and is the main value of this tool. The flow matches the Technicolor
  Homeware web UI: two POSTs to /authenticate carrying CSRFtoken, I, A then M.
- Raw authenticated requests ("request" command): fully working. Use it to replay a
  request you captured from the browser DevTools (Network tab). This is the reliable
  way to change DHCP static leases, because the exact DHCP endpoint/params are
  model- and firmware-specific and are NOT published.
- "dhcp-*" helpers: thin wrappers around the raw request with a BEST-GUESS endpoint
  for Homeware. They are UNVERIFIED on the FGA2130FWB. Treat them as a starting
  template: capture the real request first (see README), then adjust endpoint/params.

Nothing here needs root on the modem. It only drives the existing web UI over HTTP.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests. Run: pip install -r requirements.txt")

try:
    import srp  # pysrp
except ImportError:
    sys.exit("Missing dependency: srp. Run: pip install -r requirements.txt")


# --------------------------------------------------------------------------- #
# Session / login
# --------------------------------------------------------------------------- #

CSRF_META_RE = re.compile(
    r'<meta[^>]+name=["\']?CSRFtoken["\']?[^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
CSRF_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']?CSRFtoken["\']?[^>]+value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class FastgateError(RuntimeError):
    pass


class FastgateSession:
    """
    A logged-in HTTP session against the FASTGate web UI.

    SRP parameters (hash SHA-256, NG_2048) match the Technicolor Homeware GUI.
    If login fails on your firmware, capture the real /authenticate exchange in
    DevTools and compare the posted fields; the variant may differ.
    """

    def __init__(self, host: str, verify_tls: bool = False, timeout: int = 15,
                 verbose: bool = False):
        self.base = host.rstrip("/")
        if not self.base.startswith(("http://", "https://")):
            self.base = "http://" + self.base
        self.timeout = timeout
        self.verbose = verbose
        self.s = requests.Session()
        self.s.verify = verify_tls
        self.s.headers.update({
            # Generic client name on purpose: do not leak host/user identity.
            "User-Agent": "fastgate-cli/1.0",
            "X-Requested-With": "XMLHttpRequest",
        })
        self.csrf: Optional[str] = None

    # -- low level -------------------------------------------------------- #

    def url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return self.base + ("" if path.startswith("/") else "/") + path

    def _log(self, *a):
        if self.verbose:
            print("[debug]", *a, file=sys.stderr)

    def _update_csrf_from_response(self, resp: requests.Response):
        # Homeware rotates the CSRF token; it can appear in a header or in HTML.
        hdr = resp.headers.get("CSRFtoken") or resp.headers.get("X-CSRF-Token")
        if hdr:
            self.csrf = hdr
            self._log("csrf from header:", hdr[:12] + "...")
            return
        ctype = resp.headers.get("Content-Type", "")
        if "html" in ctype:
            m = CSRF_META_RE.search(resp.text) or CSRF_INPUT_RE.search(resp.text)
            if m:
                self.csrf = m.group(1)
                self._log("csrf from html:", self.csrf[:12] + "...")

    def fetch_csrf(self):
        """Load a page that carries the CSRF token."""
        for path in ("/", "/login.lp", "/index.lp"):
            try:
                r = self.s.get(self.url(path), timeout=self.timeout)
            except requests.RequestException as e:
                self._log("csrf fetch error on", path, e)
                continue
            self._update_csrf_from_response(r)
            if self.csrf:
                return
        if not self.csrf:
            raise FastgateError(
                "Could not find CSRFtoken on the login page. The UI layout may "
                "differ on your firmware; capture the login page HTML and adjust "
                "the regexes in fetch_csrf()."
            )

    def _authenticate_post(self, fields: dict) -> dict:
        data = dict(fields)
        if self.csrf:
            data["CSRFtoken"] = self.csrf
        r = self.s.post(self.url("/authenticate"), data=data, timeout=self.timeout)
        self._update_csrf_from_response(r)
        if r.status_code != 200:
            raise FastgateError(f"/authenticate HTTP {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except ValueError:
            raise FastgateError(f"/authenticate non-JSON reply: {r.text[:200]}")

    # -- login ------------------------------------------------------------ #

    def login(self, username: str, password: str):
        self.fetch_csrf()

        usr = srp.User(username, password,
                       hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _I, A = usr.start_authentication()

        # Step 1: send I and A, receive salt s and server public B.
        step1 = self._authenticate_post({"I": username, "A": A.hex()})
        if "s" not in step1 or "B" not in step1:
            raise FastgateError(f"Unexpected step-1 reply: {step1}")
        s = bytes.fromhex(step1["s"])
        B = bytes.fromhex(step1["B"])

        M = usr.process_challenge(s, B)
        if M is None:
            raise FastgateError(
                "SRP safety check failed (bad B). Wrong SRP group/hash for this "
                "firmware, or server rejected A."
            )

        # Step 2: send proof M, receive server proof M2/HAMK.
        step2 = self._authenticate_post({"M": M.hex()})
        if step2.get("error"):
            raise FastgateError(f"Login rejected: {step2}")
        hamk_hex = step2.get("M") or step2.get("M2") or step2.get("HAMK")
        if not hamk_hex:
            raise FastgateError(f"No server proof in reply: {step2}")

        usr.verify_session(bytes.fromhex(hamk_hex))
        if not usr.authenticated():
            raise FastgateError("Server proof did not verify — possible MITM or "
                                "protocol mismatch.")
        self._log("login OK, cookies:", self.s.cookies.get_dict())

    # -- authed helpers --------------------------------------------------- #

    def request(self, method: str, path: str, params=None, data=None) -> requests.Response:
        if data is not None and self.csrf and "CSRFtoken" not in (data or {}):
            data = dict(data)
            data["CSRFtoken"] = self.csrf
        r = self.s.request(method.upper(), self.url(path),
                           params=params, data=data, timeout=self.timeout)
        self._update_csrf_from_response(r)
        return r


# --------------------------------------------------------------------------- #
# DHCP helpers  (UNVERIFIED on FGA2130FWB — capture the real request first)
# --------------------------------------------------------------------------- #

# Best-guess Homeware endpoint. Override with --endpoint or in config after you
# capture the actual request from DevTools. Left here only as a template.
DEFAULT_DHCP_ENDPOINT = "/modals/device-modal.lp"


def dhcp_set(sess: FastgateSession, mac: str, ip: str, endpoint: str,
             extra: Optional[dict] = None) -> requests.Response:
    """
    Add/update a static DHCP lease (MAC -> IP).

    WARNING: endpoint and field names are a guess for Homeware and are NOT
    verified on the FGA2130FWB. Capture your modem's real request and pass the
    correct --endpoint plus any extra fields via 'request' instead.
    """
    data = {
        "action": "SET",
        "mac": mac,
        "ip": ip,
    }
    if extra:
        data.update(extra)
    return sess.request("POST", endpoint, data=data)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def get_password(args) -> str:
    if args.password:
        return args.password
    env = os.environ.get("FASTGATE_PASSWORD")
    if env:
        return env
    return getpass.getpass("FASTGate password: ")


def build_session(args) -> FastgateSession:
    sess = FastgateSession(args.host, verify_tls=args.verify_tls,
                           timeout=args.timeout, verbose=args.verbose)
    sess.login(args.user, get_password(args))
    return sess


def parse_kv(pairs) -> dict:
    out = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"Bad key=value: {p!r}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def cmd_login_test(args):
    build_session(args)
    print("Login OK.")


def cmd_request(args):
    sess = build_session(args)
    params = parse_kv(args.query)
    data = parse_kv(args.data) if args.data else None
    r = sess.request(args.method, args.path, params=params or None, data=data)
    print(f"HTTP {r.status_code}  {r.headers.get('Content-Type','')}")
    print(r.text)


def cmd_dhcp_set(args):
    sess = build_session(args)
    r = dhcp_set(sess, args.mac, args.ip, args.endpoint, parse_kv(args.extra))
    print(f"HTTP {r.status_code}")
    print(r.text)
    print("\nNote: dhcp-set uses a GUESSED endpoint. If this failed, capture the "
          "real request in DevTools and use `request` instead.", file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="fastgate-cli",
        description="CLI for the Fastweb FASTGate / Technicolor Homeware web UI.",
    )
    p.add_argument("--host", default=os.environ.get("FASTGATE_HOST", "192.168.1.1"),
                   help="Modem address (default: 192.168.1.1 or $FASTGATE_HOST).")
    p.add_argument("--user", default=os.environ.get("FASTGATE_USER", "admin"),
                   help="Username (default: admin or $FASTGATE_USER).")
    p.add_argument("--password", default=None,
                   help="Password (else $FASTGATE_PASSWORD, else prompt).")
    p.add_argument("--verify-tls", action="store_true",
                   help="Verify TLS cert (off by default; modem uses self-signed).")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("login-test", help="Log in and exit (verify credentials).")
    sp.set_defaults(func=cmd_login_test)

    sp = sub.add_parser("request",
                        help="Authenticated raw request (replay a captured call).")
    sp.add_argument("path", help="Path, e.g. /modals/device-modal.lp")
    sp.add_argument("-X", "--method", default="GET")
    sp.add_argument("-q", "--query", action="append", metavar="K=V",
                    help="URL query parameter (repeatable).")
    sp.add_argument("-d", "--data", action="append", metavar="K=V",
                    help="Form body field (repeatable). CSRFtoken added automatically.")
    sp.set_defaults(func=cmd_request)

    sp = sub.add_parser("dhcp-set",
                        help="Add/update a static DHCP lease (UNVERIFIED template).")
    sp.add_argument("--mac", required=True)
    sp.add_argument("--ip", required=True)
    sp.add_argument("--endpoint", default=DEFAULT_DHCP_ENDPOINT,
                    help=f"Override endpoint (default guess: {DEFAULT_DHCP_ENDPOINT}).")
    sp.add_argument("-e", "--extra", action="append", metavar="K=V",
                    help="Extra form fields (repeatable).")
    sp.set_defaults(func=cmd_dhcp_set)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except FastgateError as e:
        sys.exit(f"Error: {e}")
    except requests.RequestException as e:
        sys.exit(f"Network error: {e}")
    return 0


if __name__ == "__main__":
    main()
