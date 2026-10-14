"""Adds fictional passkey (WebAuthn) tickets to public/tickets.json, replacing any earlier copies.

Each credential is real: a fresh P-256 key, real CBOR attestation objects and authenticator data, and
real ES256 signatures over the sign-in responses. Each ticket is built to fail one passkey check
(npm test confirms it). The SAML tickets from make_samples.py are left untouched.

Run: python3 data/make_passkey_samples.py
"""
import base64
import hashlib
import json
import secrets
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

OUT = Path(__file__).resolve().parent.parent / "public" / "tickets.json"
FIRST_ID = 3014


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---------- a minimal CBOR writer: ints, byte strings, text, maps ----------
def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    return bytes([major << 5 | 26]) + struct.pack(">I", n)


def cbor(v):
    if isinstance(v, bool):
        raise TypeError("bools not needed here")
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        return _head(3, len(e)) + e
    if isinstance(v, dict):
        return _head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(type(v))


FLAG = {"UP": 0x01, "UV": 0x04, "BE": 0x08, "BS": 0x10, "AT": 0x40}


def auth_data(rp_id, flags, count, attested=None):
    bits = sum(FLAG[f] for f in flags) | (FLAG["AT"] if attested else 0)
    out = hashlib.sha256(rp_id.encode()).digest() + bytes([bits]) + struct.pack(">I", count)
    if attested:
        cred_id, key = attested
        nums = key.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        out += bytes(16) + struct.pack(">H", len(cred_id)) + cred_id + cose
    return out


def client_data(kind, challenge, origin):
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}, separators=(",", ":")).encode()


def register(*, rp_id, origin, challenge, flags, attachment, transports):
    """A registration response, the shape credential.toJSON() produces in the browser."""
    key, cred_id = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
    cd = client_data("webauthn.create", challenge, origin)
    att = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data(rp_id, flags, 0, (cred_id, key))})
    return {"id": b64url(cred_id), "rawId": b64url(cred_id), "type": "public-key", "authenticatorAttachment": attachment,
            "response": {"clientDataJSON": b64url(cd), "attestationObject": b64url(att), "transports": transports},
            "clientExtensionResults": {}}


def sign_in(*, rp_id, origin, challenge, flags, count, attachment):
    """A sign-in response with a real ES256 signature over authenticatorData + SHA-256(clientDataJSON)."""
    key, cred_id = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
    cd = client_data("webauthn.get", challenge, origin)
    ad = auth_data(rp_id, flags, count)
    sig = key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    return {"id": b64url(cred_id), "rawId": b64url(cred_id), "type": "public-key", "authenticatorAttachment": attachment,
            "response": {"clientDataJSON": b64url(cd), "authenticatorData": b64url(ad), "signature": b64url(sig),
                         "userHandle": b64url(secrets.token_bytes(16))},
            "clientExtensionResults": {}}


def chal():
    return b64url(secrets.token_bytes(32))


def body(intro, cred):
    return intro + "\n\n" + json.dumps(cred, indent=2)


def main():
    c_issued, c_stale = chal(), chal()
    tickets = [
        dict(plan="Enterprise", idp="Okta", from_name="Lena Fischer", company="Northwind Analytics",
             subject="Passkey sign-in broke after our IdP domain change", received_at="2026-10-13T14:20Z",
             body=body("We moved our IdP to the parent domain northwind.example last night. Since then every passkey sign-in is "
                       "rejected before anyone reaches Claude. Password plus push still works. Here's a failed sign-in from our logs:",
                       sign_in(rp_id="login.northwind.example", origin="https://login.northwind.example", challenge=c_issued,
                               flags=["UP", "UV", "BE", "BS"], count=0, attachment="platform")),
             sp={"rp_id": "northwind.example", "origin": "https://login.northwind.example", "challenge": c_issued, "passkey_policy": "uv"}),
        dict(plan="Enterprise", idp="Okta", from_name="Hannah Okafor", company="Brightpath Health",
             subject="Passkeys fail only on our new sign-in page", received_at="2026-10-13T16:05Z",
             body=body("We launched a branded sign-in page at signin.brightpath-health.example. Passkeys work on the old page "
                       "but fail on the new one. Same users, same passkeys. Response from the new page:",
                       sign_in(rp_id="brightpath-health.example", origin="https://signin.brightpath-health.example", challenge=c_issued,
                               flags=["UP", "UV", "BE", "BS"], count=0, attachment="platform")),
             sp={"rp_id": "brightpath-health.example", "origin": "https://login.brightpath-health.example", "challenge": c_issued, "passkey_policy": "uv"}),
        dict(plan="Enterprise", idp="Entra ID", from_name="Aiko Tanaka", company="Kitewise",
             subject="Security keys enroll but policy rejects them", received_at="2026-10-14T08:10Z",
             body=body("We're rolling out phishing-resistant MFA. A few staff registered security keys, but our policy rejects them "
                       "right after enrollment. The keys only ask for a tap. Registration data from one of them:",
                       register(rp_id="kitewise.example", origin="https://login.kitewise.example", challenge=c_issued,
                                flags=["UP"], attachment="cross-platform", transports=["usb", "nfc"])),
             sp={"rp_id": "kitewise.example", "origin": "https://login.kitewise.example", "challenge": c_issued, "passkey_policy": "uv"}),
        dict(plan="Enterprise", idp="Okta", from_name="Dev Patel", company="Stackmint",
             subject="Passkey works on the second try", received_at="2026-10-14T09:45Z",
             body=body("Some engineers say passkey sign-in fails the first time and works after a refresh. Our logs show a "
                       "challenge error. Here's a failed attempt:",
                       sign_in(rp_id="stackmint.example", origin="https://id.stackmint.example", challenge=c_stale,
                               flags=["UP", "UV", "BE", "BS"], count=0, attachment="platform")),
             sp={"rp_id": "stackmint.example", "origin": "https://id.stackmint.example", "challenge": c_issued, "passkey_policy": "uv"}),
        dict(plan="Enterprise", idp="Okta", from_name="Sam Whitaker", company="Casefile Legal",
             subject="Phone passkeys rejected under our new policy", received_at="2026-10-14T10:30Z",
             body=body("Our security team now requires device-bound authenticators for attorneys. A partner registered a "
                       "passkey on her phone and it's rejected. Registration data:",
                       register(rp_id="casefile.example", origin="https://sso.casefile.example", challenge=c_issued,
                                flags=["UP", "UV", "BE", "BS"], attachment="platform", transports=["internal", "hybrid"])),
             sp={"rp_id": "casefile.example", "origin": "https://sso.casefile.example", "challenge": c_issued, "passkey_policy": "device_bound"}),
        dict(plan="Team", idp="Google Workspace", from_name="Marcus Hale", company="Juniper Studio",
             subject="Passkey prompt closes with an error", received_at="2026-10-14T11:15Z",
             body="A designer on a new Windows laptop clicks \"Sign in with a passkey\" and gets this in the console. "
                  "She set up her passkey on her Mac last month.\n\n"
                  "Uncaught (in promise) NotAllowedError: The operation either timed out or was not allowed. "
                  "See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.\n"
                  "    at navigator.credentials.get (signin.js:88)",
             sp={}),
        dict(plan="Enterprise", idp="Okta", from_name="Priya Raman", company="Northwind Analytics",
             subject="Can't register passkeys on our staging sign-in", received_at="2026-10-14T13:40Z",
             body="On our staging sign-in page at northwind.example, the register button fails right away, before any prompt "
                  "appears. Our config sets rpId to login.northwind.example to match production. Console:\n\n"
                  "SecurityError: The relying party ID is not a registrable domain suffix of, nor equal to the current domain.\n"
                  "    at navigator.credentials.create (enroll.js:41)",
             sp={}),
    ]

    existing = json.loads(OUT.read_text())
    keep = [t for t in existing if int(t["id"].split("-")[1]) < FIRST_ID]
    for n, t in enumerate(tickets):
        t["id"] = f"SSO-{FIRST_ID + n}"
        t["kind"] = "passkey"
    ordered = [{k: t[k] for k in ["id", "plan", "idp", "from_name", "company", "subject", "received_at", "body", "sp", "kind"]} for t in tickets]
    OUT.write_text(json.dumps(keep + ordered, indent=2) + "\n")
    print(f"kept {len(keep)} tickets, wrote {len(ordered)} passkey tickets to {OUT}")


if __name__ == "__main__":
    main()
