"""Builds public/tickets.json: fictional SSO tickets with real, parseable SAML responses,
OIDC errors, SCIM errors and DNS output. Certificates are generated here with made-up names.
Signatures are placeholders (the assistant checks that they're present, not that they verify).

Run: python3 data/make_samples.py
"""
import base64
import datetime as dt
import json
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent.parent / "public" / "tickets.json"
UTC = dt.timezone.utc

# The service provider values a customer would copy from Claude's SSO setup screen (fictional here).
SP = {
    "entity_id": "https://sso.example-sp.com/saml/conn_01NORTHWIND",
    "acs_url": "https://sso.example-sp.com/saml/conn_01NORTHWIND/acs",
    "nameid": "email",
}


def cert(cn, not_before, not_after):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example IdP")])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(not_before).not_valid_after(not_after)
         .sign(key, hashes.SHA256()))
    der = c.public_bytes(serialization.Encoding.DER)
    fp = c.fingerprint(hashes.SHA256()).hex().upper()
    return base64.b64encode(der).decode(), ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def saml(*, issuer, issued, cert_b64, audience=SP["entity_id"], destination=SP["acs_url"], recipient=None,
         nameid="ana.lima@northwind.example", nameid_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
         not_before=None, not_after=None, status="urn:oasis:names:tc:SAML:2.0:status:Success", status_message=None,
         signed_response=True, signed_assertion=True, attributes=None, in_response_to="_req_7f1c2a"):
    not_before = not_before or issued - dt.timedelta(seconds=5)
    not_after = not_after or issued + dt.timedelta(minutes=5)
    recipient = recipient or destination
    rid, aid = "_" + secrets.token_hex(16), "_" + secrets.token_hex(16)
    attributes = attributes if attributes is not None else {"email": nameid, "firstName": "Ana", "lastName": "Lima"}
    sig = lambda ref: (f'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
                       f'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
                       f'<ds:Reference URI="#{ref}"><ds:DigestValue>{base64.b64encode(secrets.token_bytes(32)).decode()}</ds:DigestValue></ds:Reference>'
                       f'</ds:SignedInfo><ds:SignatureValue>{base64.b64encode(secrets.token_bytes(256)).decode()}</ds:SignatureValue>'
                       f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>')
    status_xml = f'<samlp:StatusCode Value="{status}"/>' if not status_message else (
        f'<samlp:StatusCode Value="{status}"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode>'
        f'<samlp:StatusMessage>{status_message}</samlp:StatusMessage>')
    attrs = "".join(f'<saml:Attribute Name="{k}"><saml:AttributeValue>{v}</saml:AttributeValue></saml:Attribute>' for k, v in attributes.items())
    assertion = "" if status != "urn:oasis:names:tc:SAML:2.0:status:Success" else (
        f'<saml:Assertion ID="{aid}" IssueInstant="{iso(issued)}" Version="2.0"><saml:Issuer>{issuer}</saml:Issuer>'
        f'{sig(aid) if signed_assertion else ""}'
        f'<saml:Subject><saml:NameID Format="{nameid_format}">{nameid}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData InResponseTo="{in_response_to}" NotOnOrAfter="{iso(not_after)}" Recipient="{recipient}"/>'
        f'</saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{iso(not_before)}" NotOnOrAfter="{iso(not_after)}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{iso(issued)}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
        f'<saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion>')
    xml = (f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
           f'ID="{rid}" Version="2.0" IssueInstant="{iso(issued)}" Destination="{destination}" InResponseTo="{in_response_to}">'
           f'<saml:Issuer>{issuer}</saml:Issuer>{sig(rid) if signed_response else ""}<samlp:Status>{status_xml}</samlp:Status>{assertion}</samlp:Response>')
    return base64.b64encode(xml.encode()).decode()


def wrap(b64, width=76):
    return "\n".join(b64[i:i + width] for i in range(0, len(b64), width))


def jwt(header, payload):
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.{base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip('=')}"


def main():
    t = lambda s: dt.datetime.fromisoformat(s).replace(tzinfo=UTC)
    good, good_fp = cert("okta.northwind.example", t("2026-01-10T00:00:00"), t("2029-01-10T00:00:00"))
    expired, _ = cert("sts.contoso-health.example", t("2023-10-01T00:00:00"), t("2026-10-05T00:00:00"))
    rotated_new, rotated_new_fp = cert("okta.ledgerline.example", t("2026-10-01T00:00:00"), t("2029-10-01T00:00:00"))
    _, rotated_old_fp = cert("okta.ledgerline.example", t("2023-10-01T00:00:00"), t("2026-12-01T00:00:00"))
    soon, _ = cert("accounts.kitewise.example", t("2023-11-01T00:00:00"), t("2026-10-30T00:00:00"))
    okta = "http://www.okta.com/exk1northwind"
    entra = "https://sts.windows.net/7c1e2a90-0000-4000-8000-contosohealth/"

    tickets = [
        dict(id="SSO-3001", plan="Enterprise", idp="Okta", from_name="Ana Lima", company="Northwind Analytics",
             subject="SSO test fails right after setup", received_at="2026-10-06T15:20Z",
             body="We just finished the Okta setup and the SSO test fails with an invalid audience message. Here's the SAMLResponse from the browser's network tab:\n\n" +
             wrap(saml(issuer=okta, issued=t("2026-10-06T15:18:02"), cert_b64=good, audience="https://claude.ai"))),
        dict(id="SSO-3002", plan="Enterprise", idp="Entra ID", from_name="Rafael Ortiz", company="Contoso Health",
             subject="Login loops back after Entra sign-in", received_at="2026-10-06T18:02Z",
             body="Users sign in to Microsoft fine, then end up back at the login page. We copied the reply URL from an old test connection. SAMLResponse:\n\n" +
             wrap(saml(issuer=entra, issued=t("2026-10-06T17:58:40"), cert_b64=good,
                       destination="https://sso.example-sp.com/saml/conn_01TESTOLD/acs", nameid="r.ortiz@contoso-health.example"))),
        dict(id="SSO-3003", plan="Enterprise", idp="Entra ID", from_name="Mei Chen", company="Contoso Health",
             subject="Nobody can log in since this morning", received_at="2026-10-07T13:45Z",
             body="SSO worked yesterday. Since this morning everyone gets an error after the Microsoft login. Nothing changed on our side as far as I know.\n\n" +
             wrap(saml(issuer=entra, issued=t("2026-10-07T13:41:12"), cert_b64=expired, nameid="m.chen@contoso-health.example"))),
        dict(id="SSO-3004", plan="Enterprise", idp="Okta", from_name="Marco Bellini", company="Ledgerline",
             subject="Broke after we rotated our Okta certificate", received_at="2026-10-08T10:12Z",
             body=f"Our security team rotated the Okta signing certificate last night. Now SSO fails. The certificate fingerprint shown in our Claude SSO settings is:\n{rotated_old_fp}\n\nSAMLResponse:\n\n" +
             wrap(saml(issuer="http://www.okta.com/exk1ledgerline", issued=t("2026-10-08T10:09:30"), cert_b64=rotated_new, nameid="marco@ledgerline.example")),
             sp_override={"cert_fingerprint": rotated_old_fp}),
        dict(id="SSO-3005", plan="Team", idp="AD FS", from_name="Tom Becker", company="Brightpath Logistics",
             subject="Works for some people, fails for others", received_at="2026-10-08T14:30Z",
             body="Login works sometimes and fails other times, usually right after people sign in. We run our own AD FS server.\n\n" +
             wrap(saml(issuer="http://adfs.brightpath.example/adfs/services/trust", issued=t("2026-10-08T14:27:00"), cert_b64=good,
                       not_before=t("2026-10-08T14:31:10"), not_after=t("2026-10-08T14:36:10"), nameid="tom.becker@brightpath.example"))),
        dict(id="SSO-3006", plan="Enterprise", idp="Okta", from_name="Priya Raman", company="Northwind Analytics",
             subject="SSO creates a weird new account", received_at="2026-10-09T09:05Z",
             body="When I log in with SSO it doesn't find my existing account. It looks like it's using my username instead of my email.\n\n" +
             wrap(saml(issuer=okta, issued=t("2026-10-09T09:02:44"), cert_b64=good, nameid="praman",
                       nameid_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", attributes={"login": "praman", "firstName": "Priya"}))),
        dict(id="SSO-3007", plan="Enterprise", idp="Okta", from_name="Jordan Lee", company="Northwind Analytics",
             subject="New hire can't get in after we required SSO", received_at="2026-10-09T16:40Z",
             body="We turned on Require SSO yesterday. A new hire gets an error from Okta and never reaches Claude. Everyone else is fine.\n\n" +
             wrap(saml(issuer=okta, issued=t("2026-10-09T16:38:15"), cert_b64=good, status="urn:oasis:names:tc:SAML:2.0:status:Responder",
                       status_message="User is not assigned to this application.", signed_assertion=False))),
        dict(id="SSO-3008", plan="Team", idp="Google Workspace", from_name="Sam Whitaker", company="Casefile Legal",
             subject="Google SAML app set up but login rejected", received_at="2026-10-10T11:15Z",
             body="We built a custom SAML app in Google Workspace. The test says the response isn't signed. Here's what Google sends:\n\n" +
             wrap(saml(issuer="https://accounts.google.com/o/saml2?idpid=C0casefile", issued=t("2026-10-10T11:13:05"), cert_b64=good,
                       signed_response=False, signed_assertion=False, nameid="sam@casefile.example"))),
        dict(id="SSO-3009", plan="Enterprise", idp="Entra ID (OIDC)", from_name="Aiko Tanaka", company="Kitewise",
             subject="OIDC login suddenly broken", received_at="2026-10-11T08:50Z",
             body="We use OpenID Connect with Entra, not SAML. Starting today the login fails. Our IdP logs show:\n\n" +
             json.dumps({"error": "invalid_client", "error_description": "AADSTS7000222: The provided client secret keys for app 'b2f1c9d0-0000-4000-8000-kitewise0001' are expired. Visit the Azure portal to create new keys for your app.", "error_codes": [7000222], "timestamp": "2026-10-11 08:47:31Z", "trace_id": "5a1f0c2e-0000-4000-8000-000000000001", "correlation_id": "c0ffee00-0000-4000-8000-000000000002"}, indent=2)),
        dict(id="SSO-3010", plan="Enterprise", idp="Okta (OIDC)", from_name="Dev Patel", company="Stackmint",
             subject="Token rejected after switching to OIDC", received_at="2026-10-11T12:05Z",
             body="We moved from SAML to OIDC. Login fails and the error mentions the audience. Here's the ID token Okta returned (from our logs):\n\n" +
             jwt({"alg": "RS256", "kid": "k1"}, {"iss": "https://stackmint.okta.example/oauth2/default", "sub": "00u1dev", "aud": "0oa1oldsamlapp",
                  "iat": 1791806690, "exp": 1791810290, "email": "dev@stackmint.example", "nonce": "n-7f1c"}),
             sp_override={"client_id": "0oa1stackclaude"}),
        dict(id="SSO-3011", plan="Enterprise", idp="Okta", from_name="Hannah Okafor", company="Brightpath Health",
             subject="Domain stuck on Pending for two days", received_at="2026-10-12T09:30Z",
             body="We added the TXT record two days ago and the domain still says Pending. Our DNS check:\n\n$ dig +short TXT brightpath-health.example\n\"v=spf1 include:_spf.example-mail.com ~all\"\n\n$ dig +short TXT www.brightpath-health.example\n\"anthropic-domain-verification-8Hq2kLm0Zp7Xv1Rt\"\n"),
        dict(id="SSO-3012", plan="Enterprise", idp="Okta", from_name="Lena Fischer", company="Northwind Analytics",
             subject="Removed a user but they keep coming back", received_at="2026-10-12T15:10Z",
             body="We use JIT provisioning. I removed a contractor from our Claude member list last week, and today they're back. We didn't touch Okta. How do we remove them for good?"),
        dict(id="SSO-3013", plan="Enterprise", idp="Okta", from_name="Ana Lima", company="Northwind Analytics",
             subject="Is this response OK? Still can't log in", received_at="2026-10-13T10:00Z",
             body="IT says the SAML looks fine, but one user still can't get in. She's on our second domain, northwind-labs.example, which we added last month.\n\n" +
             wrap(saml(issuer=okta, issued=t("2026-10-13T09:58:20"), cert_b64=good, nameid="kim@northwind-labs.example",
                       attributes={"email": "kim@northwind-labs.example", "firstName": "Kim"}))),
    ]
    for tk in tickets:
        sp = dict(SP)
        sp.update(tk.pop("sp_override", {}))
        tk["sp"] = sp
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(tickets, indent=2) + "\n")
    print(f"wrote {len(tickets)} tickets to {OUT}; good cert fingerprint {good_fp}; rotated new {rotated_new_fp}")


if __name__ == "__main__":
    main()
