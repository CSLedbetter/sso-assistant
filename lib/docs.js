// The only pages Claude may cite, and the facts it may rely on, taken from Claude's help center (checked October 13, 2026)
// plus two general passkey references (checked October 14, 2026).

export const DOCS = [
  { url: 'https://support.claude.com/en/articles/13132885-set-up-single-sign-on-sso', title: 'Set up single sign-on (SSO)' },
  { url: 'https://support.claude.com/en/articles/10276682-important-considerations-before-enabling-single-sign-on-sso-and-jit-scim-provisioning', title: 'Important considerations before enabling SSO and JIT/SCIM provisioning' },
  { url: 'https://support.claude.com/en/articles/13133195-set-up-jit-or-scim-provisioning', title: 'Set up JIT or SCIM provisioning' },
  { url: 'https://support.claude.com/en/articles/14625619-claim-and-migrate-accounts-on-your-domain', title: 'Claim and migrate accounts on your domain' },
  { url: 'https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API', title: 'Web Authentication API (MDN)' },
  { url: 'https://passkeys.dev/docs/reference/terms/', title: 'Passkey terms: synced and device-bound passkeys (passkeys.dev)' },
];

export const FACTS = `
How SSO works for Claude Team, Enterprise and Console organizations (from the Claude help center):
- Setup needs an Owner or Primary Owner (Team/Enterprise) or an Admin (Console), plus access to the company's DNS and its identity provider (IdP).
- WorkOS is Anthropic's provider for domain verification and SSO setup; the setup flow walks through IdP-specific guides (Okta, Entra ID, Google, OneLogin, JumpCloud, Duo).
- Domain verification comes first: add the TXT record whose value begins with anthropic-domain-verification- at the domain root (not www or another subdomain), exactly as shown and case-sensitive, alongside existing TXT records. Wait at least 10 minutes; propagation can take 24 to 48 hours. If it stays Pending, check the record is at the root and matches exactly. Removing and re-adding the domain generates a new value, so the DNS record must be updated to match. If everything is correct and it's still Pending, contact support.
- All verified domains in an organization must use a single IdP. Each parent organization links to one IdP.
- After setup, the admin runs Test Single Sign-on. With "Require SSO" on, users not correctly assigned to the Anthropic app in the IdP can't log in.
- When the IdP's SAML signing certificate expires or is rotated (or an OIDC client secret expires), update it in Claude: Organization settings (claude.ai/admin-settings/organization) or Console Identity settings > Authentication > Manage SSO > Metadata configuration > Edit (SAML), or replace the client secret (OIDC).
- Provisioning modes: Invite only (default), Just-in-time (JIT, all plans: users assigned to the IdP app are provisioned at first login with the User role), and SCIM directory sync (Enterprise and Console only, not Team).
- JIT never removes members automatically. A user removed only in Claude is re-added the next time they log in with SSO. To remove a JIT user for good, remove them in Claude AND unassign them in the IdP.
- With SCIM, users removed from the IdP app are removed automatically. Group mappings can set role and seat tier from IdP groups.
- IdP-initiated login isn't supported for Console organizations that share SSO settings with a Team or Enterprise organization; use SP-initiated login.

General SAML and OIDC facts:
- The SAML Audience must equal the service provider's entity ID, and Destination/Recipient must equal its ACS URL. These come from the SSO setup screen and are entered in the IdP app.
- Service providers reject assertions outside NotBefore/NotOnOrAfter, allowing only small clock skew; an IdP server with a wrong clock causes intermittent failures.
- A SAML Responder/RequestDenied status means the IdP refused to issue an assertion (for example, the user isn't assigned to the app). No assertion reaches the service provider.
- NameID should be the user's email address so accounts match.
- Responses must be signed (response, assertion, or both).
- An OIDC ID token's aud must be the client ID of the app registration the service provider uses.

Passkey (WebAuthn) facts. Passkeys are set up and checked by the customer's identity provider, not by Claude; a passkey failure stops the user at the IdP, before SSO reaches Claude.
- A passkey is bound to one relying party ID (RP ID), a domain. The authenticator data starts with the SHA-256 hash of that RP ID, and the relying party rejects responses whose hash doesn't match its own RP ID.
- The RP ID must be the page's own domain or a parent of it. A passkey made for example.com works on login.example.com; one made for login.example.com doesn't work on example.com. Changing the RP ID (for example in a domain migration) orphans existing passkeys, so users must register new ones unless the old RP ID is restored.
- The browser writes the page's real origin into clientDataJSON, which the authenticator signs. The relying party accepts only the origins it expects. This is why passkeys resist phishing: a look-alike domain can't produce a response the real site accepts. A legitimate new sign-in page or custom domain must be added to the relying party's allowed origins.
- Each ceremony uses a fresh challenge from the server. A response to an old challenge (a second tab, the back button, a page left open) is rejected; reloading fixes it.
- Flags: user present (a tap), user verified (PIN or biometric), backup eligible and backed up (a synced passkey). Policies that treat passkeys as phishing-resistant MFA usually require user verification. Policies that require device-bound credentials reject synced passkeys, which copy across devices through a password manager such as iCloud Keychain or Google Password Manager.
- Synced passkeys usually report a signature counter of 0. Attestation "none" means the authenticator didn't identify its model, which is normal for consumer passkeys.
- Browser errors: NotAllowedError means the user cancelled, the prompt timed out, or no passkey on this device matches the site (deliberately vague for privacy). A passkey can be used from another device, for example a phone over the hybrid QR-code flow. InvalidStateError on registration means the authenticator already holds a passkey for that account. SecurityError means the requested RP ID isn't valid for the page's domain or the page isn't on HTTPS.
`.trim();
