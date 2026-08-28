# Security Policy

## Reporting a Vulnerability

Please report vunerabilities using GitHub's Private Vulnerability Reporting tool.

You can expect a response within a few days.

---

Warpgate considers the following trusted inputs:

* Contents of the connected database
* Contents of the config file, as long as Warpgate does not fail to lock down its permissions.
* HTTP requests made by a session previously authenticated by a user who has the `warpgate:admin` role.
* Network infrastructure and actuality and stability of target IPs/hostnames.

In particular, this does not include the traffic from known Warpgate targets.

---

Additional scope clarifications:

* Privileged-by-design actors turning hostile are out of scope, regardless of how many tiers exist.
* Hardening suggestions are welcome; their absence isn't itself a vulnerability unless independently reachable.
* Malicious transitive dependencies are only in-scope with a confirmed exploit path, not just a bad advisory.
* A trusted IdP's own authenticated users acting maliciously is between them and the IdP, not Warpgate.
* Only code that shipped in a tagged release needs a formal advisory.
* Judge severity against the most direct alternative attack the same actor already has.

---

CNA: [GitHub](https://www.cve.org/PartnerInformation/ListofPartners/partner/GitHub_M)
