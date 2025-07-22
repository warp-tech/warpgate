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

CNA: [GitHub](https://www.cve.org/PartnerInformation/ListofPartners/partner/GitHub_M)
