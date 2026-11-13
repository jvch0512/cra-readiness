# CRA readiness: Acme IoT Gateway GW-200

Role: **manufacturer**. Product class: **important-1**. Assessed on 2026-11-13.

Readiness against Annex I: **49%**.
Article 14 reporting has applied since 2026-09-11, including to products already on the market. The remaining obligations apply from 2027-12-11 (393 days away).

## Do first

1. Start the Article 14 clock now: 1 actively exploited vulnerability found in the SBOM (EXAMPLE-2026-0001). Early warning is due within 24 hours of awareness.
2. Publish a vulnerability contact address and register for the single reporting platform: Article 14 duties already apply.
3. Write a coordinated vulnerability disclosure policy (Annex I Part II (5)).
4. Support period is under five years: document why the product is expected to be used for less (Art. 13(8)), or extend it.
5. Close Annex I Part I (2)(a): Placed on the market without known exploitable vulnerabilities.
6. Close Annex I Part I (2)(k): Exploitation mitigation mechanisms to reduce the impact of incidents.
7. Close Annex I Part II (4): Public disclosure of fixed vulnerabilities once an update is available.

## Conformity route

**Harmonised standard, or third-party assessment otherwise.** Important product class I (Annex III). Internal control is available only if harmonised standards, common specifications or a certification scheme are applied in full.

## Duties as manufacturer

- Carry out and document a cybersecurity risk assessment for the product (Art. 13)
- Draw up technical documentation and keep it for at least 10 years or the support period (Art. 13(12), Annex VII)
- Set a support period of at least five years unless the product is expected to be used for less (Art. 13(8))
- Issue the EU declaration of conformity and affix the CE marking (Art. 28)
- Report actively exploited vulnerabilities and severe incidents through the single reporting platform (Art. 14)
- Provide user information and instructions, including the security contact (Art. 13(18), Annex II)

## Annex I self-assessment

| Requirement | Reference | Answer |
|---|---|---|
| Placed on the market without known exploitable vulnerabilities | Annex I Part I (2)(a) | no |
| Secure by default configuration, with the ability to reset to the original state | Annex I Part I (2)(b) | yes |
| Security updates, automatic by default with an opt-out | Annex I Part I (2)(c) | partial |
| Protection against unauthorised access: authentication, identity and access management | Annex I Part I (2)(d) | yes |
| Confidentiality of data: encryption at rest and in transit | Annex I Part I (2)(e) | yes |
| Integrity of data, commands, programs and configuration | Annex I Part I (2)(f) | yes |
| Data minimisation: only adequate, relevant and necessary data | Annex I Part I (2)(g) | no |
| Availability of essential functions, including resilience against denial of service | Annex I Part I (2)(h) | partial |
| Minimised negative impact on other devices or networks | Annex I Part I (2)(i) | no |
| Limited attack surfaces, including external interfaces | Annex I Part I (2)(j) | yes |
| Exploitation mitigation mechanisms to reduce the impact of incidents | Annex I Part I (2)(k) | no |
| Security logging and monitoring with an opt-out for the user | Annex I Part I (2)(l) | partial |
| Secure and easy removal of all data and settings | Annex I Part I (2)(m) | no |
| Vulnerabilities identified and documented, including an SBOM covering at least the top-level dependencies | Annex I Part II (1) | yes |
| Vulnerabilities addressed without delay, including through security updates | Annex I Part II (2) | partial |
| Effective and regular tests and reviews of the security of the product | Annex I Part II (3) | partial |
| Public disclosure of fixed vulnerabilities once an update is available | Annex I Part II (4) | no |
| A coordinated vulnerability disclosure policy | Annex I Part II (5) | no |
| A contact address for reporting vulnerabilities | Annex I Part II (6) | no |
| Secure distribution of updates | Annex I Part II (7) | yes |
| Security patches disseminated without delay and free of charge, with advisory messages | Annex I Part II (8) | no |

## SBOM

Quality score: **95/100** across 12 components (NTIA minimum elements).

| Element | Coverage |
|---|---|
| Component version | 92% |
| Supplier name | 83% |
| Unique identifier (purl) | 92% |
| Licence (not an NTIA element, useful for CRA due diligence) | 83% |
| Hash | 58% |
| Dependency relationships | present |
| Author of SBOM data | present |
| Timestamp | present |

## Issues

- Only 92% of components carry a version.
- Only 83% of components name a supplier.
- Only 92% of components have a package URL, so vulnerability matching will miss them.
- Only 83% of components declare a licence.
- Duplicate entries: jsonwebtoken@8.5.1.

### Known vulnerabilities in the SBOM

| Component | Advisory | Severity | Exploited | Fixed in |
|---|---|---|---|---|
| openssl@1.1.1k | EXAMPLE-2026-0001 | critical | **yes** | 3.0.15 |
| lodash@4.17.15 | EXAMPLE-2026-0002 | high | no | 4.17.21 |
| curl@7.76.0 | EXAMPLE-2026-0003 | medium | no | 8.5.0 |

1 component(s) have no package URL and could not be matched.

_Dates and thresholds are encoded from Regulation (EU) 2024/2847. This is a readiness aid, not legal advice._
