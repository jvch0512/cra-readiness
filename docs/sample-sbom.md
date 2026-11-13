# SBOM quality (cyclonedx)

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

3 known vulnerabilities matched, 1 actively exploited.
