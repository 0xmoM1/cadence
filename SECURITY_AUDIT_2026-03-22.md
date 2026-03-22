# Security Audit Notes (2026-03-22)

Scope: deep review of account capability / inbox flows, controller lifecycle, and type enforcement boundaries.

## Confirmed high-risk leads investigated

### 1) Inbox publish: no ownership check for published capability
- `AccountInboxPublish` accepts any `CapabilityValue` and stores it without verifying `capability.address == provider`.
- Unlike `AccountCapabilitiesPublish`, which rejects cross-account capability publication, inbox publish has no equivalent guard.

Potential impact: capability substitution / confused-deputy behavior in higher-level protocols that trust inbox sender identity.

### 2) Inbox publish: overwrite allowed (no collision prevention)
- `AccountInboxPublish` directly `WriteStored(... StorageDomainInbox, key, publishedValue)` with no `StoredValueExists` pre-check.
- `AccountCapabilitiesPublish` explicitly blocks overwrite.

Potential impact: replacement/replay of pending inbox payloads by any principal with inbox publish authority, enabling DoS or malicious substitution of expected capabilities.

### 3) Capability controller stale-reference behavior after delete
- Controller delete sets only in-memory `deleted` bool on the specific instance (`controller.deleted = true`).
- Other references to the same controller instance loaded earlier may not get `deleted=true`.
- Some stale operations then fail only via later storage invariants/panics, rather than explicit "deleted" gating.

Potential impact: stale-reference semantics can be abused for confusion, inconsistent errors, and possible griefing; requires deeper validation for exploitability beyond DoS.

## Additional observations
- Authorization/bounds checks around `AccountCapabilitiesGet/Borrow` and controller retrieval are generally robust, including entitlement and dynamic dereference checks.
- Iteration mutation protections are present for controller index maps.
