# Changelog

## 1.4.3 - 2026-11-23

- Check each registration once and treat completion of a social login account as registration.
- Keep later profile edits and confirmed spam or HAM feedback separate from registration.
- Keep account age unknown when the stored join timestamp is missing or invalid.
- Omit unverified guest and Post Before Registering usernames and account age from topic/reply checks.
- Preserve submitted content, links, network and first-post checks; continue evaluating genuine registered member identities.
- Verified the native application lifecycle on Invision Community 5.0.21 with PHP 8.3.

## 1.4.2 - 2026-10-12

- Add an off-by-default native seven-day repeat-spammer ban option and minutely
  task, with atomic hashed evidence, body/reference deduplication, bounded storage,
  fresh account/role checks and moderator-reversal receipts.
- Persist evidence after validated native forms/content events; keep account
  mutation in the separate task and preserve existing identity and held metadata.
- Add disposable native upgrade, concurrency, rollback/crash, AdminCP and lifecycle
  verification with rehydration snapshots and container removal on exit.


## 1.4.1 - 2026-09-18

- Route lifecycle and bootstrap requests through the resilient public API path.

## 1.4.0 - 2026-09-11

- Replace health and endpoint-catalogue routing with deterministic GeoDNS
  fallback and keep regional routing locked unless global fallback is enabled.
- Limit standard-plan heartbeat attempts to hourly while retaining ten-minute
  Pro/MultiMod check-ins.

## 1.3.6 - 2026-09-07

- First release licensed under `GPL-2.0-or-later`.
- Add the complete GPLv2 text, project notice and same-licence contribution
  terms while keeping the hosted service separate.
- Forum Fortress approved GPL publication on 2026-09-07; no linking exception
  is granted or asserted.
