# Odoo Bus device-channel - security findings (REPORT-ONLY)

Findings on the device websocket channel surfaced by the 3-lens architectural
review of 2026-07-24 (the double-branch hello race). **None of them was
introduced by that fix** - they are pre-existing properties of the proto-3
channel. Nothing here is fixed yet: each needs either an owner decision or a
scheduled hardening pass, and several are closed by the proto-4 redesign.

Threat model: an on-LAN peer on a cleartext `ws://` install. Serial + key are
NOT secret in proto 3 (the key is `crc16(MAC)`, 16-bit, and it rides in the bus
channel NAME); the only real proof of firmware authenticity is the hello HMAC
over `s|k|n` with the build-wide `FW_SECRET`.

| # | Finding | Module | Closed by proto 4? |
|---|---|---|---|
| 1 | Presence forgery (pre-validation stamp + unauthenticated `hb`) | polimex_ws | yes (per-frame sig) |
| 2 | Nack published to an attacker-chosen channel name | polimex_ws | yes (session channel) |
| 3 | `ok`-ack can be published for a hello whose handler rolled back | polimex_ws | no - own fix |
| 4 | Watermark check+write has no row lock (cross-transaction race) | polimex_ws | yes (per-session nonce) |
| 5 | Co-install double-counts auth failures | polimex_ws | partly - own fix |
| 6 | `_op_effects` is advisory on the normal dispatch path | polimex_iot_base | no - own fix |
| 7 | Borica `_encode_job` does not enforce `fiscal_mode='test'` | polimex_iot_borica | no - own fix |

## 1. Presence forgery - stamp happens before validation, and `hb` is unauthenticated

`_ws_dispatch` stamps presence (`device._ws_touch()`) as soon as the frame's key
matches the stored key, i.e. BEFORE `_ws_check_hello` proves the firmware HMAC
and the counter. Separately, `hb` frames carry no `auth`/`n` at all - the `hb`
handler does no cryptographic check.

**Impact:** a peer who sniffed `s` + `k` off the cleartext channel can keep a
dead/unplugged/tampered device showing `ws_online = True` indefinitely with
crafted heartbeats, suppressing an operator's outage investigation. No data is
altered; this is an integrity-of-monitoring issue, and on an access-control
product a "green" dead controller is operationally meaningful.

**Fix direction:** move the hello-path presence stamp to AFTER
`_ws_check_hello`, and treat `hb` as unauthenticated telemetry (proto 4's
per-frame session signature closes it properly).

## 2. Nack is published to a channel name the caller chose

`_ws_nack_hello` publishes the refusal to `<prefix>#<serial>#<k>` using the `k`
**exactly as presented on the wire** - deliberately, so a refused peer (which is
subscribed only to its claimed channel) actually receives the refusal instead of
sitting deaf-mute. The consequence is that an unauthenticated caller steers a
bus publish to an arbitrary channel name.

**Impact:** low - the nack body carries no key or secret, and the shared
auth-fail threshold rate-limits it. It is a confused-deputy amplification
inherent to "channel-name-as-credential" with no subscription ACL.

**Fix direction:** proto 4's session-scoped channels + subscription
authorization. Until then, keep the rate limit; do not widen it.

## 3. An `ok` ack can be published for a hello whose handler later rolled back

`_ws_on_hello` publishes `hello_ack {ok: true}` through `bus._sendone` from
INSIDE the handler savepoint. `_sendone` defers the row insert to a precommit
callback whose data is captured at call time, so if the handler raises AFTER the
ack call, the savepoint rolls the ORM work back while the ack still goes out.

**Impact:** the device believes a hello succeeded although the branch's
capture/provisioning was rolled back - a state divergence, not a breach.

**Fix direction:** publish the ack after the handler body completes (or make the
ack itself part of the rolled-back unit).

## 4. The anti-replay watermark check+write is not serialized

`_ws_check_hello` reads `ws_last_n`, compares, then writes it, with no row lock
on the endpoint. Two overlapping connections for the same serial (a reconnect
race) can both read the old watermark in parallel transactions and both accept
the same `n`.

**Impact:** a narrow duplicate-accept window; it does not grant access to a peer
that lacks `FW_SECRET` (the HMAC still has to verify).

**Fix direction:** note that BOTH Odoo ORM lock helpers use `FOR UPDATE SKIP
LOCKED` (they skip/raise, they do not wait), so serializing this needs a raw
`SELECT ... FOR UPDATE` on the endpoint row. Proto 4's per-session random nonce
removes the shared-counter design entirely.

## 5. A genuinely invalid hello is counted twice on a co-installed system

Both branch ingresses claim the same wire frame, so a genuinely bad hello fails
validation in each and calls `_ws_auth_failed` twice - the anti-flood threshold
(5) is reached in 3 frames instead of 5, and two identical warnings are logged
per frame.

**Impact:** cosmetic/telemetry; it makes the anti-flood trip earlier than
designed. (The valid-hello case is fixed - that was the 2026-07-24 per-frame
validation dedup.)

**Fix direction:** an analogous per-frame marker for the FAILURE path, or count
auth failures per frame rather than per branch.

## Consumer-side findings (recorded here because the same review surfaced them)

These live in the IoT consumer, not in the neutral transport. Listed for one
complete record of the review; the transport does not depend on them.

### 6. `_op_effects` does not gate the normal dispatch path

`polimex.iot.job._send_now` encodes and sends unconditionally;
`_op_effect`/`_is_bench_safe` are consulted only by the auto-detect sweep and by
external bench scripts. So the `OP_SAFE` / `OP_IRREVERSIBLE` classification is
**advisory** on a manually dispatched job - it will not stop a mis-dispatched
irreversible op (e.g. a purchase at a real terminal).

**Operational rule until this is enforced:** on a bench device with a real
money-moving terminal, create ONLY the intended safe job; never queue a
purchase-family job alongside it. (The Borica `probe` is separately safe *by
construction* - it structurally cannot emit a send-amount frame - so it does not
rely on this classification.)

**Fix direction:** enforce `_op_effect` in `_send_now` against the device's
fiscal/test mode + an explicit operator permission, the way `_check_actuation`
already gates the Paradox actuating ops.

### 7. Borica `_encode_job` does not call the test-mode guard

Unlike the pattern the base contract suggests (and unlike the Paradox driver's
actuation guard), the Borica driver's `_encode_job` does not call
`_check_test_mode` / `_check_actuation`, so `fiscal_mode='test'` is not enforced
for Borica purchases. Irrelevant to `probe` (it never reaches send-amount), but
it means a purchase op is not blocked by test mode.

**Fix direction:** call the base guard in `_encode_job` for the purchase family.

---

Method: findings produced by three independent review lenses (security,
Odoo-framework, production-ops) against the source, then cross-checked against
Odoo core (`odoo/sql_db.py`, `odoo/tools/misc.py`) for the transaction-lifecycle
claims. Numbers 6-7 additionally confirmed by the Borica money-safety gate of
2026-07-24.
