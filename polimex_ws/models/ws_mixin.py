# Polimex Holding Ltd. - https://polimex.co
"""Shared secure-websocket transport + auth mixin (``polimex.ws.mixin``).

The transport-generic half of the device real-time channel: the anonymous
``/websocket`` ingress dispatch, the secure hello (firmware HMAC over ``s|k|n``
with a build-wide ``FW_SECRET`` + strictly-monotonic anti-replay counter + TOFU
key adoption), the per-frame constant-time key auth, presence, the channel
lifecycle and the single bus-publish helper.

Both host models mix this in and keep their own domain layer:

* ``hr.rfid.webstack`` (Access Control) - controllers, command delivery, event
  batches, HTTP provisioning.
* ``polimex.iot.gateway`` (IoT) - the frame-aware tunnel to serial devices.

The wire contract (SSOT) is ``docs/odoo-bus/ODOO_BUS_PROTOCOL_SPEC.md`` in the
iCON1XX firmware repo (proto 3, owner 2026-07-14). The per-branch differences
(channel prefix, key casing, handler map, hello capture, system-event sink,
disable semantics) are expressed as small overridable hooks - see the
``# --- hooks ---`` section; everything else is byte-behaviour-identical to the
two copies this mixin replaces.
"""
import hashlib
import hmac
import logging
from datetime import timedelta

from odoo import api, fields, models
from odoo.tools import consteq

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wire-contract constants (proto 3; SPEC §6.1). Values are UNCHANGED from the
# two branches this mixin unifies - do not tune them here without a wire review.
# ---------------------------------------------------------------------------
WS_PROTO_VERSION = 3
WS_PROTO_SUPPORTED = (3,)

# HMAC secret shared with the firmware build (out-of-band; NOT in any spec).
# FW_SECRET is a build-time global #define - ONE shared value for every device
# (FW answer Q5, 2026-07-16). The canonical parameter lives in this neutral
# module; the two legacy per-app names are read as a documented fallback so an
# existing single-app install keeps working and a co-installed system configures
# the secret only once. This is a DATA-level lookup (get_param returns None when
# a row is absent), NOT a module dependency.
WS_FW_SECRET_PARAM = "polimex_ws.ws_fw_secret"
WS_FW_SECRET_PARAM_FALLBACKS = (
    "polimex_iot.ws_fw_secret",
    "hr_rfid.ws_fw_secret",
)

# Heartbeat interval advertised in hello_ack (SPEC §6.1); tunable per install.
# Same canonical-then-fallback lookup as the secret so a pre-set legacy param is
# honoured after the extraction.
WS_HB_INTERVAL_DEFAULT_S = 60
WS_HB_INTERVAL_PARAM = "polimex_ws.ws_hb_interval"
WS_HB_INTERVAL_PARAM_FALLBACKS = (
    "polimex_iot.ws_hb_interval",
    "hr_rfid.ws_hb_interval",
)

# hello_ack settings advertised to the device (SPEC §6.1).
WS_ACK_TIMEOUT_S = 10
WS_RL = {"rate": 5, "burst": 8}

# Anti-flood on invalid tokens (SPEC §9.2): after this many failures within the
# window, ONE operator notification is raised.
WS_AUTH_FAIL_THRESHOLD = 5
WS_AUTH_FAIL_WINDOW_S = 60

# ---------------------------------------------------------------------------
# FW-pinned wire TYPE literals. INV-1 (FW answer Q2, PERMANENT): the FW
# down_type() map (esp32 modules/OdooWs) knows ONLY the hr_rfid.* type literals
# and DROPS + watermarks any unknown type, so a renamed alias silently reproduces
# the burned "stuck at tn_open" symptom with no error anywhere. Channel = routing
# (per-branch prefix); type = the hr_rfid.* literal, UNCHANGED. These are WIRE
# CONSTANTS, not a code dependency on the AC app.
# ---------------------------------------------------------------------------
HELLO_ACK = "hr_rfid.hello_ack"
BYE = "hr_rfid.bye"
TN_OPEN = "hr_rfid.tn_open"
TN_TX = "hr_rfid.tn_tx"
TN_CLOSE = "hr_rfid.tn_close"
TN_ACK = "hr_rfid.tn_ack"


class PolimexWsMixin(models.AbstractModel):
    _name = "polimex.ws.mixin"
    _description = "Polimex Secure WebSocket Transport (shared base)"

    # ------------------------------------------------------------------
    # Presence
    # ------------------------------------------------------------------
    @api.model
    def _ws_get_param(self, primary, fallbacks, default):
        """Read a config parameter by the canonical name, then the legacy
        per-app fallbacks, then a static default. One place so the secret and
        the heartbeat interval share the same canonical-then-fallback rule."""
        icp = self.env["ir.config_parameter"].sudo()
        for name in (primary,) + tuple(fallbacks):
            value = icp.get_param(name)
            if value:
                return value
        return default

    @api.model
    def _ws_hb_interval(self):
        """Heartbeat interval (seconds) advertised to devices (SPEC §6.1)."""
        param = self._ws_get_param(
            WS_HB_INTERVAL_PARAM, WS_HB_INTERVAL_PARAM_FALLBACKS,
            WS_HB_INTERVAL_DEFAULT_S)
        try:
            return max(10, int(param))
        except (TypeError, ValueError):
            return WS_HB_INTERVAL_DEFAULT_S

    def _ws_online_threshold(self):
        """Online if seen within 2 heartbeat intervals (timestamp-based
        presence, no connection tracking)."""
        return fields.Datetime.now() - timedelta(seconds=2 * self._ws_hb_interval())

    @api.depends("ws_enabled", "ws_last_seen")
    def _compute_ws_online(self):
        threshold = self._ws_online_threshold()
        for rec in self:
            rec.ws_online = bool(
                rec.ws_enabled and rec.ws_last_seen and rec.ws_last_seen >= threshold)

    def _search_ws_online(self, operator, value):
        if operator not in ("=", "!=") or not isinstance(value, bool):
            return NotImplemented
        online = (operator == "=") == value
        threshold = self._ws_online_threshold()
        if online:
            return ["&", ("ws_enabled", "=", True), ("ws_last_seen", ">=", threshold)]
        return ["|", ("ws_enabled", "=", False), "|",
                ("ws_last_seen", "=", False), ("ws_last_seen", "<", threshold)]

    def _ws_touch(self):
        """Record upstream activity (any device message updates presence)."""
        self.sudo().write({"ws_last_seen": fields.Datetime.now()})

    # ------------------------------------------------------------------
    # Channel lifecycle
    # ------------------------------------------------------------------
    def action_ws_enable(self):
        """Enable the real-time channel. proto 3 has no server-issued token: the
        channel credential is the device ``key`` it already holds. A device with
        no key yet adopts it on the first authenticated hello (TOFU,
        :meth:`_ws_check_hello`)."""
        for rec in self:
            rec.sudo().write({"ws_enabled": True, "ws_provision_pending": True})
            rec.message_post(body=self.env._("Real-time channel enabled."))
        return True

    def action_ws_disable(self):
        """Disable the real-time channel. The branch decides whether to also
        signal a connected device (AC sends a ``bye`` + kicks the socket so it
        parks on HTTP; IoT flips local state only, because on a co-installed
        system the socket is shared with the AC channel - Q3, FW 2026-07-16)."""
        for rec in self:
            rec._ws_before_disable()
            rec.sudo().write({"ws_enabled": False, "ws_provision_pending": True})
            rec.message_post(body=self.env._("Real-time channel disabled."))
        self._ws_after_disable()
        return True

    def action_ws_rekey(self):
        """Re-key by TOFU (SPEC §6.6): clear the stored key; the next
        authenticated hello presents the device's current ``k``, which Odoo
        adopts (:meth:`_ws_check_hello`). No server-issued token to rotate."""
        for rec in self:
            rec.sudo().write({"key": False, "ws_provision_pending": True})
            rec.message_post(body=self.env._(
                "Real-time channel re-key armed: the next device check-in "
                "sets the new key."))
        return True

    # ------------------------------------------------------------------
    # Publish helper - the ONLY place that knows the channel name
    # ------------------------------------------------------------------
    def _ws_channel(self):
        """The device's bus channel: ``<prefix>#<serial>#<key>`` (proto 3).

        ``prefix`` and the key formatting are branch hooks; the shape is fixed
        so the naming lives in exactly ONE place per install.
        """
        self.ensure_one()
        rec = self.sudo()
        return "%s#%s#%s" % (
            self._ws_channel_prefix(), rec.serial, self._ws_channel_key())

    def _ws_send(self, mtype, payload):
        """Publish ``mtype``/``payload`` on this device's bus channel.

        Returns True when a publish happened. sudo() is deliberate and narrow:
        reading the group-protected key to build the channel name is a system
        operation on behalf of whatever flow produced the message; the payload
        itself never contains the key. No key -> silent no-op.
        """
        self.ensure_one()
        rec = self.sudo()
        if not (rec.ws_enabled and rec.key):
            return False
        # bus.bus._sendone defers the row insert to a precommit callback that
        # always runs sudo().create(); no create right is needed here.
        self.env["bus.bus"]._sendone(self._ws_channel(), mtype, payload)
        return True

    # ------------------------------------------------------------------
    # Inbound dispatch (device -> Odoo over the websocket)
    # ------------------------------------------------------------------
    @api.model
    def _ws_dispatch(self, data):
        """Entry point for device websocket messages (SPEC §4.1).

        Called by the ``ir.websocket`` ingress for every frame routed to this
        branch. The connection is anonymous (public user); every message carries
        the channel token and is re-authenticated with a constant-time compare -
        the token IS the device identity.
        """
        if not isinstance(data, dict):
            return
        serial, k, mtype = data.get("s"), data.get("k"), data.get("t")
        if not (serial and k and isinstance(mtype, str)):
            _logger.debug("WS: malformed frame (missing s/k/t): %r", data)
            return
        device = self.sudo().with_context(active_test=False).search(
            [("serial", "=", str(serial))], limit=1)
        # proto 3 auth: the channel credential is the device `key` (`k`). Every
        # frame must key-match the stored key, EXCEPT a hello from a keyless
        # device (never-contacted or re-keyed) - a TOFU candidate whose key is
        # adopted inside _ws_check_hello, but ONLY after the firmware HMAC over
        # s|k|n verifies (so a network peer cannot seed a key without FW_SECRET).
        key_ok = (device and device.key
                  and consteq(device.key.upper(), str(k).upper()))
        tofu_hello = bool(mtype == "hello" and device and not device.key)
        if (not device or not device.active or not device.ws_enabled
                or not (key_ok or tofu_hello)):
            self._ws_auth_failed(device, mtype)
            if mtype == "hello":
                self._ws_nack_hello(serial, k, device)
            return
        device._ws_touch()
        proto = data.get("v")
        if proto not in WS_PROTO_SUPPORTED:
            # Unsupported protocol: answer only a hello (SPEC §9.2), drop
            # anything else silently.
            if mtype == "hello":
                device._ws_send(HELLO_ACK, {
                    "ok": False, "err": "proto", "proto": WS_PROTO_VERSION})
            return
        if mtype == "hello" and not device._ws_check_hello(data):
            # The secure-hello identity (firmware HMAC + counter, + key adoption
            # on TOFU) did not hold - same refusal shape as a bad key.
            self._ws_auth_failed(device, mtype)
            self._ws_nack_hello(serial, k, device)
            return
        handler = device._ws_handlers().get(mtype)
        if handler is None:
            _logger.debug("WS: unknown message type %r from %s", mtype, serial)
            return
        # Isolate the transport from malformed device input. A parse error in a
        # handler must NOT escape to the bus frame loop: there it would close the
        # socket with 1011 SERVER_ERROR and log a full traceback, letting a
        # device with a valid token churn connections and flood the ERROR log.
        # Roll the partial work back in a savepoint, log a warning, note it.
        # SPEC §9.2.
        try:
            with self.env.cr.savepoint():
                handler(data)
        except Exception:
            _logger.warning(
                "WS: handler %r from device %s failed to process",
                mtype, serial, exc_info=True)
            self._ws_report_sys_ev(
                device, "Real-time message could not be processed",
                {"t": mtype})

    def _ws_fw_secret(self):
        """The build-wide FW_SECRET (canonical param, then legacy fallbacks)."""
        return self._ws_get_param(
            WS_FW_SECRET_PARAM, WS_FW_SECRET_PARAM_FALLBACKS, False)

    def _ws_check_hello(self, data):
        """Secure-hello identity for proto 3 (SPEC §5.1).

        The channel credential ``k`` IS the device key; there is no separate
        token. The hello proves ``auth`` (firmware authenticity:
        ``lowercase_hex(HMAC_SHA256(FW_SECRET, s|k|n))`` over the wire values
        verbatim) and ``n`` (strictly-monotonic anti-replay counter). A keyless
        device that presents an HMAC-verified hello has its ``k`` ADOPTED (TOFU),
        the only way a keyless device comes online - gated by the HMAC, so not a
        network-triggerable key seed. A missing FW_SECRET skips only the HMAC
        with a loud WARNING (resilience over fleet lockout); adoption is then NOT
        performed - a keyless device cannot pass without a proof to trust.
        """
        self.ensure_one()
        rec = self.sudo()
        wire_s = str(data.get("s"))
        wire_k = str(data.get("k"))
        secret = self._ws_fw_secret()
        if not secret:
            _logger.warning(
                "WS: %s is not set - accepting hello from %s WITHOUT the "
                "firmware authenticity check. Set the parameter in "
                "production.", WS_FW_SECRET_PARAM, rec.serial)
            # No proof: an already-keyed device passes (its key matched in the
            # dispatcher); a keyless device cannot be adopted without a proof.
            return bool(rec.key)
        try:
            n = int(data.get("n"))
        except (TypeError, ValueError):
            _logger.info("WS: hello from %s with a malformed counter %r",
                         rec.serial, data.get("n"))
            return False
        if n <= rec.ws_last_n:
            _logger.info("WS: hello replay from %s (n=%s <= last %s)",
                         rec.serial, n, rec.ws_last_n)
            return False
        expected = hmac.new(
            secret.encode(),
            ("%s|%s|%s" % (wire_s, wire_k, n)).encode(),
            hashlib.sha256).hexdigest()
        auth = data.get("auth")
        if not (auth and hmac.compare_digest(expected, str(auth).lower())):
            _logger.info("WS: firmware authenticity check did not pass for "
                         "hello from %s", rec.serial)
            return False
        if not rec.key:
            # TOFU: adopt the HMAC-proven key for a keyless / re-keyed device.
            rec.key = wire_k
            _logger.info("WS: adopted key for device %s on an authenticated "
                         "hello (TOFU re-key)", rec.serial)
        rec.ws_last_n = n
        return True

    @api.model
    def _ws_nack_hello(self, serial, k, device):
        """Explicit auth refusal for a hello - and ONLY a hello. Without it a
        refused device sits deaf-mute on a live socket and never falls back to
        HTTP. The nack goes to the CLAIMED channel (serial+key exactly as
        presented) - the only channel the refused peer is subscribed to.
        Rate-limited by the shared auth-fail window; an unknown serial gets no
        nack (never a nack for a device that is not ours)."""
        if not device:
            return
        if device.sudo().ws_auth_fail_count >= WS_AUTH_FAIL_THRESHOLD:
            return
        self.env["bus.bus"]._sendone(
            "%s#%s#%s" % (device._ws_channel_prefix(), serial, k), HELLO_ACK,
            {"ok": False, "err": "auth", "proto": WS_PROTO_VERSION})

    @api.model
    def _ws_report_sys_ev(self, device, description, post_data):
        """Record a diagnostic through the branch's sink - never raises into the
        caller: the websocket paths stay isolated even from a logging failure."""
        try:
            device._ws_sys_ev_record(description, post_data)
        except Exception:
            _logger.exception("WS: could not record system note: %s", description)

    @api.model
    def _ws_auth_failed(self, device, mtype):
        """Count invalid-token messages; notify ONCE at the threshold (SPEC §9.2
        anti-flood - never per message)."""
        if not device:
            _logger.debug("WS: message for unknown device (type %r)", mtype)
            return
        rec = device.sudo()
        now = fields.Datetime.now()
        window_start = now - timedelta(seconds=WS_AUTH_FAIL_WINDOW_S)
        if not rec.ws_auth_fail_since or rec.ws_auth_fail_since < window_start:
            rec.write({"ws_auth_fail_count": 1, "ws_auth_fail_since": now})
            return
        # Bound the pre-auth writes. The serial is enumerable (not secret), so an
        # attacker who guessed a valid one could otherwise force one UPDATE on
        # that row for EVERY frame. Once the window's single note has fired, stop
        # counting: writes are capped at THRESHOLD per window per serial.
        if rec.ws_auth_fail_count >= WS_AUTH_FAIL_THRESHOLD:
            return
        rec.ws_auth_fail_count += 1
        if rec.ws_auth_fail_count == WS_AUTH_FAIL_THRESHOLD:
            rec._ws_auth_fail_notify(rec.ws_auth_fail_count, mtype)

    # ------------------------------------------------------------------
    # Shared hello / heartbeat handlers
    # ------------------------------------------------------------------
    def _ws_on_hello(self, data):
        """Common secure-hello handling: capture fw/hw + proto, run the branch
        capture hook, clear the pending flag, run the branch after-hello hook,
        then answer hello_ack with the shared settings plus any branch extras."""
        self.ensure_one()
        rec = self.sudo()
        if data.get("fw"):
            rec.version = str(data["fw"])[:6]
        if data.get("hw"):
            rec.hw_version = str(data["hw"])[:6]
        rec.ws_proto = data.get("v") or WS_PROTO_VERSION
        rec._ws_on_hello_extra(data)
        rec.ws_provision_pending = False
        rec._ws_after_hello()
        ack = {
            "ok": True,
            "proto": WS_PROTO_VERSION,
            "srv_ts": fields.Datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hb_interval": self._ws_hb_interval(),
            "ack_timeout": WS_ACK_TIMEOUT_S,
            "rl": dict(WS_RL),
            "err": None,
        }
        ack.update(rec._ws_hello_ack_extra())
        self._ws_send(HELLO_ACK, ack)

    def _ws_on_hb(self, data):
        """Heartbeat: presence is already stamped by the dispatcher's
        _ws_touch(); the branch may pre-provision from the body."""
        self.ensure_one()
        self.sudo()._ws_on_hb_extra(data)

    # ------------------------------------------------------------------
    # --- hooks --- (per-branch; base defaults are the IoT-lean behaviour,
    # AC overrides the ones it needs). ``_ws_channel_prefix`` has no sensible
    # default and MUST be overridden.
    # ------------------------------------------------------------------
    def _ws_channel_prefix(self):
        """Bus-channel prefix for this branch (``hr_rfid`` / ``polimex_iot``)."""
        raise NotImplementedError(
            "a polimex.ws.mixin host must define _ws_channel_prefix()")

    def _ws_channel_key(self):
        """The key segment of the channel name. Base: the stored key verbatim.
        A branch that normalises casing overrides this."""
        return self.sudo().key or ""

    def _ws_handlers(self):
        """Message-type -> bound-handler map. Base serves the shared presence
        frames; a branch overrides with super() + its own domain frames."""
        self.ensure_one()
        return {"hello": self._ws_on_hello, "hb": self._ws_on_hb}

    def _ws_on_hello_extra(self, data):
        """Branch capture from the hello body (controllers / tunnel ports)."""
        return

    def _ws_after_hello(self):
        """Branch action after the hello is recorded (e.g. AC command sync)."""
        return

    def _ws_hello_ack_extra(self):
        """Branch-specific extra keys for the hello_ack settings block."""
        return {}

    def _ws_on_hb_extra(self, data):
        """Branch pre-provisioning from a heartbeat body."""
        return

    def _ws_sys_ev_record(self, description, post_data):
        """Persist a diagnostic in the branch's own sink. Base: post it on the
        record's chatter (mail.thread). AC overrides to use its event.system."""
        self.ensure_one()
        self.message_post(body=self.env._(
            "%(desc)s (%(data)s)", desc=description,
            data=repr(post_data)[:200]))

    def _ws_auth_fail_notify(self, count, mtype):
        """Notify the operator once the auth-fail threshold is hit. Base: chatter
        note. AC overrides to use its event.system."""
        self.ensure_one()
        self.message_post(body=self.env._(
            "Real-time messages with an invalid channel key "
            "(%(n)d in the last minute).", n=count))

    def _ws_before_disable(self):
        """Branch action before the disable flag is written (AC: send bye)."""
        return

    def _ws_after_disable(self):
        """Branch action after disabling (AC: kick the live socket)."""
        return
