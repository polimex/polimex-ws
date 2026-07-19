# Polimex Holding Ltd. - https://polimex.co
"""The shared per-serial credential + presence row (``polimex.ws.endpoint``).

ONE row per physical device serial. Both host models (``hr.rfid.webstack`` and
``polimex.iot.gateway``) delegate their real-time credential and presence to it
via ``_inherits`` and a get-or-create-by-serial ``create`` override, so a single
physical device that serves BOTH access-control controllers AND an IoT tunnel has
exactly ONE key and ONE presence watermark - fixing the double-credential drift
that a per-host key produced when the two diverged.

The row carries only the transport credential/presence (key + ws_* state); the
device's business identity (name, company, controllers, wired serial devices)
stays on the host records. It inherits ``polimex.ws.mixin`` purely to reuse the
presence compute/search + the config-parameter helpers - the transport dispatch
methods on the mixin are never called on an endpoint (they run on the hosts).
"""
from odoo import api, fields, models


class PolimexWsEndpoint(models.Model):
    _name = "polimex.ws.endpoint"
    _inherit = ["polimex.ws.mixin"]
    _description = "Polimex WebSocket Endpoint (per-serial shared credential)"
    _order = "serial"

    # serial is the dedup key: one endpoint per physical serial. NOT required -
    # a host created without a serial yet (rare manual case) gets its own fresh
    # endpoint (serial NULL; Postgres UNIQUE permits many NULLs); the real
    # register/discovery flows always create the host WITH a serial, so they
    # dedup through the create override. UNIQUE guarantees one row per serial.
    serial = fields.Char(
        string="Serial number",
        index=True,
        help="The physical device serial this credential belongs to.",
    )
    _serial_uniq = models.Constraint(
        "UNIQUE(serial)",
        "A websocket endpoint for this serial already exists.")

    # default=False (UNPROVISIONED) - NOT '0000' (owner + FW-Q26, 2026-07-19).
    # '0000' is a legacy/insecure placeholder, never a valid minted credential
    # (the firmware derives a NON-zero MAC key on reset). A fresh endpoint is
    # therefore keyless: it adopts the device's presented key on the first
    # authenticated hello (TOFU) - but ONLY a NON-zero key (a device presenting
    # '0000' is left unprovisioned, never adopted; see the mixin _ws_check_hello /
    # the AC HTTP auth). An EXISTING '0000' credential still auth-matches (a
    # legacy field device keeps working) but is flagged needs-provisioning.
    # No tracking= here: the endpoint is not a mail.thread; the hosts post audit
    # notes through the mixin's action_ws_* / _ws_check_hello.
    key = fields.Char(
        string="Key",
        size=4,
        index=True,
        default=False,
        help="Security key for device authentication - the channel credential "
             "the device presents on the real-time connection. Blank or 0000 = "
             "not securely provisioned.",
    )
    ws_needs_provisioning = fields.Boolean(
        string="Needs provisioning",
        compute="_compute_ws_needs_provisioning",
        search="_search_ws_needs_provisioning",
        help="The device has no secure key yet (blank or the insecure 0000 "
             "placeholder). Re-key it so it presents a real generated credential.",
    )

    @api.depends("key")
    def _compute_ws_needs_provisioning(self):
        for rec in self:
            rec.ws_needs_provisioning = rec.key in (False, "", "0000")

    def _search_ws_needs_provisioning(self, operator, value):
        if operator not in ("=", "!=") or not isinstance(value, bool):
            return NotImplemented
        insecure = [("key", "in", [False, "", "0000"])]
        needs = (operator == "=") == value
        return insecure if needs else (["!"] + insecure)

    # ------------------------------------------------------------------
    # Real-time presence / anti-replay / anti-flood (shared across the hosts).
    # The compute/search behind ws_online lives in polimex.ws.mixin.
    # ------------------------------------------------------------------
    ws_enabled = fields.Boolean(
        string="Real-time Channel",
        help="Whether the permanent real-time connection is enabled for this "
             "device.",
        default=False,
    )
    ws_proto = fields.Integer(
        string="Protocol Version",
        readonly=True,
        copy=False,
        help="Real-time protocol version negotiated on the last connection.",
    )
    ws_last_seen = fields.Datetime(
        string="Last Real-time Activity",
        readonly=True,
        copy=False,
        help="Last time the device sent anything over the real-time link.",
    )
    ws_online = fields.Boolean(
        string="Real-time Online",
        compute="_compute_ws_online",
        search="_search_ws_online",
        help="The device is currently connected in real time (activity within "
             "the last two heartbeat intervals).",
    )
    ws_provision_pending = fields.Boolean(
        string="Settings Pending Delivery",
        copy=False,
        help="The real-time settings changed and will be delivered on the next "
             "check-in.",
    )
    ws_auth_fail_count = fields.Integer(copy=False)
    ws_auth_fail_since = fields.Datetime(copy=False)
    # Anti-replay watermark for the secure hello: the highest `n`
    # (boot_count*65536 + seq) this device has proven; a hello with
    # n <= ws_last_n is a replay and is refused.
    ws_last_n = fields.Integer(copy=False, default=0)

    @api.model
    def _ws_get_or_create(self, serial):
        """Return the single endpoint for ``serial``, creating it if absent.
        Race-safe: a concurrent create that wins the UNIQUE(serial) is caught
        and the winner is re-read. Called from the host create/write overrides
        so one serial maps to exactly one endpoint (the double-key fix)."""
        endpoint = self.sudo().search([("serial", "=", serial)], limit=1)
        if endpoint:
            return endpoint
        try:
            with self.env.cr.savepoint():
                return self.sudo().create({"serial": serial})
        except Exception:  # UNIQUE(serial) race - a concurrent create won
            return self.sudo().search([("serial", "=", serial)], limit=1)
