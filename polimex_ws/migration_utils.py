# Polimex Holding Ltd. - https://polimex.co
"""Shared migration helper: back-fill polimex.ws.endpoint for an existing host.

Called from each host module's ``pre-migrate`` (hr_rfid, polimex_iot_base) when
the P2 endpoint-delegation lands on a DB that already has host rows. It runs
BEFORE the ORM schema sync so the required ``endpoint_id`` is populated by the
time Odoo tries to enforce NOT NULL - the canonical "add a required FK to
existing data" pattern.

Raw SQL is deliberate: at pre-migrate time the models are not loaded, AND the
host's OLD credential/presence columns (``key``, ``ws_*``) are exactly what we
must read - once the P2 code loads, those field names delegate to the (still
empty) endpoint, so the ORM can no longer see the legacy values. The columns
themselves survive (Odoo never drops a removed field's column), so we read them
directly here.

One endpoint per serial (get-or-create); a device that is BOTH a webstack and a
gateway converges on ONE endpoint. The credential/presence is copied VERBATIM
(including a legacy ``0000`` - the device keeps working; the 0000-is-insecure
handling is a separate app-level concern, not a data drop). On a shared serial
the first host to migrate seeds the endpoint; a later host only fills fields the
endpoint still has NULL, and logs a warning if it holds a DIFFERENT non-empty
key (the rare genuine double-key divergence).
"""
import logging

_logger = logging.getLogger(__name__)

# Endpoint credential/presence columns that may exist on a host table and must
# be carried over. serial is handled separately (the dedup key).
_EP_COLS = (
    "key", "ws_enabled", "ws_proto", "ws_last_seen",
    "ws_provision_pending", "ws_auth_fail_count", "ws_auth_fail_since",
    "ws_last_n",
)


def _col_exists(cr, table, column):
    cr.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = %s AND column_name = %s",
        (table, column),
    )
    return bool(cr.fetchone())


def link_host(cr, host_table):
    """Create/reuse one endpoint per serial for every host row and set
    endpoint_id. Idempotent: rows already linked are skipped."""
    if not _col_exists(cr, host_table, "serial"):
        _logger.warning("polimex_ws migration: %s has no serial column - skip",
                        host_table)
        return
    # The endpoint_id column is added by the ORM schema sync AFTER pre-migrate;
    # create it early so we can populate it now.
    cr.execute(
        'ALTER TABLE "%s" ADD COLUMN IF NOT EXISTS endpoint_id integer'
        % host_table)
    present = [c for c in _EP_COLS if _col_exists(cr, host_table, c)]
    select_cols = ", ".join(['"%s"' % c for c in ["id", "serial"] + present])
    cr.execute(
        'SELECT %s FROM "%s" WHERE endpoint_id IS NULL' % (select_cols, host_table))
    rows = cr.fetchall()
    linked = created = 0
    for row in rows:
        host_id, serial = row[0], row[1]
        vals = dict(zip(present, row[2:]))
        if serial:
            ep_id = _get_or_create_endpoint(cr, serial, vals)
            created += ep_id[1]
            ep_id = ep_id[0]
        else:
            # serial-less placeholder (rare manual row): its own private endpoint.
            ep_id = _insert_endpoint(cr, None, vals)
            created += 1
        cr.execute(
            'UPDATE "%s" SET endpoint_id = %%s WHERE id = %%s' % host_table,
            (ep_id, host_id))
        linked += 1
    _logger.info("polimex_ws migration: linked %s %s row(s) to %s endpoint(s) "
                 "(%s newly created)", linked, host_table, linked, created)


def _get_or_create_endpoint(cr, serial, vals):
    """Return (endpoint_id, created_flag). On a pre-existing endpoint (shared
    serial), fill any NULL column from vals and warn on a divergent key."""
    cr.execute("SELECT id, key FROM polimex_ws_endpoint WHERE serial = %s",
               (str(serial),))
    found = cr.fetchone()
    if not found:
        return _insert_endpoint(cr, serial, vals), 1
    ep_id, ep_key = found
    incoming_key = vals.get("key")
    if (incoming_key and ep_key and incoming_key != ep_key):
        _logger.warning(
            "polimex_ws migration: serial %s has divergent keys across hosts "
            "(endpoint=%r, host=%r); keeping the first (endpoint) value. Review "
            "and re-key if needed.", serial, ep_key, incoming_key)
    # Fill only columns the endpoint still has NULL (first-writer wins otherwise).
    fill = {c: v for c, v in vals.items() if v is not None}
    if fill:
        sets = ", ".join('"%s" = COALESCE("%s", %%s)' % (c, c) for c in fill)
        cr.execute(
            'UPDATE polimex_ws_endpoint SET %s WHERE id = %%s' % sets,
            list(fill.values()) + [ep_id])
    return ep_id, 0


def _insert_endpoint(cr, serial, vals):
    cols = ["serial"] + list(vals.keys())
    placeholders = ", ".join(["%s"] * len(cols))
    params = [str(serial) if serial is not None else None] + list(vals.values())
    cr.execute(
        'INSERT INTO polimex_ws_endpoint (%s, create_uid, create_date, '
        'write_uid, write_date) VALUES (%s, 1, now(), 1, now()) RETURNING id'
        % (", ".join('"%s"' % c for c in cols), placeholders),
        params)
    return cr.fetchone()[0]
