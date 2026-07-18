==================================
Polimex Secure WebSocket Transport
==================================

Shared secure-websocket transport base for Polimex devices that hold a permanent
real-time connection to Odoo over the bus (``/websocket``).

Overview
========

Both the ``hr_rfid`` Access Control application and the ``polimex_iot`` gateway
app talk to the same class of iCON1XX firmware over the same secure-websocket
wire contract (proto 3): the device holds one anonymous websocket, subscribes to
a per-device string channel whose credential is the device ``key``, and proves
firmware authenticity with an HMAC over ``s|k|n`` using a build-wide
``FW_SECRET``. Historically each app carried its own near-verbatim copy of the
ingress + auth layer (hello / HMAC / anti-replay / TOFU re-key / bus publish),
which drifted and produced a double-credential bug when both apps saw the same
physical serial.

This module extracts that transport layer into one neutral place so both apps
reuse a single implementation and a single credential per serial.

Architecture
============

* ``polimex.ws.mixin`` (AbstractModel) - the shared transport + auth methods
  (secure hello with HMAC / anti-replay / TOFU key adoption, inbound dispatch,
  bus publish, presence, channel lifecycle). Each host model adds it to
  ``_inherit`` and implements a small set of domain hooks.
* ``polimex.ws.endpoint`` - the one credential/presence row per physical serial;
  both host models delegate to it via ``_inherits`` so a serial maps to exactly
  one key.
* ``polimex.ws.session.mixin`` - tunnel-session lifecycle (only the IoT session
  inherits it).
* One ``ir.websocket`` ingress with a per-app branch registry.

Independence
============

This module depends only on Odoo core (``mail``, ``bus``). It references neither
Access Control nor IoT. Both domain modules depend on this one; neither depends
on the other - the two remain fully independent functions sharing only transport.

Credits
=======

* Polimex Holding Ltd. <https://polimex.co>
