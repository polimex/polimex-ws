# Polimex Holding Ltd. - https://polimex.co
{
    "name": "Polimex Secure WebSocket Transport",
    "summary": "Shared secure-websocket transport base (device hello/HMAC auth, "
               "anti-replay, TOFU re-key, bus publish and tunnel ingress) reused "
               "by hr_rfid Access Control and Polimex IoT.",
    "version": "19.0.1.4.0",
    "category": "Technical",
    "author": "Polimex Dev Team",
    "website": "https://polimex.co",
    "license": "LGPL-3",
    "application": False,
    "installable": True,
    # Neutral shared infra: depends ONLY on core. Neither Access Control nor IoT
    # is referenced here - both domain modules depend on THIS one, never on each
    # other (two-independent-functions law).
    "depends": ["mail", "bus"],
    "data": [
        "security/ir.model.access.csv",
    ],
}
