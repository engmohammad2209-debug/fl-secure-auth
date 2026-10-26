"""Attack scenarios against the protocol and the secured FL channel.

Each scenario returns (blocked: bool, detail: str). They are used by both
the test-suite and the demo so the security claims are executable.
"""

from __future__ import annotations

from dataclasses import replace
from unittest import mock

import numpy as np

from . import crypto_utils as cu
from .federated import UP, FLServer, Update, seal
from .protocol import AuthError, Client, RegistrationAuthority, Server, handshake


def _setup():
    ra = RegistrationAuthority()
    return ra, Server("server", ra), Client("client-1", ra)


def _expect_auth_error(fn) -> tuple[bool, str]:
    try:
        fn()
    except AuthError as e:
        return True, str(e)
    return False, "attack succeeded"


def replay_m1():
    ra, srv, cli = _setup()
    m1 = cli.start(srv.identity)
    srv.respond(m1)
    return _expect_auth_error(lambda: srv.respond(m1))


def stale_timestamp():
    ra, srv, cli = _setup()
    m1 = cli.start(srv.identity)
    with mock.patch.object(cu, "now_ms", return_value=m1.t1 + 60_000):
        return _expect_auth_error(lambda: srv.respond(m1))


def mitm_swap_client_ephemeral():
    ra, srv, cli = _setup()
    m1 = cli.start(srv.identity)
    evil = cu.pub_bytes(cu.generate_keypair().public_key())
    return _expect_auth_error(lambda: srv.respond(replace(m1, X=evil)))


def mitm_swap_server_ephemeral():
    ra, srv, cli = _setup()
    m2 = srv.respond(cli.start(srv.identity))
    evil = cu.pub_bytes(cu.generate_keypair().public_key())
    return _expect_auth_error(lambda: cli.finish(replace(m2, Y=evil)))


def forged_certificate():
    ra, srv, _ = _setup()
    rogue_ra = RegistrationAuthority()
    attacker = Client("client-1", rogue_ra)  # same ID, cert from untrusted RA
    attacker.ra = ra
    return _expect_auth_error(lambda: srv.respond(attacker.start(srv.identity)))


def stolen_certificate():
    ra, srv, victim = _setup()
    attacker = Client("attacker", ra)
    m1 = attacker.start(srv.identity)
    # present the victim's certificate but sign with the attacker's own key
    forged = replace(m1, id_c=victim.identity, cert_c=victim.cert)
    return _expect_auth_error(lambda: srv.respond(forged))


def revoked_client():
    ra, srv, cli = _setup()
    ra.revoke(cli.identity)
    return _expect_auth_error(lambda: srv.respond(cli.start(srv.identity)))


def rogue_server():
    ra, _, cli = _setup()
    rogue = Server("server", RegistrationAuthority())
    rogue.ra = ra  # it accepts the client, but cannot prove itself
    return _expect_auth_error(lambda: cli.finish(rogue.respond(cli.start("server"))))


def message_redirection():
    """M1 meant for server A is forwarded to server B."""
    ra = RegistrationAuthority()
    cli, a, b = Client("client-1", ra), Server("server-A", ra), Server("server-B", ra)
    m1 = cli.start(a.identity)
    return _expect_auth_error(lambda: b.respond(m1))


def bad_key_confirmation():
    ra, srv, cli = _setup()
    srv.respond(cli.start(srv.identity))
    from .protocol import M3
    return _expect_auth_error(lambda: srv.confirm(cli.identity, M3(b"\x00" * 32)))


def _fl_setup():
    ra, srv, cli = _setup()
    handshake(cli, srv)
    fl = FLServer(srv, 3, 2)
    return cli, fl


def tampered_update():
    cli, fl = _fl_setup()
    blob = bytearray(seal(cli.session, np.ones((3, 2)), 1, UP))
    blob[-5] ^= 0xFF
    accepted = fl.aggregate([Update(cli.identity, 1, 10, bytes(blob))], 1)
    return accepted == 0, fl.log[-1] if fl.log else "accepted"


def replayed_update():
    cli, fl = _fl_setup()
    old = seal(cli.session, np.ones((3, 2)), 1, UP)  # captured in round 1
    accepted = fl.aggregate([Update(cli.identity, 2, 10, old)], 2)
    return accepted == 0, fl.log[-1] if fl.log else "accepted"


def unauthenticated_update():
    ra, srv, _ = _setup()
    fl = FLServer(srv, 3, 2)
    fake = Update("intruder", 1, 10, b"\x00" * 64)
    accepted = fl.aggregate([fake], 1)
    return accepted == 0, fl.log[-1] if fl.log else "accepted"


ALL = {
    "Replay of M1": replay_m1,
    "Stale timestamp": stale_timestamp,
    "MITM: replace client ephemeral key": mitm_swap_client_ephemeral,
    "MITM: replace server ephemeral key": mitm_swap_server_ephemeral,
    "Certificate from untrusted RA": forged_certificate,
    "Impersonation with stolen certificate": stolen_certificate,
    "Revoked client": revoked_client,
    "Rogue aggregation server": rogue_server,
    "Redirect M1 to another server": message_redirection,
    "Forged key confirmation (M3)": bad_key_confirmation,
    "Tampered model update": tampered_update,
    "Replay of old model update": replayed_update,
    "Update from unauthenticated node": unauthenticated_update,
}
