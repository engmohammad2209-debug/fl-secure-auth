"""Mutual authentication and key agreement (AKA) protocol for federated learning.

Entities
--------
RA      Registration Authority. Offline, trusted. Issues certificates.
Server  Aggregation server that coordinates training.
Client  Data owner (hospital, phone, IoT node) that trains locally.

Phases
------
1. Registration (once, secure channel):
   each entity generates a long-term ECC key pair; the RA signs
   cert = Sig_RA(ID || PK || expiry).

2. Authentication and key agreement (every training session):

   Client                                                Server
   x <- random, X = xG, N_C, T1
   sig_C = Sig_C(H("M1", ID_C, ID_S, X, N_C, T1))
                 M1 = {ID_C, cert_C, X, N_C, T1, sig_C}  -->
                                         check T1 fresh, N_C unseen
                                         verify cert_C, sig_C
                                         y <- random, Y = yG, N_S, T2
                                         Z  = ECDH(y, X)
                                         tr = H(M1, ID_S, Y, N_S, T2)
                                         K_enc || K_mac = HKDF(Z, N_C||N_S, tr)
                                         sig_S = Sig_S(H("M2", tr))
                                         tau_S = MAC(K_mac, "S" || tr)
             <--  M2 = {ID_S, cert_S, Y, N_S, T2, sig_S, tau_S}
   check T2 fresh, verify cert_S, sig_S
   Z = ECDH(x, Y), derive same keys, check tau_S
   tau_C = MAC(K_mac, "C" || tr)
                 M3 = {tau_C}                           -->
                                         check tau_C  => session established

Security properties (see tests/test_attacks.py)
  - Mutual authentication     (signatures under RA-certified keys)
  - Session key agreement     (ephemeral ECDH + HKDF)
  - Perfect forward secrecy   (x, y are discarded after the session)
  - Explicit key confirmation (tau_S, tau_C)
  - Replay resistance         (timestamps + nonce cache)
  - MITM resistance           (ephemeral keys are bound into signatures)
  - Revocation                (RA revocation list)
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from . import crypto_utils as cu

PROTOCOL_ID = b"FL-AKA-v1"
MAX_CLOCK_SKEW_MS = 5_000  # acceptable |now - T|


class AuthError(Exception):
    """Raised whenever a protocol check fails."""


# ------------------------------------------------------------ encoding
def encode(*fields: bytes | str | int) -> bytes:
    """Length-prefixed encoding, used for transcripts and size measurement."""
    out = bytearray()
    for f in fields:
        if isinstance(f, str):
            f = f.encode()
        elif isinstance(f, int):
            f = f.to_bytes(8, "big")
        out += len(f).to_bytes(2, "big") + f
    return bytes(out)


# --------------------------------------------------------- certificates
@dataclass(frozen=True)
class Certificate:
    identity: str
    public_key: bytes
    expiry_ms: int
    signature: bytes

    def body(self) -> bytes:
        return encode(b"CERT", self.identity, self.public_key, self.expiry_ms)

    def to_bytes(self) -> bytes:
        return self.body() + encode(self.signature)


class RegistrationAuthority:
    def __init__(self, validity_days: int = 365):
        self._key = cu.generate_keypair()
        self.public_key = self._key.public_key()
        self.validity_ms = validity_days * 24 * 3600 * 1000
        self.revoked: set[str] = set()

    def issue(self, identity: str, public_key: bytes) -> Certificate:
        expiry = cu.now_ms() + self.validity_ms
        unsigned = Certificate(identity, public_key, expiry, b"")
        return Certificate(identity, public_key, expiry, cu.sign(self._key, unsigned.body()))

    def revoke(self, identity: str) -> None:
        self.revoked.add(identity)

    def check(self, cert: Certificate) -> None:
        if not cu.verify(self.public_key, cert.signature, cert.body()):
            raise AuthError("certificate signature invalid")
        if cert.expiry_ms < cu.now_ms():
            raise AuthError("certificate expired")
        if cert.identity in self.revoked:
            raise AuthError("certificate revoked")


# ------------------------------------------------------------- messages
@dataclass(frozen=True)
class M1:
    id_c: str
    cert_c: Certificate
    X: bytes
    n_c: bytes
    t1: int
    sig_c: bytes

    def signed_part(self, id_s: str) -> bytes:
        return cu.h(b"M1", PROTOCOL_ID, self.id_c.encode(), id_s.encode(),
                    self.X, self.n_c, self.t1.to_bytes(8, "big"))

    def to_bytes(self) -> bytes:
        return encode(self.id_c, self.cert_c.to_bytes(), self.X, self.n_c, self.t1, self.sig_c)


@dataclass(frozen=True)
class M2:
    id_s: str
    cert_s: Certificate
    Y: bytes
    n_s: bytes
    t2: int
    sig_s: bytes
    tau_s: bytes

    def to_bytes(self) -> bytes:
        return encode(self.id_s, self.cert_s.to_bytes(), self.Y, self.n_s,
                      self.t2, self.sig_s, self.tau_s)


@dataclass(frozen=True)
class M3:
    tau_c: bytes

    def to_bytes(self) -> bytes:
        return encode(self.tau_c)


@dataclass
class Session:
    peer: str
    session_id: bytes
    k_enc: bytes
    k_mac: bytes
    confirmed: bool = False


def _transcript(m1: M1, id_s: str, Y: bytes, n_s: bytes, t2: int) -> bytes:
    return cu.h(b"TR", m1.to_bytes(), id_s.encode(), Y, n_s, t2.to_bytes(8, "big"))


def _derive(z: bytes, n_c: bytes, n_s: bytes, tr: bytes) -> tuple[bytes, bytes]:
    okm = cu.hkdf(z, salt=n_c + n_s, info=PROTOCOL_ID + tr)
    return okm[: cu.KEY_LEN], okm[cu.KEY_LEN:]


def _fresh(t: int) -> None:
    if abs(cu.now_ms() - t) > MAX_CLOCK_SKEW_MS:
        raise AuthError("stale or future timestamp")


# -------------------------------------------------------------- parties
class Party:
    def __init__(self, identity: str, ra: RegistrationAuthority):
        self.identity = identity
        self.ra = ra
        self._key = cu.generate_keypair()
        self.cert = ra.issue(identity, cu.pub_bytes(self._key.public_key()))


class Client(Party):
    def __init__(self, identity: str, ra: RegistrationAuthority):
        super().__init__(identity, ra)
        self._pending: dict | None = None
        self.session: Session | None = None

    def start(self, server_id: str) -> M1:
        x = cu.generate_keypair()
        unsigned = M1(self.identity, self.cert, cu.pub_bytes(x.public_key()),
                      cu.nonce(), cu.now_ms(), b"")
        m1 = replace(unsigned, sig_c=cu.sign(self._key, unsigned.signed_part(server_id)))
        self._pending = {"x": x, "m1": m1, "server_id": server_id}
        return m1

    def finish(self, m2: M2) -> M3:
        if self._pending is None:
            raise AuthError("no handshake in progress")
        p, self._pending = self._pending, None  # one shot: x is dropped after use

        if m2.id_s != p["server_id"] or m2.cert_s.identity != m2.id_s:
            raise AuthError("unexpected server identity")
        _fresh(m2.t2)
        self.ra.check(m2.cert_s)

        tr = _transcript(p["m1"], m2.id_s, m2.Y, m2.n_s, m2.t2)
        if not cu.verify(cu.load_pub(m2.cert_s.public_key), m2.sig_s, cu.h(b"M2", tr)):
            raise AuthError("server signature invalid")

        z = cu.ecdh(p["x"], cu.load_pub(m2.Y))
        k_enc, k_mac = _derive(z, p["m1"].n_c, m2.n_s, tr)
        if not cu.mac_ok(k_mac, b"S" + tr, m2.tau_s):
            raise AuthError("server key confirmation failed")

        self.session = Session(m2.id_s, tr[:16], k_enc, k_mac, confirmed=True)
        return M3(cu.mac(k_mac, b"C" + tr))


class Server(Party):
    def __init__(self, identity: str, ra: RegistrationAuthority):
        super().__init__(identity, ra)
        self._seen_nonces: set[bytes] = set()
        self._pending: dict[str, tuple[Session, bytes]] = {}
        self.sessions: dict[str, Session] = {}

    def respond(self, m1: M1) -> M2:
        _fresh(m1.t1)
        if m1.n_c in self._seen_nonces:
            raise AuthError("replayed nonce")
        if m1.cert_c.identity != m1.id_c:
            raise AuthError("identity does not match certificate")
        self.ra.check(m1.cert_c)
        if not cu.verify(cu.load_pub(m1.cert_c.public_key), m1.sig_c, m1.signed_part(self.identity)):
            raise AuthError("client signature invalid")
        self._seen_nonces.add(m1.n_c)

        y = cu.generate_keypair()
        Y, n_s, t2 = cu.pub_bytes(y.public_key()), cu.nonce(), cu.now_ms()
        tr = _transcript(m1, self.identity, Y, n_s, t2)
        z = cu.ecdh(y, cu.load_pub(m1.X))
        del y  # ephemeral secret discarded -> forward secrecy
        k_enc, k_mac = _derive(z, m1.n_c, n_s, tr)

        self._pending[m1.id_c] = (Session(m1.id_c, tr[:16], k_enc, k_mac), tr)
        return M2(self.identity, self.cert, Y, n_s, t2,
                  cu.sign(self._key, cu.h(b"M2", tr)), cu.mac(k_mac, b"S" + tr))

    def confirm(self, client_id: str, m3: M3) -> Session:
        if client_id not in self._pending:
            raise AuthError("no pending handshake for client")
        session, tr = self._pending.pop(client_id)
        if not cu.mac_ok(session.k_mac, b"C" + tr, m3.tau_c):
            raise AuthError("client key confirmation failed")
        session.confirmed = True
        self.sessions[client_id] = session
        return session


def handshake(client: Client, server: Server) -> tuple[Session, Session]:
    """Run the full three-message handshake in-process."""
    m1 = client.start(server.identity)
    m2 = server.respond(m1)
    m3 = client.finish(m2)
    s_session = server.confirm(client.identity, m3)
    return client.session, s_session
