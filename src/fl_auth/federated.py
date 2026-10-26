"""Federated learning simulation secured by the AKA protocol.

Model:   multinomial logistic regression (NumPy, no deep-learning framework).
Data:    scikit-learn handwritten digits (8x8 images, 10 classes), bundled
         with scikit-learn so nothing has to be downloaded.
Rounds:  FedAvg. Every model update travels encrypted with AES-256-GCM under
         the session key from the handshake. The associated data binds each
         ciphertext to the session, the round and the direction, so updates
         cannot be replayed into another round or reflected back.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import numpy as np
from cryptography.exceptions import InvalidTag
from sklearn.datasets import load_digits
from sklearn.model_selection import train_test_split

from . import crypto_utils as cu
from .protocol import AuthError, Client, Server, Session


# ---------------------------------------------------------------- model
def softmax(z: np.ndarray) -> np.ndarray:
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def accuracy(w: np.ndarray, X: np.ndarray, y: np.ndarray) -> float:
    return float((np.argmax(X @ w, axis=1) == y).mean())


def local_train(w, X, y, epochs=5, lr=0.5, batch=32, rng=None):
    rng = rng or np.random.default_rng()
    w = w.copy()
    Y = np.eye(w.shape[1])[y]
    for _ in range(epochs):
        idx = rng.permutation(len(X))
        for i in range(0, len(X), batch):
            b = idx[i:i + batch]
            grad = X[b].T @ (softmax(X[b] @ w) - Y[b]) / len(b)
            w -= lr * grad
    return w


def to_bytes(w: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.save(buf, w, allow_pickle=False)
    return buf.getvalue()


def from_bytes(b: bytes) -> np.ndarray:
    return np.load(io.BytesIO(b), allow_pickle=False)


def load_data(n_clients: int, seed: int = 0):
    X, y = load_digits(return_X_y=True)
    X = X / 16.0
    X = np.hstack([X, np.ones((len(X), 1))])  # bias column
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=seed, stratify=y)
    parts = np.array_split(np.random.default_rng(seed).permutation(len(X_tr)), n_clients)
    return [(X_tr[p], y_tr[p]) for p in parts], (X_te, y_te)


# ------------------------------------------------------- secure channel
def _aad(session: Session, rnd: int, direction: bytes) -> bytes:
    return session.session_id + rnd.to_bytes(4, "big") + direction


def seal(session: Session, w: np.ndarray, rnd: int, direction: bytes) -> bytes:
    return cu.aead_encrypt(session.k_enc, to_bytes(w), _aad(session, rnd, direction))


def open_(session: Session, blob: bytes, rnd: int, direction: bytes) -> np.ndarray:
    return from_bytes(cu.aead_decrypt(session.k_enc, blob, _aad(session, rnd, direction)))


DOWN, UP = b"S->C", b"C->S"


# ------------------------------------------------------------- training
@dataclass
class Update:
    client_id: str
    round: int
    n_samples: int
    ciphertext: bytes


class FLClient:
    def __init__(self, client: Client, data, seed: int = 0):
        self.c = client
        self.X, self.y = data
        self.rng = np.random.default_rng(seed)

    @property
    def id(self) -> str:
        return self.c.identity

    def train(self, global_blob: bytes, rnd: int) -> Update:
        w = open_(self.c.session, global_blob, rnd, DOWN)
        w_new = local_train(w, self.X, self.y, rng=self.rng)
        return Update(self.id, rnd, len(self.X), seal(self.c.session, w_new, rnd, UP))


class FLServer:
    def __init__(self, server: Server, n_features: int, n_classes: int):
        self.s = server
        self.w = np.zeros((n_features, n_classes))
        self.log: list[str] = []

    def broadcast(self, client_ids, rnd: int) -> dict[str, bytes]:
        out = {}
        for cid in client_ids:
            sess = self.s.sessions.get(cid)
            if sess is None or not sess.confirmed:
                self.log.append(f"round {rnd}: {cid} skipped (not authenticated)")
                continue
            out[cid] = seal(sess, self.w, rnd, DOWN)
        return out

    def aggregate(self, updates: list[Update], rnd: int) -> int:
        accepted, total = [], 0
        for u in updates:
            sess = self.s.sessions.get(u.client_id)
            if sess is None:
                self.log.append(f"round {rnd}: rejected update from {u.client_id} (no session)")
                continue
            try:
                w = open_(sess, u.ciphertext, rnd, UP)
            except InvalidTag:
                self.log.append(f"round {rnd}: rejected update from {u.client_id} (integrity check failed)")
                continue
            if u.round != rnd or w.shape != self.w.shape or not np.isfinite(w).all():
                self.log.append(f"round {rnd}: rejected update from {u.client_id} (malformed)")
                continue
            accepted.append((w, u.n_samples))
            total += u.n_samples
        if accepted:
            self.w = sum(w * n for w, n in accepted) / total
        return len(accepted)


def authenticate_all(clients: list[FLClient], server: Server) -> list[str]:
    """Run the handshake for each client; return the IDs that succeeded."""
    ok = []
    for fc in clients:
        try:
            m1 = fc.c.start(server.identity)
            m2 = server.respond(m1)
            m3 = fc.c.finish(m2)
            server.confirm(fc.id, m3)
            ok.append(fc.id)
        except AuthError:
            pass
    return ok
