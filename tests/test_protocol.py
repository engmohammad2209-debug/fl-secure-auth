import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import numpy as np  # noqa: E402

from fl_auth import attacks  # noqa: E402
from fl_auth.federated import (FLClient, FLServer, accuracy,  # noqa: E402
                               authenticate_all, load_data)
from fl_auth.protocol import Client, RegistrationAuthority, Server, handshake  # noqa: E402


class TestHandshake(unittest.TestCase):
    def setUp(self):
        self.ra = RegistrationAuthority()
        self.srv = Server("server", self.ra)
        self.cli = Client("client-1", self.ra)

    def test_both_sides_derive_same_keys(self):
        c, s = handshake(self.cli, self.srv)
        self.assertEqual(c.k_enc, s.k_enc)
        self.assertEqual(c.k_mac, s.k_mac)
        self.assertEqual(c.session_id, s.session_id)
        self.assertTrue(c.confirmed and s.confirmed)

    def test_fresh_keys_every_session(self):
        k1 = handshake(self.cli, self.srv)[0].k_enc
        k2 = handshake(self.cli, self.srv)[0].k_enc
        self.assertNotEqual(k1, k2)

    def test_enc_and_mac_keys_differ(self):
        c, _ = handshake(self.cli, self.srv)
        self.assertNotEqual(c.k_enc, c.k_mac)


class TestAttacks(unittest.TestCase):
    pass


def _make(fn):
    def test(self):
        blocked, detail = fn()
        self.assertTrue(blocked, detail)
    return test


for _name, _fn in attacks.ALL.items():
    setattr(TestAttacks, "test_" + _fn.__name__, _make(_fn))


class TestFederatedTraining(unittest.TestCase):
    def test_secure_training_learns(self):
        ra = RegistrationAuthority()
        srv = Server("server", ra)
        parts, (X_te, y_te) = load_data(4)
        clients = [FLClient(Client(f"c{i}", ra), p, seed=i) for i, p in enumerate(parts)]
        ids = authenticate_all(clients, srv)
        self.assertEqual(len(ids), 4)

        fl = FLServer(srv, X_te.shape[1], 10)
        for rnd in range(1, 4):
            blobs = fl.broadcast(ids, rnd)
            fl.aggregate([c.train(blobs[c.id], rnd) for c in clients], rnd)
        self.assertGreater(accuracy(fl.w, X_te, y_te), 0.85)

    def test_revoked_client_excluded(self):
        ra = RegistrationAuthority()
        srv = Server("server", ra)
        parts, _ = load_data(3)
        clients = [FLClient(Client(f"c{i}", ra), p) for i, p in enumerate(parts)]
        ra.revoke("c1")
        self.assertEqual(authenticate_all(clients, srv), ["c0", "c2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
