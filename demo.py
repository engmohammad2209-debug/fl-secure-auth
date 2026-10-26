"""End-to-end demo: registration -> authentication -> secure federated training -> attacks.

    python demo.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from fl_auth import attacks  # noqa: E402
from fl_auth.federated import (FLClient, FLServer, Update, accuracy,  # noqa: E402
                               authenticate_all, load_data)
from fl_auth.protocol import Client, RegistrationAuthority, Server  # noqa: E402

N_CLIENTS, ROUNDS = 5, 8


def title(t):
    print(f"\n{'=' * 64}\n {t}\n{'=' * 64}")


def main():
    title("1. Registration")
    ra = RegistrationAuthority()
    server = Server("aggregator", ra)
    parts, (X_te, y_te) = load_data(N_CLIENTS)
    clients = [FLClient(Client(f"hospital-{i + 1}", ra), p, seed=i) for i, p in enumerate(parts)]
    print(f"RA issued certificates to the server and {N_CLIENTS} clients")
    ra.revoke("hospital-5")
    print("RA revoked hospital-5 (simulating a compromised node)")

    title("2. Mutual authentication and key agreement")
    ok = authenticate_all(clients, server)
    for c in clients:
        if c.id in ok:
            print(f"  {c.id:<12} authenticated, session {c.c.session.session_id.hex()[:12]}...")
        else:
            print(f"  {c.id:<12} REJECTED")
    active = [c for c in clients if c.id in ok]

    title("3. Secure federated training (FedAvg, AES-256-GCM updates)")
    fl = FLServer(server, X_te.shape[1], 10)
    intruder = Update("intruder", 0, 500, b"\x00" * 128)
    for rnd in range(1, ROUNDS + 1):
        blobs = fl.broadcast(ok, rnd)
        updates = [c.train(blobs[c.id], rnd) for c in active]
        if rnd == 3:
            updates.append(Update("intruder", rnd, 500, intruder.ciphertext))
        n = fl.aggregate(updates, rnd)
        print(f"  round {rnd}: {n} updates aggregated, test accuracy = {accuracy(fl.w, X_te, y_te):.3f}")
    for line in fl.log:
        print(f"  [server] {line}")

    title("4. Attack simulation")
    blocked = 0
    for name, fn in attacks.ALL.items():
        ok_, detail = fn()
        blocked += ok_
        print(f"  {'BLOCKED' if ok_ else 'FAILED '}  {name:<40} ({detail})")
    print(f"\n  {blocked}/{len(attacks.ALL)} attacks blocked")


if __name__ == "__main__":
    main()
