"""Measure computation and communication cost of the protocol.

    python benchmark.py            # prints a Markdown table
    python benchmark.py --n 500    # more iterations
"""

import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import numpy as np  # noqa: E402

from fl_auth import crypto_utils as cu  # noqa: E402
from fl_auth.federated import UP, seal, to_bytes  # noqa: E402
from fl_auth.protocol import Client, RegistrationAuthority, Server  # noqa: E402


def timed(fn, n):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1000)
    return statistics.median(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    n = ap.parse_args().n

    ra = RegistrationAuthority()
    srv, cli = Server("aggregator", ra), Client("client-1", ra)

    t_client = t_server = 0.0
    sizes = None
    rows_c, rows_s = [], []
    for _ in range(n):
        t0 = time.perf_counter(); m1 = cli.start(srv.identity); t1 = time.perf_counter()
        m2 = srv.respond(m1); t2 = time.perf_counter()
        m3 = cli.finish(m2); t3 = time.perf_counter()
        srv.confirm(cli.identity, m3); t4 = time.perf_counter()
        rows_c.append(((t1 - t0) + (t3 - t2)) * 1000)
        rows_s.append(((t2 - t1) + (t4 - t3)) * 1000)
        sizes = (len(m1.to_bytes()), len(m2.to_bytes()), len(m3.to_bytes()))
    t_client, t_server = statistics.median(rows_c), statistics.median(rows_s)

    priv, pub = cu.generate_keypair(), cu.generate_keypair().public_key()
    data = b"x" * 64
    sig = cu.sign(priv, data)
    prim = {
        "ECDSA sign": timed(lambda: cu.sign(priv, data), n),
        "ECDSA verify": timed(lambda: cu.verify(priv.public_key(), sig, data), n),
        "ECDH": timed(lambda: cu.ecdh(priv, pub), n),
        "Key generation": timed(cu.generate_keypair, n),
        "HKDF": timed(lambda: cu.hkdf(b"s" * 32, b"n" * 32, b"i"), n),
        "SHA-256": timed(lambda: cu.h(data), n),
    }

    w = np.random.default_rng(0).normal(size=(65, 10))
    sess = cli.session
    plain = len(to_bytes(w))
    enc = len(seal(sess, w, 1, UP))
    t_seal = timed(lambda: seal(sess, w, 1, UP), n)

    print(f"Median of {n} runs, Python {sys.version.split()[0]}\n")
    print("| Primitive | Time (ms) |\n|---|---|")
    for k, v in prim.items():
        print(f"| {k} | {v:.3f} |")
    print("\n| Handshake | Value |\n|---|---|")
    print(f"| Client computation | {t_client:.2f} ms |")
    print(f"| Server computation | {t_server:.2f} ms |")
    print(f"| M1 / M2 / M3 size | {sizes[0]} / {sizes[1]} / {sizes[2]} bytes |")
    print(f"| Total communication | {sum(sizes)} bytes |")
    print("\n| Model update (65x10 float64) | Value |\n|---|---|")
    print(f"| Plaintext size | {plain} bytes |")
    print(f"| Encrypted size | {enc} bytes (+{enc - plain} bytes, {100 * (enc - plain) / plain:.1f}%) |")
    print(f"| Encryption time | {t_seal:.3f} ms |")


if __name__ == "__main__":
    main()
