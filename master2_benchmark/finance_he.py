"""Prototype scientifique : montants entiers FCFA, Cloud simulé sans clé secrète."""
from __future__ import annotations
import argparse, csv, json, platform, random, statistics, time, sys
from pathlib import Path

def dataset(n: int, seed: int) -> list[int]:
    rng = random.Random(seed)
    return [rng.randint(-5000, 15000) for _ in range(n)]

def paillier_sum(values: list[int], bits: int = 2048):
    from phe import paillier
    t = time.perf_counter()
    public, private = paillier.generate_paillier_keypair(n_length=bits)
    keygen = time.perf_counter() - t
    t = time.perf_counter()
    encrypted = [public.encrypt(v) for v in values]
    encryption = time.perf_counter() - t
    t = time.perf_counter()
    result = encrypted[0]
    for value in encrypted[1:]:
        result += value
    evaluation = time.perf_counter() - t
    t = time.perf_counter()
    decoded = private.decrypt(result)
    decryption = time.perf_counter() - t
    # Mesure du payload canonique minimal (entier modulo n²), hors métadonnées.
    cipher_bytes = sum((c.ciphertext(be_secure=False).bit_length() + 7) // 8 for c in encrypted)
    return dict(keygen_s=keygen, encryption_s=encryption, evaluation_s=evaluation,
                decryption_s=decryption, result=decoded, ciphertext_bytes=cipher_bytes,
                ciphertext_count=len(encrypted), parameter=f"paillier-{bits}")

def bfv_sum(values: list[int], degree: int = 8192, plain_modulus: int = 1032193):
    import numpy as np
    from Pyfhel import Pyfhel
    he = Pyfhel()
    t = time.perf_counter()
    he.contextGen(scheme="BFV", n=degree, t=plain_modulus, sec=128)
    he.keyGen()
    keygen = time.perf_counter() - t
    # Une transaction par ciphertext : benchmark comparable sans batching implicite.
    t = time.perf_counter()
    encrypted = [he.encryptInt(np.array([v], dtype=np.int64)) for v in values]
    encryption = time.perf_counter() - t
    t = time.perf_counter()
    result = encrypted[0].copy()
    for item in encrypted[1:]:
        result += item
    evaluation = time.perf_counter() - t
    t = time.perf_counter()
    decoded = int(he.decryptInt(result)[0])
    decryption = time.perf_counter() - t
    size = sum(len(c.to_bytes()) for c in encrypted)
    return dict(keygen_s=keygen, encryption_s=encryption, evaluation_s=evaluation,
                decryption_s=decryption, result=decoded, ciphertext_bytes=size,
                ciphertext_count=len(encrypted), parameter=f"bfv-n{degree}-t{plain_modulus}")

def bfv_polynomial(x: int, y: int, degree: int = 8192, plain_modulus: int = 1032193):
    """f(x,y)=x*y+2*x+3*y+7 ; une multiplication ciphertext×ciphertext."""
    import numpy as np
    from Pyfhel import Pyfhel
    he = Pyfhel()
    t = time.perf_counter()
    he.contextGen(scheme="BFV", n=degree, t=plain_modulus, sec=128)
    he.keyGen()
    he.relinKeyGen()
    keygen = time.perf_counter() - t
    t = time.perf_counter()
    cx = he.encryptInt(np.array([x], dtype=np.int64))
    cy = he.encryptInt(np.array([y], dtype=np.int64))
    encryption = time.perf_counter() - t
    t = time.perf_counter()
    product = cx * cy
    product = ~(product)
    output = product + (cx * 2) + (cy * 3) + 7
    evaluation = time.perf_counter() - t
    t = time.perf_counter()
    decoded = int(he.decryptInt(output)[0])
    decryption = time.perf_counter() - t
    return dict(keygen_s=keygen, encryption_s=encryption, evaluation_s=evaluation,
                decryption_s=decryption, result=decoded,
                ciphertext_bytes=len(cx.to_bytes())+len(cy.to_bytes()),
                ciphertext_count=2, parameter=f"bfv-poly-n{degree}-t{plain_modulus}")

def run(sizes, repetitions, seed, schemes, bits, degree, modulus, output):
    import psutil
    process = psutil.Process()
    rows = []
    for n in sizes:
        if n < 1: raise ValueError("N doit être positif")
        values = dataset(n, seed)
        expected = sum(values)
        if abs(expected) >= modulus // 2 and "bfv" in schemes:
            raise ValueError(f"Somme {expected} hors de la plage signée BFV pour t={modulus}; augmenter t ou limiter N/montants")
        for repetition in range(repetitions):
            for scheme in schemes:
                before = process.memory_info().rss
                if scheme == "plain":
                    t = time.perf_counter()
                    result = sum(values)
                    elapsed = time.perf_counter() - t
                    measure = dict(keygen_s=0., encryption_s=0., evaluation_s=elapsed,
                                   decryption_s=0., result=result, ciphertext_bytes=0,
                                   ciphertext_count=0, parameter="plain")
                elif scheme == "paillier":
                    measure = paillier_sum(values, bits)
                else:
                    measure = bfv_sum(values, degree, modulus)
                after = process.memory_info().rss
                correct = measure.pop("result") == expected
                row = dict(scenario="sum", scheme=scheme, n=n, repetition=repetition,
                           seed=seed, correct=correct, rss_before_bytes=before,
                           rss_after_bytes=after, **measure)
                rows.append(row)
                print(json.dumps(row, ensure_ascii=False), flush=True)
                if not correct: raise AssertionError(f"Résultat incorrect: {row}")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV enregistré : {output}")

def main():
    p = argparse.ArgumentParser(description="Benchmark Paillier / BFV / clair sur montants synthétiques entiers")
    p.add_argument("--sizes", type=int, nargs="+", default=[10,100,1000,10000])
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--seed", type=int, default=20261008)
    p.add_argument("--schemes", nargs="+", choices=["plain","paillier","bfv"], default=["plain","paillier","bfv"])
    p.add_argument("--paillier-bits", type=int, default=2048)
    p.add_argument("--bfv-degree", type=int, default=8192)
    p.add_argument("--bfv-t", type=int, default=1032193)
    p.add_argument("--output", default="results/benchmarks.csv")
    p.add_argument("--polynomial", action="store_true")
    args = p.parse_args()
    if args.repetitions < 1: p.error("repetitions doit être positif")
    if args.polynomial:
        result = bfv_polynomial(12, 7, args.bfv_degree, args.bfv_t)
        assert result["result"] == 12*7 + 2*12 + 3*7 + 7
        print(json.dumps(result, indent=2))
    else:
        run(args.sizes,args.repetitions,args.seed,args.schemes,args.paillier_bits,args.bfv_degree,args.bfv_t,args.output)

if __name__ == "__main__":
    main()
