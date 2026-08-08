#!/usr/bin/env python3
"""
🕐 Timing Attack — Devine un mot de passe chronomètre en main

Démonstration d'attaque par canal auxiliaire (side-channel).
Principe : comparer 2 chaînes caractère par caractère prend
un peu plus de temps quand le caractère est CORRECT.

Usage :
  python3 timing-attack.py           # Démo interactive
  python3 timing-attack.py --demo    # Démo automatique
"""

import time
import sys
import string
import secrets

# ── La cible : une fonction de comparaison vulnérable ─────

def check_password(guess, secret):
    """
    Compare `guess` et `secret` OCTET par OCTET.
    Dès qu'un octet diffère → retourne False.
    
    SIMULATION : délai artificiel de 10ms par caractère comparé,
    comme un vrai serveur qui hache/compare en temps non-constant.
    """
    if len(guess) != len(secret):
        return False
    for i, (g, s) in enumerate(zip(guess, secret)):
        time.sleep(0.01)  # ← Simule le temps de traitement par caractère
        if g != s:
            return False
    return True


# ── L'attaque ─────────────────────────────────────────────

def measure(guess, secret, rounds=100):
    """Mesure le temps moyen de check_password()."""
    start = time.perf_counter()
    for _ in range(rounds):
        check_password(guess, secret)
    elapsed = time.perf_counter() - start
    return elapsed / rounds


def crack_char(known_prefix, secret, rounds=1):
    """Trouve le prochain caractère par timing (1 seul essai, délai 10ms/car)."""
    charset = string.ascii_lowercase + string.digits
    best_char = "?"
    best_time = 0
    times = {}

    for c in charset:
        guess = known_prefix + c + "0" * (len(secret) - len(known_prefix) - 1)
        t = measure(guess, secret, rounds)
        times[c] = t
        if t > best_time:
            best_time = t
            best_char = c

    return best_char, best_time


def crack(secret):
    """Devine le mot de passe complet caractère par caractère."""
    known = ""
    print(f"\n🎯 CIBLE : {secret}  (longueur {len(secret)})\n")

    for pos in range(len(secret)):
        c, t = crack_char(known, secret, rounds=1)
        known += c
        bar = "█" * (pos + 1) + "░" * (len(secret) - pos - 1)
        match = "✅" if c == secret[pos] else "❌"
        print(f"  Position {pos+1}: {match} {c}  [{bar}]  {t*1e6:.1f} µs")

    print(f"\n{'✅ TROUVÉ' if known == secret else '❌ ÉCHEC'}: {known}")
    return known


# ── Démo ──────────────────────────────────────────────────

def demo():
    print("═" * 55)
    print("  🕐 TIMING ATTACK — Démonstration")
    print("═" * 55)
    print()
    print("Principe :")
    print("  check_password() compare octet par octet.")
    print("  Plus la comparaison va loin, plus c'est long.")
    print("  → On mesure le temps pour chaque caractère.")
    print("  → Le bon caractère prend ~10-50 µs de plus.")
    print()

    # Test avec un mot de passe aléatoire
    secret = "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
    print(f"🔐 Mot de passe cible : {secret}")
    print()

    # Démonstration de la fuite
    print("📏 Preuve de la fuite temporelle :")
    for i in range(len(secret)):
        correct = secret[:i+1] + "0" * (len(secret) - i - 1)
        wrong   = "x" * (i+1) + "0" * (len(secret) - i - 1)
        t_correct = measure(correct, secret, 500) * 1e6
        t_wrong   = measure(wrong,   secret, 500) * 1e6
        diff = t_correct - t_wrong
        print(f"  Pos {i+1} correcte : {t_correct:.1f} µs  |  fausse : {t_wrong:.1f} µs  |  Δ = {diff:+.1f} µs")
    print()

    # Attaque
    print("⚔️  Attaque en cours...")
    crack(secret)


if __name__ == "__main__":
    if "--demo" in sys.argv or len(sys.argv) == 1:
        demo()
    elif len(sys.argv) == 2:
        crack(sys.argv[1])
    else:
        print("Usage: python3 timing-attack.py [--demo] [mot_de_passe]")
