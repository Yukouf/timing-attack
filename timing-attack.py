#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""timing-attack.py — Démonstration d'une attaque par canal temporel.

Principe : comparer 2 chaînes caractère par caractère (et s'arrêter à la
première divergence) prend un peu plus de temps quand les caractères testés
sont CORRECTS. En chronométrant les réponses d'une fonction vulnérable, on
devine le mot de passe caractère par caractère.

Usage :
  python3 timing-attack.py --demo    # Démo automatique (recommandé)
  python3 timing-attack.py "secret"  # Attaquer un mot de passe précis

Code de retour :
  0  succès (mot de passe entièrement retrouvé)
  1  échec (le mot de passe n'a pas pu être retrouvé)
  2  mauvaise utilisation de la ligne de commande

LIMITE HONNÊTE DU CANAL TEMPOREL (pourquoi la dernière lettre est spéciale) :
  Dans la version "classique" de check_password(), la comparaison s'arrête à
  la première divergence. Conséquence : à la dernière position, un candidat
  faux qui diverge au tout dernier octet exécute exactement AUTANT de
  comparaisons que le bon caractère (qui, lui, fait tourner la boucle
  entière). Les temps sont identiques → le canal temporel est AMBIGU sur le
  dernier caractère. Beaucoup de démos trichent en ré-utilisant le secret pour
  trancher ce dernier caractère (un "oracle" caché) — c'est malhonnête.

  Pour rester pédagogiquement fidèle, la cible simulée ci-dessous matérialise
  une TERMINAISON SENTINELLE : un vrai serveur, quand le mot de passe est
  entièrement correct, effectue un traitement supplémentaire (entrée en base,
  comparaison HMAC, exécution de la session…) qui coûte du temps. On simule
  ce coût par un délai supplémentaire à la toute fin. Cette sentinelle fait
  qu'un match complet EST mesurablement plus long qu'une divergence au dernier
  octet → la fuite du dernier caractère devient réelle et reproductible, sans
  aucun accès direct au secret. Le timing retrouve donc les `len` caractères.

  En résumé : on ne consulte JAMAIS `secret` depuis la fonction d'attaque ;
  tout ne passe que par le temps de réponse de la cible, sentinelle comprise.

Variables d'environnement (utiles aux tests / réglage fin) :
  TIMING_SLEEP   délai artificiel par comparaison (défaut 0.01 s)
  TIMING_CHARSET jeu de caractères attaqué (défaut a-z0-9)
"""

import os
import sys
import time
import string
import secrets

# ── Paramètres (surchargeables par environnement pour les tests) ────────────
SLEEP_PER_CHAR = float(os.environ.get("TIMING_SLEEP", "0.01"))
CHARSET = os.environ.get("TIMING_CHARSET", string.ascii_lowercase + string.digits)


# ── La cible : une fonction de comparaison vulnérable ───────────────────────

def check_password(guess, secret):
    """Compare `guess` et `secret` OCTET par OCTET, délai simulant le temps réel.

    SIMULATION d'un serveur réel : chaque comparaison coûte SLEEP_PER_CHAR
    secondes (hachage / comparaison non-constante).

    TERMINAISON SENTINELLE : quand la boucle se termine SANS divergence (le
    mot de passe est entièrement correct), le serveur effectue le traitement
    d'après-authentification (session, HMAC…) qui coûte aussi du temps. Ce
    délai supplémentaire est ce qui rend le DERNIER caractère mesurable — sans
    recourir à un oracle d'égalité caché dans la fonction d'attaque. Le temps
    total de réponse est alors `len + 1` unités contre `len` pour tout candidat
    qui diverge au dernier octet.
    """
    if len(guess) != len(secret):
        return False
    for g, s in zip(guess, secret):
        time.sleep(SLEEP_PER_CHAR)  # ← coût réaliste par comparaison
        if g != s:
            return False
    # ── Terminaison sentinelle : seulement si guess == secret ──────────────
    if guess == secret:
        time.sleep(SLEEP_PER_CHAR)  # ← traitement post-auth, mesurable
    return True


def matched_count(guess, secret):
    """Nombre d'unités temporelles consommées par check_password().

    Correspond EXACTEMENT à la durée mesurée par measure() : on compte les
    comparaisons de la boucle, plus l'unité supplémentaire de la sentinelle
    quand `guess == secret`.
    """
    if len(guess) != len(secret):
        return 0
    for i, (g, s) in enumerate(zip(guess, secret)):
        if g != s:
            return i + 1          # divergence → s'arrête ici
    return len(guess) + 1         # boucle complète + terminaison sentinelle


# ── L'attaque ───────────────────────────────────────────────────────────────

def measure(guess, secret, rounds):
    """Mesure le temps moyen de check_password() sur `rounds` essais."""
    start = time.perf_counter()
    for _ in range(rounds):
        check_password(guess, secret)
    elapsed = time.perf_counter() - start
    return elapsed / rounds


def crack_char(known_prefix, secret, rounds=3):
    """Devine le bon caractère à la position len(known_prefix) par timing.

    Le bon caractère produit une unité de comparaison de plus que les mauvais
    → son temps moyen est strictement supérieur, quel que soit le caractère
    (les premiers par divergences, le dernier grâce à la sentinelle).
    """
    pos = len(known_prefix)
    best_char = None
    best_time = -1.0
    for c in CHARSET:
        guess = known_prefix + c + "0" * (len(secret) - pos - 1)
        t = measure(guess, secret, rounds)
        if t > best_time:
            best_time = t
            best_char = c
    return best_char, best_time


def crack(secret, rounds=1):
    """Devine le mot de passe complet. Retourne (mot_de_passe, succes: bool).

    Tous les caractères, y compris le dernier, sont déduits du TEMPS de
    réponse de la cible (la sentinelle rend le dernier mesurable). On ne
    compare jamais `guess` au `secret` depuis cette fonction.

    Fiabilité : à chaque position le bon candidat consomme UNE unité de plus
    (différence = rounds * SLEEP_PER_CHAR). Avec le délai par défaut de 10 ms,
    la différence est ~10 ms, très au-dessus du bruit de mesure.
    """
    known = ""
    print(f"\n🎯 CIBLE : {secret}  (longueur {len(secret)})\n")

    for pos in range(len(secret)):
        c, t = crack_char(known, secret, rounds)
        known += str(c)
        bar = "█" * (pos + 1) + "░" * (len(secret) - pos - 1)
        match = "✅" if c == secret[pos] else "❌"
        print(f"  Position {pos+1}: {match} {c}  [{bar}]  {t*1e6:.1f} µs")

    ok = (known == secret)
    print(f"\n{'✅ TROUVÉ' if ok else '❌ ÉCHEC'}: {known}")
    return known, ok


# ── Démo ───────────────────────────────────────────────────────────────────

def demo():
    print("═" * 55)
    print("🕐 TIMING ATTACK — démonstration d'une attaque par canal auxiliaire")
    print("═" * 55)
    print()
    print("  check_password() compare octet par octet et s'arrête à la")
    print("  première divergence. Plus la comparaison va loin, plus c'est long.")
    print("  → On mesure le temps pour chaque caractère, sentinelle comprise.")
    print(f"  → Le bon caractère prend ~{SLEEP_PER_CHAR*1e6:.0f} µs de plus.")
    print()

    secret = "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
    print(f"🔐 Mot de passe cible : {secret}")
    print()

    # Démonstration de la fuite (mesure bornée pour ne pas durer indéfiniment)
    print("📏 Preuve de la fuite temporelle :")
    rounds = 25
    for i in range(len(secret)):
        correct = secret[:i + 1] + "0" * (len(secret) - i - 1)
        wrong = "x" * (i + 1) + "0" * (len(secret) - i - 1)
        t_correct = measure(correct, secret, rounds) * 1e6
        t_wrong = measure(wrong, secret, rounds) * 1e6
        print(f"  Pos {i+1} correcte : {t_correct:6.1f} µs | fausse : {t_wrong:6.1f} µs")
    print()

    # Attaque
    print("⚔️  Attaque en cours...")
    _, ok = crack(secret)
    return ok


def main():
    # --demo : démo automatique ; sinon un mot de passe à attaquer
    if "--demo" in sys.argv or len(sys.argv) == 1:
        ok = demo()
        sys.exit(0 if ok else 1)

    if len(sys.argv) == 2:
        secret = sys.argv[1]
        _, ok = crack(secret)
        sys.exit(0 if ok else 1)

    print("Usage: python3 timing-attack.py [--demo] [mot_de_passe]")
    sys.exit(2)


if __name__ == "__main__":
    main()
