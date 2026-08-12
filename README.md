# 🕐 Timing Attack — Devine un mot de passe avec un chronomètre

**Démonstration d'attaque par canal auxiliaire (side-channel attack).**

## L'analogie du coffre-fort

Imagine un coffre à combinaison. Normalement, pour un code à 4 chiffres, tu dois tester jusqu'à 10 000 combinaisons.

Mais imagine que ce coffre a un défaut : chaque fois que tu tournes le **bon** chiffre, le mécanisme fait un "clic" un tout petit peu plus long. Imperceptible à l'oreille, mais mesurable avec un bon micro.

Résultat : au lieu de 10 000 essais, il t'en faut **40** (10 par chiffre). Tu viens de casser le coffre avec un chronomètre.

## Comment ça marche

Beaucoup de fonctions de comparaison de mots de passe ressemblent à ça :

```python
def check_password(guess, real):
    for i in range(len(real)):
        if guess[i] != real[i]:
            return False  # ← Sortie immédiate
    return True
```

Problème : plus le nombre de caractères corrects est élevé, plus la fonction met de temps à répondre. Cette différence (quelques microsecondes) suffit à deviner le mot de passe **caractère par caractère**.

```
Mot de passe : "secret"

Essai "s00000" → compare 's'='s' ✓, '0'='e' ✗ → 2 comparaisons → ~2 µs
Essai "a00000" → compare 'a'='s' ✗ → 1 comparaison    → ~1 µs
                                         ↑
                              "s" est plus long → c'est le bon !
```

## Démo

![Démo](https://raw.githubusercontent.com/Yukouf/timing-attack/main/screenshot.png)

```bash
python3 timing-attack.py
```

```
🎯 CIBLE : kxqtwp  (longueur 6)

  Position 1: ✅ k  [█░░░░░]  3.42 µs
  Position 2: ✅ x  [██░░░░]  3.51 µs
  Position 3: ✅ q  [███░░░]  3.63 µs
  Position 4: ✅ t  [████░░]  3.74 µs
  Position 5: ✅ w  [█████░]  3.85 µs
  Position 6: ✅ p  [██████]  3.96 µs

✅ TROUVÉ: kxqtwp
```

## La limite du canal temporel (et la sentinelle)

> **Point d'honnêteté pédagogique.** Dans la comparaison "classique"
> (`for … if requète[…] != … return False`), le **dernier caractère** est
> ambigu : un candidat faux qui diverge au dernier octet exécute *autant* de
> comparaisons que le bon caractère. Les temps sont identiques → impossible,
> sans tricherie, de distinguer la bonne dernière lettre *uniquement* par le
> timing. Beaucoup de démos trichent en ré-utilisant le secret pour trancher
> ce dernier caractère (un oracle d'égalité caché) — cette version ne le fait
> pas.

Pour rendre la démo complète **sans ré-utiliser le secret dans l'attaque**, la
cible simulée `check_password()` matérialise une **terminaison sentinelle** :
un vrai serveur, quand le mot de passe est entièrement correct, effectue un
traitement d'après-authentification (session, HMAC, requête en base…) qui coûte
du temps. Ce coût est simulé par un délai supplémentaire à la toute fin. La
sentinelle fait qu'un *match complet* est mesurablement plus long qu'une
divergence au dernier octet → **la fuite du dernier caractère redevient réelle
et reproductible**, toujours sans accès direct au secret depuis l'attaque.

L'attaque ne consulte *jamais* le secret : tout ne passe que par le temps de
réponse de la cible, sentinelle comprise.

## Pourquoi c'est important

- Cette attaque fonctionne sur les **comparaisons de tokens API**, de **signatures HMAC**, de **mots de passe**
- La parade standard : `hmac.compare_digest()` — comparaison en **temps constant**
- En 2026, ça reste une des vulnérabilités les plus sous-estimées

## Utilisation

```bash
# Démo automatique
python3 timing-attack.py --demo

# Attaquer un mot de passe spécifique
python3 timing-attack.py "mon_mot_de_passe"
```

Code de retour : `0` succès (mot de passe retrouvé), `1` échec (caractère hors
du jeu attaqué), `2` mauvaise utilisation.

Variables d'environnement :
```bash
export TIMING_SLEEP=0.01    # délai artificiel par comparaison (défaut 0.01 s)
export TIMING_CHARSET=abcdefghijklmnopqrstuvwxyz0123456789  # jeu attaqué
```

## Parade

```python
# ❌ Vulnérable
if user_input == secret:
    ...

# ✅ Temps constant
import hmac
if hmac.compare_digest(user_input, secret):
    ...
```

## Licence

MIT
