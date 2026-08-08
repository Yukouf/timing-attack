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
