# Benchmark scientifique Paillier–BFV (Master 2)

Prototype indépendant du reste du dépôt : **calcul en clair / Paillier / BFV**, transactions financières fictives en entiers FCFA, CSV de résultats et tests de correction.

## Installation locale (Ubuntu 24.04 recommandé)

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential cmake
cd master2_benchmark
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Pyfhel peut nécessiter une compilation native et des outils supplémentaires. Vérifier la version Python et les instructions officielles de Pyfhel en cas d'erreur.

## Validation

```bash
pytest -q
python finance_he.py --sizes 10 100 --repetitions 2
python finance_he.py --polynomial
```

## Campagne de montée en charge

**Attention** : BFV avec un ciphertext par transaction est coûteux. Tester les petites tailles d'abord.

```bash
python finance_he.py --sizes 10 100 1000 --repetitions 5
python finance_he.py --sizes 10000 --repetitions 3 --schemes plain paillier
```

Pour BFV à 10 000 transactions, la somme maximale des valeurs doit être représentable dans l'espace signé modulo t. Le script refuse un cas où la somme de référence dépasse t/2. Un dimensionnement complet doit aussi borner les valeurs intermédiaires.

## Hypothèses et limites

- Aucune transaction bancaire réelle.
- Cloud **simulé dans un processus local** : aucune latence réseau réelle mesurée.
- La clé secrète reste dans le moteur client en mémoire ; la séparation Cloud est **logique**, pas une isolation réseau démontrée.
- Les temps sont mesurés avec `perf_counter`.
- La mémoire RSS est relevée avant/après : **ce n'est pas un pic mémoire**.
- La taille Paillier est une estimation de charge cryptographique minimale, BFV utilise `to_bytes()`. Ne pas assimiler ces deux représentations à des formats de transport identiques.
- Le benchmarking BFV ne fait **pas** de batching pour préserver la comparaison une transaction par ciphertext.
- Paramètres cryptographiques de démonstration à faire valider avant toute revendication de niveau de sécurité.
- Le script échoue explicitement en cas de résultat incorrect ; aucune valeur n'est fabriquée.
- Ce prototype est un point de départ reproductible, **pas une solution bancaire de production**.

## Export

`results/benchmarks.csv` contient les durées, tailles, paramètres, RSS avant/après et validation de la correction.
