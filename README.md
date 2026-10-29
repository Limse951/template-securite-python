# TP3 - Sécurité Python

Le but du TP est de récupérer deux flags avec Python.

Le programme cherche une page cachée, lit un CAPTCHA avec Tesseract, récupère le premier flag puis se connecte en TCP pour trouver le deuxième.

## Installation

Il faut Python, Poetry et Tesseract.

`poetry install`

## Lancement

`poetry run python -m tp3.main --target http://localhost:8080`

## Tests

`poetry run pytest tests/tp3 -v`

`poetry run ruff check src/tp3 tests/tp3`

Le programme a été testé en local et sur une instance distante. Les deux flags ont été récupérés.