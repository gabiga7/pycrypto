# Installation et utilisation du système
Ce README vous guide à travers les étapes d'installation et d'utilisation de notre système.

## Installation des dépendances

Les dépendances nécessaires pour ce projet sont listées dans le fichier `requirements.txt` dans le dossier `src/`. Pour installer ces dépendances, exécutez la commande suivante:

`pip install -r ./src/requirements.txt`

### Si vous rencontrez des problèmes avec la bibliothèque Crypto

`pip3 uninstall crypto` 
`pip3 uninstall pycrypto` 
`pip3 uninstall pycryptodome` 
`pip3 install pycryptodome`

## Configuration initiale

Avant de lancer les tests, il est nécessaire de générer les paires de clés pour les utilisateurs et de préparer l'environnement. Suivez ces étapes :

1. Depuis le dossier `src/`, lancez le script de génération de clés avec la commande suivante :

    ```bash
    python generate_keys.py
    ```

    Ce script va créer deux paires de clés RSA pour Alice et Bob, les sauvegarder dans les dossiers `alice_pc` et `bob_pc` respectivement, et copier les clés publiques dans le dossier `ac_issuer` sous les noms `alice_dupont.pub` et `bob_dumas.pub`.

2. Vérifiez que les clés sont bien en place dans les dossiers `alice_pc`, `bob_pc`, et `ac_issuer`.

Ces étapes garantissent le bon fonctionnement des tests et des simulations dans le système.

## Mise en place du système

Pour mettre en place le système, vous devez lancer les trois serveurs dans un nouveau terminal. Ces serveurs se trouvent dans les dossiers respectifs :

- `src/ac_issuer/ac_issuer.py`
- `src/ac_repository/repo_ac.py`
- `src/application_server/application_server.py`

## Procédure

Création du AC d'Alice :
`src/alice_pc/alice_pc.py 5000` (où `5000` correspond au port de l'AC issuer)


Une fois qu'Alice a son AC, elle peut se connecter au supercalculateur :
 `src/alice_pc/alice_pc.py 5001` (où `5001` correspond au port du supercalculateur)
