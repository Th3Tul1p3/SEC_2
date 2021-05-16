# Laboratoire 2 - SEC

> Jérôme Arn

# Setup 

Pour démarrer le projet, il faut commencer par mettre en place la base de données avec les commandes suivantes.

```sh
cd DB
docker-compose up -d 
```

# Utilisation

```shell
./laboratoire_2 --help 
laboratoire_2 0.1.0

USAGE:
    laboratoire_2 [FLAGS] [OPTIONS]

FLAGS:
    -h, --help              Prints help information
    -l, --login             If you want to login
    -p, --password-reset    If you want to reset password
    -r, --register          If you want to register
    -t, --twofa             If you want to disable/enable 2fa
    -V, --version           Prints version information

OPTIONS:
        --browser <browser>      enter password [default: ]
        --password <password>    enter password [default: empty]
        --username <username>    enter username [default: empty]
```

## Exemple d'enregistrement

Pour s'enregistrer en activant l'authentification double facteur :

```sh
./laboratoire_2 -rt --username jerome@heig.ch --password PiC$!@H%ucCuMt59$3UGzmxE
```

## Exemple pour s'authentifier 

authentification d'un utilisateur avec la 2fa activé avec ouverture du code QR dans le navigateur de votre choix.

```sh
./laboratoire_2 -l --username jerome@heig.ch --password PiC$!@H%ucCuMt59$3UGzmxE --browser firefox
```

Dans ce cas, on affiche juste l'URL du code QR.

```sh
./laboratoire_2 -l --username jerome@heig.ch --password PiC$!@H%ucCuMt59$3UGzmxE 
```

# Test

## Test implémenté

La validation d'entrée a été mise en place dans la librairie **validators**. Les parties sans interactions utilisateurs et authentifications double facteurs ont été testées pour vérifier le bon fonctionnement. 

Pour les tests de login et d'enregistrement, il faut utiliser le script **manual_cargo_test.sh** car la base de données n'a pas l'air d'apprécié la vitesse à laquelle les tests s'effectuent.

## Test à implémenter

Tous les tests qui ont un rapport avec google authenticator, n'ont pas été mis en place par manque de temps. Il aurait fallut faire un mock des fonctions utilisées. 

De même que pour l'envoi de mail, aucun test n'a été fait car, Il aurait fallut avoir allez lire le mail entrant pour voir si le message envoyé est correct.

# Bonus effectué

- Mise en place d'une base de donnée postgresql
- Envoi d'un vrai mail
- Suggestion d'un bon mot de passe à l'utilisateur.
- (interface CLI)