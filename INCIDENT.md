# Playbook incident : version compromise du paquet `requests`

## 1. Détecter

L'alerte peut venir de plusieurs sources :
- la CI : le job `pip-audit` ou Trivy échoue sur `requests`
- Dependabot : une alerte de sécurité ou une PR automatique
- un avis public (GitHub Advisory, PyPI) ou une alerte Slack/Teams

Les commandes pour confirmer sont :

```bash
python -m pip_audit -r app/requirements.txt          # voir si la version est signalée
grep -n "^requests==" app/requirements.txt           # voir si la version est pinnée
git log --oneline -- app/requirements.txt            # depuis quand
```

## 2. Évaluer l'exposition

Le risque : `requests` est critique dans notre cas, car `/fetch` l'utilise. Un paquet compromis peut exécuter du code (à l'installation ou à l'import), lire les variables d'environnement (`SECRET_KEY`), voler ou altérer des données. Il faut déterminer ce qui est touché et ce qui est épargné.

```bash
# Vérifier quelle version tourne réellement (sur dev, image et production)
python -m pip show requests
docker run --rm minishop pip show requests

# Consulter l'arbre de dépendances pour voir qui dépend du package requests
python -m pip install pipdeptree && pipdeptree -r -p requests

# Vérifier si l'image déployée contient la version compromise
trivy image minishop:ci

# Inventaire à partir du SBOM généré par la CI
grep -A3 '"name": "requests"' sbom.cdx.json
```

## 3. Contenir

### Cas A : la CI a bloqué avant la production

- Ne pas déployer, et geler les merges vers `master`.
- Vérifier que les versions sont pinnées avec hashes (dans le projet on l'avait fait avec `pip-compile --generate-hashes` et `--require-hashes`).
- Dependabot (pip, docker, actions) propose les mises à jour.
- Vérifier l'intégrité avec le SBOM.
- Vérifier que les secrets ne sont pas dans l'image et que le conteneur tourne en non-root.

```bash
docker run --rm minishop id                  # vérifier que root n'est pas affiché (on veut des droits utilisateurs uniquement)
git diff master -- app/requirements.txt      # seulement le fix doit avoir changé
```

### Cas B : le code compromis est déjà en production

Il faut isoler tout de suite :

```bash
docker ps                            # repérer le conteneur
docker stop <id_conteneur>           # arrêter le service touché
docker network disconnect <réseau> <id_conteneur>   # ou couper l'accès réseau
docker logs <id_conteneur> > incident-logs.txt      # il est important de garder les preuves avant de supprimer
docker rm <id_conteneur>
```

Puis remettre en ligne la dernière version saine en effectuant un rollback de l'image :

```bash
docker run -d -p 127.0.0.1:5000:5000 -e SECRET_KEY=<nouvelle_clé> minishop:<tag_sain>
```

## 4. Corriger

On monte de version (ou on patche), on repinne avec les hashes, on rebuild et on redéploie. Il faut vérifier chaque commande dans la précipitation (e.g. ne pas écrire le mauvais nom de paquet).

```bash
git checkout -b hotfix/requests
cd app
# Dans requirements.in on veut requests>=<version_corrigée>
rm requirements.txt
pip-compile --upgrade --generate-hashes requirements.in -o requirements.txt
git diff requirements.txt                          # seule la version attendue doit avoir changé

# Vérifier dans un venv propre
python3.12 -m venv /tmp/venv-test && source /tmp/venv-test/bin/activate
python -m pip install --require-hashes -r requirements.txt
python -m pip check
python -m pytest -q ../tests
python -m pip_audit -r requirements.txt            # doit afficher "No known vulnerabilities found"

# Rebuild et scan de l'image
docker build -t minishop:fixed .
trivy image --severity HIGH,CRITICAL --ignore-unfixed minishop:fixed
```

Puis commit, push et vérifier la PR Github. La CI doit être au vert avant de commencer à redéployer.

```bash
git add app/requirements.in app/requirements.txt
git commit -m "fix(deps): requests mis à jour suite à l'avis de sécurité"
git push -u origin hotfix/requests
```

Si la version corrigée n'existe pas encore, on verrouille la dernière version saine connue (e.g. `requests==<version_saine>`), en attendant le correctif.

## 5. Considérer l'attaque comme réussie

On part du principe que tous les secrets accessibles au processus sont compromis.

**Rotation des secrets :**

```bash
# Nouvelle SECRET_KEY (qui invalide toutes les sessions existantes)
python -c "import secrets; print(secrets.token_urlsafe(48))"
# La mettre dans le gestionnaire de secrets ou la config de déploiement, puis redéployer
```

- Changer aussi les mots de passe des comptes (`admin`, `alice`, `bob`, ...), car les hashes de la base ont pu fuiter.
- Révoquer les tokens et clés d'API éventuels (CI, registre Docker, cloud).
- Vérifier que `.env` n'a jamais été commité : `gitleaks detect --source .`

**Analyse des logs :**

```bash
grep -iE "fetch|error|failed login" incident-logs.txt   # requêtes inhabituelles
docker logs <id_conteneur> --since 48h | grep -i "fetch"
```

On cherche des connexions sortantes inconnues, des pics de tentatives de login ou des erreurs inhabituelles pendant la période d'exposition. (changer 48h)

**Rebuild propre :** reconstruire l'image depuis zéro et sans cache, car l'ancienne image est suspecte :

```bash
docker build --no-cache -t minishop:clean app/
```

## 6. Capitaliser

- **Post-mortem sans blâme** : chronologie, cause, ce qui a bien ou mal fonctionné, actions.
- **Règles de CI ajoutées ou renforcées** : `pip-audit` bloquant, installation avec `--require-hashes`, actions pinnées par SHA, Dependabot, SBOM conservé à chaque build.
- **SLA de correction** : par exemple CRITICAL sous 24 h, HIGH sous 7 jours.
