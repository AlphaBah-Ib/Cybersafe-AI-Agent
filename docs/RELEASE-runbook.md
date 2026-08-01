# Runbook — Publier une nouvelle release d'agent (auto-update)

Procedure pour publier une version signee que les agents installeront
automatiquement (timer nocturne + jitter). Le coeur de securite : chaque archive
est signee Ed25519 ; les agents verifient la signature avec la cle publique
embarquee avant d'appliquer. La cle privee ne quitte JAMAIS le poste de release.

## Pre-requis (une seule fois)
- Cle privee Ed25519 : `/home/bah/cybersafe-signing-keys/agent-signing-private.pem`
  (chmod 600, sauvegardee dans KeePassXC "Cybersafe Agent - cle signature Ed25519").
- La cle PUBLIQUE correspondante est embarquee en dur dans
  `cybersafe_agent/signing.py` (`_SIGNING_PUBLIC_KEY_PEM`). Si on regenere la
  paire, il FAUT mettre a jour cette constante et re-livrer l'agent par
  reinstallation (install.sh) avant que l'auto-update signe fonctionne.
- Bucket Scaleway prive : `cybersafe-agent-releases` (region fr-par).
- Les VM web + worker ont les creds `SCALEWAY_*` + boto3.

## Etapes pour publier la version X.Y.Z

### 1. Preparer le code + le tag
```bash
cd ~/Projects/Cybersafe-AI-Agent
# Mettre a jour __version__ dans cybersafe_agent/__init__.py -> "X.Y.Z"
git add -A && git commit -m "release: vX.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

### 2. Construire l'archive (reproductible depuis le tag)
```bash
git archive --format=tar.gz -o /tmp/cybersafe-agent-X.Y.Z.tar.gz vX.Y.Z
sha256sum /tmp/cybersafe-agent-X.Y.Z.tar.gz   # note ce hash
```

### 3. Signer l'archive (cle privee locale)
```bash
cd /home/bah/Projects/Cybersafe-AI/backend
./venv/bin/python manage.py sign_agent_release \
    --release-version X.Y.Z \
    --archive /tmp/cybersafe-agent-X.Y.Z.tar.gz \
    --private-key /home/bah/cybersafe-signing-keys/agent-signing-private.pem \
    --dry-run
# Note le SHA256 et la Signature (b64) affiches.
```

### 4. Uploader l'archive dans le bucket
```bash
# transferer sur une VM qui a boto3 + creds (worker)
scp -i ~/.ssh/scaleway_celery /tmp/cybersafe-agent-X.Y.Z.tar.gz root@163.172.191.41:/tmp/
# puis, sur la VM worker :
docker cp /tmp/cybersafe-agent-X.Y.Z.tar.gz cybersafe-worker:/tmp/
docker exec cybersafe-worker python -c "
import os, boto3
s3 = boto3.client('s3', endpoint_url=os.environ['SCALEWAY_S3_ENDPOINT_URL'],
    aws_access_key_id=os.environ['SCALEWAY_ACCESS_KEY_ID'],
    aws_secret_access_key=os.environ['SCALEWAY_SECRET_ACCESS_KEY'],
    region_name=os.environ['SCALEWAY_S3_REGION'])
s3.upload_file('/tmp/cybersafe-agent-X.Y.Z.tar.gz',
    'cybersafe-agent-releases', 'cybersafe-agent-X.Y.Z.tar.gz')
print('uploade')
"
```

### 5. Creer l'AgentRelease en prod (marque latest)
Sur la VM web, `docker exec cybersafe-web python` :
```python
from apps.soc.models import AgentRelease
from django.core.cache import cache
AgentRelease.objects.update_or_create(version='X.Y.Z', defaults={
    's3_key': 'cybersafe-agent-X.Y.Z.tar.gz',
    'sha256': '<SHA256 de l etape 3>',
    'signature': '<Signature b64 de l etape 3>',
    'is_latest': True,
    'min_supported': '<version mini supportee>',
    'notes': '<notes de version>',
})
cache.delete('agent_latest_release_info')
```

### 6. Verifier (preuve E2E)
Depuis le laptop (module agent present) :
```bash
cd ~/Projects/Cybersafe-AI-Agent
python3 -c "
import json, urllib.request
from cybersafe_agent.signing import verify_release
TOKEN='<un token agent actif>'
req=urllib.request.Request('https://app.cybersafe-ai.com/api/soc/agents/release/X.Y.Z/',
    headers={'X-Agent-Token': TOKEN})
d=json.load(urllib.request.urlopen(req))
a=urllib.request.urlopen(d['download_url']).read()
verify_release(a, d['sha256'], d['signature'])
print('OK — release verifiee, prete pour la flotte')
"
```

## Notes de securite
- Signature du SHA256 hex de l'archive (integrite + authenticite).
- Bucket PRIVE : distribution par URL pre-signee generee a la volee (600s).
- Un agent ne remplace son code que si la signature est valide (sinon rollback).
- Opt-out client : `auto_update: { enabled: false }` dans /etc/cybersafe/config.yaml.
- Timer : 02h + jitter 3h (etale la flotte, deploiement progressif).

## Rollback d'une mauvaise release
Si une release X.Y.Z pose probleme : remarquer la precedente comme latest.
```python
AgentRelease.objects.filter(version='<precedente>').update(is_latest=True)
# (le save() du modele retire is_latest des autres)
```
Les agents non encore mis a jour resteront sur l'ancienne ; ceux deja a jour
peuvent etre redescendus en publiant l'ancienne comme une nouvelle release.
