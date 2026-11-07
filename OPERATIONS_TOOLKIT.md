# Operations Toolkit — quatre outils de support informatique

Outils personnels de démonstration, développés avec assistance IA. Python 3.11+, bibliothèque standard uniquement. Les entrées sont des fichiers JSON fournis par l'utilisateur; aucun accès réseau ou changement système n'est effectué.

## Démarrage depuis la racine du dépôt

```bash
python -m ops_toolkit inventory examples/ops-inventory.json
python -m ops_toolkit capacity examples/ops-capacity.json
python -m ops_toolkit subnet examples/ops-subnet.json
python -m ops_toolkit sla examples/ops-sla.json
python -m unittest discover -s tests -p test_ops_toolkit.py -v
```

Les commandes produisent du JSON sur la sortie standard. Code de sortie 0 : analyse terminée, même si des anomalies sont signalées. Code 2 : entrée invalide ou fichier illisible; erreur JSON sur la sortie d'erreur.

## Cas d'usage et contrats

| Commande | Entrée | Résultat |
|---|---|---|
| inventory | before et after : listes avec asset_id unique | Identifiants ajoutés/supprimés et champs modifiés |
| capacity | volumes : volume, total_bytes, used_bytes | Pourcentage occupé, octets libres, état ok/warning/critical |
| subnet | cidr : réseau IPv4 ou IPv6 strict | Taille et bornes des adresses utilisables sans énumération |
| sla | tickets et now; chaque ticket contient id, opened_at, target_hours, closed_at facultatif | Durée écoulée, état et dépassement du délai |

### Inventaires
Comparer deux exports avant/après une maintenance. Les identifiants sont sensibles à la casse. Un doublon invalide l'analyse. Un champ absent et un champ explicitement nul sont considérés comme différents. Aucun rapprochement approximatif n'est effectué.

### Capacité
Seuils par défaut : avertissement à 80 %, critique à 95 %, bornes incluses. Les valeurs négatives, non finies et les volumes nuls sont refusés. Une mesure ponctuelle ne permet pas de prédire une date de saturation.

### Réseaux
Le CIDR doit être aligné sur son adresse réseau. IPv4 /31 et /32 sont traités explicitement. IPv6 exclut l'adresse de sous-réseau sauf pour /127 et /128. Aucune découverte d'hôtes ni vérification de disponibilité n'est effectuée.

### Délais de tickets
Les horodatages doivent préciser leur fuseau. Les durées sont calculées en heures continues, sans calendrier ouvrable, pauses ni jours fériés. Le dépassement est strictement supérieur à la cible. Un ticket fermé arrête son compteur à closed_at; les dates futures ou incohérentes sont refusées.

## Architecture

- ops_toolkit/audits.py : fonctions pures, déterministes, sans fichiers ni réseau.
- ops_toolkit/__main__.py : lecture de fichiers, sélection d'analyse et sérialisation.
- tests/test_ops_toolkit.py : seuils, dates, entrées incorrectes, CLI et réseaux.
- examples/ops-*.json : données synthétiques reproductibles.

Le module est exécuté depuis la racine du dépôt. Il n'est pas inclus dans le paquet src/it_operations_lab installé par pip.

## Scénario de démonstration en entretien

1. Exécuter inventory et expliquer le remplacement de PC-002 par PC-003.
2. Montrer la modification du champ os de PC-001.
3. Exécuter capacity et expliquer la classification de chaque volume.
4. Montrer pourquoi un ticket fermé ne continue pas à accumuler du temps.
5. Lancer les tests, puis expliquer les limites des modèles ci-dessus.

## Validation

15 tests unittest exécutés avec succès lors de l'ajout. Pour intégrer cette suite à une autre chaîne de validation, utiliser la commande unittest ci-dessus. Aucun résultat de déploiement en production n'est revendiqué.
