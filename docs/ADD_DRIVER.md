# Ajouter un équipement ou un constructeur

LastHop n'utilise **aucun fichier MIB** : il lit des tables SNMP standard par OID numérique (IF-MIB, BRIDGE/Q-BRIDGE, LLDP,
ARP, ENTITY). Un nouvel équipement fonctionne donc s'il expose ces tables ; sinon il faut un **pilote** (quelques lignes
de Python pour les particularités du constructeur). Ce guide va du diagnostic au pilote testé.

## 1. Diagnostic : qu'est-ce qui manque ?

Sur la fiche d'un équipement (onglet *Résumé*, super admin) : **Lancer le diagnostic**. LastHop lit — sans rien modifier —
chaque table utile et répond :

- **ce qu'il peut faire** : inventaire des ports, topologie (LLDP/CDP), apprentissage MAC → port, IP ↔ MAC (ARP), localisation en direct ;
- **pourquoi une fonction manque** et **que faire** (activer LLDP, élargir la vue SNMP, ajouter les switchs d'accès…) ;
- le **détail** des tables (lignes lues, courts exemples).

Un résultat « partiel » signifie que la fonction marche avec une hypothèse (par exemple port de bridge = ifIndex, VLAN
inconnu parce que la FDB est lue sans Q-BRIDGE). Un routeur/pare-feu (FortiGate) n'a pas de table MAC : c'est normal,
c'est lui qui fournit l'**ARP** ; les ports se lisent sur les switchs.

## 2. Récupérer un parcours SNMP (snmpwalk) chez l'utilisateur

Machine qui joint l'équipement, avec `snmpwalk` (net-snmp). Adaptez l'authentification (SNMPv3 recommandé) :

```bash
OPTS='-v3 -l authPriv -u lecture -a SHA -A "<clé auth>" -x AES -X "<clé priv>" -On -Ox -t 5 -r 1'
for T in 1.3.6.1.2.1.1 1.3.6.1.2.1.2 1.3.6.1.2.1.31 1.3.6.1.2.1.4.22 1.3.6.1.2.1.4.35 \
         1.3.6.1.2.1.17 1.3.6.1.2.1.47.1.1.1.1 1.0.8802.1.1.2 1.3.6.1.4.1.9.9.23 1.3.6.1.4.1.9.9.46; do
  eval snmpwalk $OPTS 192.0.2.10 $T
done > walk.txt
```

`-On` : OID numériques ; `-Ox` : chaînes en hexadécimal (lecture sans ambiguïté). Les derniers sous-arbres (Cisco CDP/VTP)
peuvent rester vides sur les autres marques. Équipement Cisco : ajouter un parcours par VLAN
(`-n vlan-10` en SNMPv3, community `public@10` en v2c) si la table MAC en dépend.

## 3. Anonymiser

Les adresses MAC, IP, noms d'équipements, descriptions de ports, numéros de série et textes libres sont remplacés de façon
**cohérente** (une même valeur donne toujours la même valeur anonyme, donc les liens entre tables restent exacts). Le
préfixe constructeur (OUI) des MAC est conservé ; un sel aléatoire rend l'opération irréversible.

```bash
docker compose run --rm --no-deps -v "$PWD:/work" api \
  python -m app.cli walk-anonymize /work/walk.txt /work/hpe-6100.snmprec
```

**Relisez le fichier** avant de le transmettre (`grep -i` sur le nom de l'entreprise, des noms de personnes, des domaines) :
l'outil ne peut pas deviner tous les textes sensibles (par exemple une description de port saisie librement est remplacée,
mais pas un nom propre glissé dans une autre colonne). Aucun identifiant SNMP n'apparaît dans un parcours.

Vérifier le diagnostic hors ligne, sans l'équipement :

```bash
docker compose run --rm --no-deps -v "$PWD:/work" api python -m app.cli diagnose-walk /work/hpe-6100.snmprec
```

## 4. Ajouter le jeu de tests de l'équipement

Déposez dans `backend/tests/fixtures/walks/` :

- `<constructeur>-<modèle>.snmprec` : le parcours anonymisé ;
- `<constructeur>-<modèle>.expect.json` : ce que les collecteurs doivent produire.

```json
{
  "driver": "aruba_os",
  "interfaces": 24,
  "neighbors": 2,
  "fdb": 120,
  "arp": 0,
  "arp_vlans": {"10.12.3.4": 10},
  "verdicts": {"Apprentissage MAC → port": "ok", "Apprentissage IP ↔ MAC (ARP)": "na"}
}
```

Les valeurs se déterminent avec `diagnose-walk` puis **se vérifient à la main** sur l'équipement (nombre de ports, voisins
connus). Ajoutez `"synthetic": true` pour un parcours écrit à la main (FortiGate et « générique minimal » le sont : ils
décrivent la documentation du constructeur, pas du matériel réel — à remplacer par un vrai parcours dès qu'il existe).

```bash
docker compose -f docker-compose.test.yml run --rm tests \
  sh -c "alembic upgrade head && pytest -q --no-cov tests/unit/test_fixture_conformance.py"
```

Ces tests n'ont besoin d'aucun réseau : les **vrais collecteurs** sont rejoués sur le parcours (`WalkClient`). Si un
parcours révèle un défaut, corrigez le collecteur, pas le fichier attendu.

## 5. Écrire le pilote (si le générique ne suffit pas)

Le pilote générique (`GenericDriver`) tolère déjà : types d'interface anciens (62, 69, 117), absence d'`ifDescr`, de table
des ports de bridge (hypothèse port = ifIndex), de colonne de statut dans la FDB, LLDP ou CDP. Un pilote n'est utile que
pour une particularité. Dans `backend/app/drivers/families.py` :

```python
class MonConstructeurDriver(Driver):
    name = "mon_constructeur"
    vendor = "Mon Constructeur"
    oid_prefixes = ("1.3.6.1.4.1.<numéro d'entreprise>.",)   # sysObjectID

    def parse_model(self, sys_descr: str) -> str | None:     # repli quand ENTITY-MIB ne donne pas le modèle
        ...
```

Redéfinissables selon le besoin : `collect_neighbors` (voisins), `collect_trunks` (liens inter-switchs),
`collect_arp`, `collect_fdb` (ex. une table MAC par VLAN/contexte comme Cisco), `lookup_mac` (localisation en direct).

Ensuite, quatre branchements :

1. `drivers/registry.py` : ajouter la classe à `_SPECIFIC` (l'ordre compte : premier préfixe qui correspond) ;
2. `api/devices.py` : ajouter le nom à `DriverName` ;
3. une migration Alembic qui étend la contrainte `ck_dev_driver` (voir `0008_driver_fortinet.py`) ;
4. `front/src/views/DevicesView.vue` : libellé dans `DRIVER`.

La sauvegarde de configuration par SSH est indépendante : elle utilise un profil de commandes de lecture seule
(`services/cli.py`). Elle n'existe pas pour un constructeur sans profil.

## 6. Liste de contrôle avant d'envoyer la modification

- [ ] parcours **anonymisé et relu** + `.expect.json` vérifié sur l'équipement ;
- [ ] `pytest tests/unit/test_fixture_conformance.py` vert ;
- [ ] pilote branché aux quatre endroits (si pilote) ;
- [ ] diagnostic lancé sur l'équipement réel : les verdicts correspondent à la réalité ;
- [ ] `./scripts/security-check.sh` vert.

## Constructeurs couverts aujourd'hui

| Pilote | Matériel | État |
|---|---|---|
| `aruba_os` | ArubaOS-Switch / ProCurve, AOS-CX | simulateurs |
| `comware` | HPE Comware | simulateurs |
| `cisco_ios` | Cisco IOS (FDB par VLAN) | simulateurs |
| `fortinet` | FortiGate / FortiSwitch (ARP du routeur) | **parcours synthétique uniquement : à valider sur du matériel réel** |
| `generic` | tout autre équipement | parcours synthétique minimal |
