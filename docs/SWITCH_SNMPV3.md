# Configuration SNMPv3 lecture seule sur les équipements

> **Avertissement** : ces exemples n'ont **pas** été testés sur du matériel réel (seuls des enregistrements `snmpsim` ont servi aux tests).
> La syntaxe et les algorithmes disponibles (SHA-256, AES) dépendent de la version du firmware : valider sur un équipement de laboratoire.

Principes communs, à appliquer partout :

1. **SNMPv3 authPriv** uniquement (authentification + chiffrement). Pas de v1/v2c si l'équipement permet de les désactiver.
2. Un utilisateur **dédié et en lecture seule** (vue limitée à ce qui est nécessaire : `system`, `interfaces`, `ifMIB`, `dot1d`/`dot1q` bridge, `ip` ARP, LLDP, ENTITY, CDP).
3. **ACL source** : seule l'adresse IP de l'hôte LastHop (celle du `worker`, c'est-à-dire l'IP de l'hôte Docker après NAT) peut interroger l'agent.
4. Algorithmes : SHA-256 (ou plus) + AES-128/192/256 si l'équipement le permet. **SHA-1** n'est un repli que si rien de mieux n'existe ; le profil doit alors porter `allow_legacy_algos=true` (tracé dans l'audit). MD5 et DES ne sont pas supportés par LastHop.
5. Mots de passe SNMP (clés) ≥ 12 caractères aléatoires, uniques par équipement ou par site (un profil LastHop par groupe d'équipements).

Côté LastHop, avant tout : déclarer les réseaux cibles (par défaut **aucune** cible n'est autorisée) :

```bash
curl -X PUT https://lasthop.example.org/api/v1/settings/snmp_allowed_cidrs \
  -H "Origin: https://lasthop.example.org" -H "X-CSRF-Token: <jeton>" --cookie "<session>" \
  -H "Content-Type: application/json" -d '{"value": ["10.20.0.0/16"]}'
```
(réglage réservé aux sessions administrateur : un token d'API ne peut jamais modifier les paramètres ; le front le proposera au lot f).

## HPE / Aruba — ArubaOS-Switch (ProCurve)

```text
snmpv3 enable
snmpv3 user lasthop-ro auth sha <CLE_AUTH> priv aes <CLE_PRIV>
snmpv3 group ManagerReadOnly user lasthop-ro sec-model ver3
snmpv3 restricted-access           ! désactive l'accès v1/v2c en écriture et force v3
no snmp-server community public
! Restreindre l'accès de gestion à l'hôte LastHop (s'applique à toutes les méthodes de gestion) :
ip authorized-managers 10.20.0.50 255.255.255.255 access manager
```
Notes : les firmwares anciens ne supportent que `sha` (SHA-1) et `aes` (AES-128) → profil LastHop `auth_proto=sha1`, `allow_legacy_algos=true`, `priv_proto=aes128`. AOS-CX utilise une autre syntaxe (`snmp-server vrf mgmt`, `snmpv3 user ... auth sha256 ... priv aes`) et un contexte de VRF.

## HPE Comware (H3C)

```text
acl basic 2999
 rule 0 permit source 10.20.0.50 0
 rule 100 deny
quit
snmp-agent
snmp-agent sys-info version v3
snmp-agent mib-view included LASTHOP-VIEW iso
snmp-agent group v3 LASTHOP-RO privacy read-view LASTHOP-VIEW acl 2999
snmp-agent usm-user v3 lasthop-ro LASTHOP-RO simple authentication-mode sha256 <CLE_AUTH> privacy-mode aes128 <CLE_PRIV> acl 2999
```
Notes : selon la version, `sha256` n'est pas disponible (utiliser `sha`) ; le mot-clé `simple` (clé en clair dans la commande) peut être remplacé par `cipher` pour saisir un hash. Pas de `write-view` : l'utilisateur est en lecture seule.

## Cisco IOS / IOS-XE

```text
ip access-list standard SNMP-LASTHOP
 permit 10.20.0.50
 deny any log
!
snmp-server view LASTHOP-VIEW iso included
snmp-server group LASTHOP-RO v3 priv read LASTHOP-VIEW access SNMP-LASTHOP
snmp-server user lasthop-ro LASTHOP-RO v3 auth sha256 <CLE_AUTH> priv aes 128 <CLE_PRIV> access SNMP-LASTHOP
```
Notes : `auth sha256` n'existe que sur IOS-XE récent (sinon `auth sha`). Pour la FDB par VLAN (lot d), il faudra autoriser les contextes `vlan-<id>` :
`snmp-server group LASTHOP-RO v3 priv context vlan- match prefix read LASTHOP-VIEW access SNMP-LASTHOP` (à valider).

## Vérifier depuis l'hôte LastHop

```bash
snmpget -v3 -l authPriv -u lasthop-ro -a SHA-256 -A '<CLE_AUTH>' -x AES -X '<CLE_PRIV>' <IP_SWITCH> 1.3.6.1.2.1.1.5.0
```
puis dans LastHop : créer le profil, l'équipement, et lancer `POST /api/v1/devices/{id}/test`.
