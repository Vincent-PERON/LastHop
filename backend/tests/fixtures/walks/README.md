# Parcours SNMP de référence

Un équipement = `<nom>.snmprec` (parcours, idéalement **réel et anonymisé**) + `<nom>.expect.json` (attendus).
`tests/unit/test_fixture_conformance.py` rejoue les vrais collecteurs sur chaque parcours, sans réseau.

- `lab-*.snmprec` : simulateurs de laboratoire (identiques à `tests-infra/snmpsim/data`).
- `fortigate-synthetic`, `generic-minimal` : écrits à la main par `../gen_synthetic.py` (marqués `"synthetic": true`).

Procédure complète : [docs/ADD_DRIVER.md](../../../../docs/ADD_DRIVER.md). **Ne jamais déposer un parcours non anonymisé.**
