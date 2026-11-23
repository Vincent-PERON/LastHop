"""Messages en français clair pour le journal de sauvegarde : ce qui s'est passé + que faire."""

from __future__ import annotations

# code -> (ce qui s'est passé, que faire)
HUMAN: dict[str, tuple[str, str]] = {
    "UNSUPPORTED_DRIVER": (
        "Ce modèle d'équipement n'est pas encore reconnu : on ne sait pas quelles commandes lui envoyer.",
        "Lancez d'abord un « test SNMP » sur l'équipement pour l'identifier (Cisco, Comware ou Aruba sont gérés).",
    ),
    "NO_SSH_PROFILE": (
        "Aucun profil de connexion SSH n'est associé à cet équipement.",
        "Créez un profil SSH (menu « Profils SSH »), puis choisissez-le dans la fiche de l'équipement.",
    ),
    "TARGET_NOT_ALLOWED": (
        "L'adresse de l'équipement est en dehors des réseaux autorisés : la connexion a été refusée par sécurité.",
        "Vérifiez le paramètre « Réseaux SNMP autorisés » : il s'applique aussi aux sauvegardes.",
    ),
    "SSH_HOSTKEY_UNKNOWN": (
        "L'empreinte (clé d'hôte) de l'équipement n'a jamais été validée : par sécurité, on ne s'y connecte pas sans cela.",
        "Dans la fiche de l'équipement, cliquez « Vérifier l'empreinte SSH », comparez-la avec celle affichée sur l'équipement, puis approuvez-la.",
    ),
    "SSH_HOSTKEY_CHANGED": (
        "L'empreinte de l'équipement a CHANGÉ depuis son approbation. Cela peut venir d'un remplacement de matériel ou d'une réinstallation… "
        "ou d'une tentative d'usurpation. Aucun identifiant n'a été envoyé.",
        "Si le changement est attendu, refaites la vérification d'empreinte et approuvez la nouvelle. Sinon, prévenez la sécurité.",
    ),
    "SSH_UNREACHABLE": (
        "L'équipement n'a pas répondu à la connexion SSH.",
        "Vérifiez qu'il est allumé, que son adresse est correcte, que SSH est activé (port indiqué dans la fiche) et qu'aucun pare-feu ne bloque le port.",
    ),
    "SSH_REFUSED": (
        "L'équipement a refusé la connexion SSH (port fermé).",
        "Activez SSH sur l'équipement ou corrigez le numéro de port dans sa fiche.",
    ),
    "SSH_AUTH_FAILED": (
        "L'équipement a refusé l'identifiant ou le mot de passe (ou la clé) du profil SSH.",
        "Vérifiez le profil SSH (utilisateur, mot de passe ou clé) et que ce compte existe sur l'équipement et peut se connecter en SSH.",
    ),
    "SSH_ALGO_MISMATCH": (
        "L'équipement et la plateforme n'ont aucun algorithme de chiffrement SSH en commun (équipement ancien).",
        "Mettez à jour l'équipement si possible. Sinon, activez « Algorithmes SSH anciens » dans sa fiche (moins sûr, tracé dans l'audit).",
    ),
    "SSH_PRIVILEGE_REQUIRED": (
        "Le compte se connecte en mode utilisateur : il n'a pas le droit d'afficher la configuration.",
        "Donnez au compte le niveau de privilège maximal (Cisco : privilege 15 ; Aruba : manager ; Comware : rôle network-admin).",
    ),
    "SSH_ERROR": (
        "La connexion SSH s'est interrompue de façon inattendue.",
        "Réessayez. Si cela se reproduit, consultez le détail technique et les journaux de l'équipement.",
    ),
    "CLI_PROMPT_TIMEOUT": (
        "La connexion a réussi mais l'équipement n'a pas affiché son invite de commande à temps.",
        "Vérifiez que le compte arrive bien sur une ligne de commande (pas de menu ni de message bloquant à la connexion).",
    ),
    "CLI_COMMAND_REJECTED": (
        "L'équipement a refusé la commande d'affichage de la configuration.",
        "Vérifiez les droits du compte et la version du logiciel de l'équipement ; le détail technique montre sa réponse exacte.",
    ),
    "CLI_TIMEOUT": (
        "L'équipement a mis trop de temps à répondre à la commande.",
        "L'équipement est peut-être surchargé : réessayez plus tard.",
    ),
    "CLI_OUTPUT_EMPTY": (
        "L'équipement a répondu, mais la configuration reçue est vide ou trop courte pour être valide : elle n'a PAS été enregistrée.",
        "Vérifiez les droits du compte ; le détail technique montre ce qui a été reçu.",
    ),
    "BACKUP_TOO_LARGE": (
        "La configuration reçue dépasse la taille maximale acceptée (5 Mo) : elle n'a pas été enregistrée.",
        "Vérifiez qu'il s'agit bien d'une configuration et non d'un autre affichage.",
    ),
    "INTERNAL_ERROR": (
        "Erreur interne inattendue pendant la sauvegarde.",
        "Réessayez ; si cela persiste, contactez l'administrateur de la plateforme (le détail technique est dans les journaux serveur).",
    ),
}

KIND_LABEL = {"running": "configuration en cours (running)", "startup": "configuration de démarrage (startup)"}


def human(code: str) -> tuple[str, str]:
    return HUMAN.get(code, HUMAN["INTERNAL_ERROR"])


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} octets"
    return f"{n / 1024:.1f} Ko" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} Mo"
