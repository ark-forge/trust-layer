"""Émission des clés d'exploitation, par un chemin rejouable plutôt qu'à la main.

Une clé créée au clavier sur l'hôte ne laisse pas de trace, ne se rejoue pas à
l'identique et ne survit pas à celui qui l'a créée. Ce module porte la logique
(idempotence, garde-fous) ; `scripts/provision_challenge_key.py` n'est que la
ligne de commande qui la branche sur le coffre réel.
"""

import logging
from typing import Callable

from .keys import (
    create_api_key,
    deactivate_key_by_ref,
    find_key_info_by_ref,
    get_key_plan,
)

logger = logging.getLogger("trust_layer.provisioning")


class ProvisioningError(RuntimeError):
    """Émission impossible ou ambiguë. Jamais levée pour un simple rejeu."""


def provision_key(
    ref_id: str,
    plan: str,
    email: str,
    writer: Callable[[str], None],
    stripe_customer_id: str = "",
) -> dict:
    """Garantit qu'une clé `plan` existe pour `ref_id`, et qu'elle est au coffre.

    Rejouable : appelée deux fois, elle ne crée qu'une clé et n'écrit qu'une fois.
    Le compte rendu retourné est fait pour être journalisé, donc il ne contient
    jamais la clé — seul `writer` la voit.

    Une clé existante mais désactivée, ou d'un autre plan, arrête l'émission au
    lieu d'être réutilisée : les deux cas donneraient un système qui a l'air
    provisionné et qui ne l'est pas (401 pour la première, quotas faux pour la
    seconde).
    """
    existant = find_key_info_by_ref(ref_id)
    if existant is not None:
        if not existant.get("active"):
            raise ProvisioningError(
                f"une clé existe déjà pour « {ref_id} » et elle est désactivée : "
                "la réactiver ou changer de ref, jamais en créer une seconde en silence"
            )
        plan_existant = get_key_plan(existant["_key"])
        if plan_existant != plan:
            raise ProvisioningError(
                f"une clé existe déjà pour « {ref_id} » avec le plan « {plan_existant} », "
                f"or « {plan} » est demandé : les quotas ne seraient pas ceux qu'on croit"
            )
        logger.info("provisioning: clé déjà en place pour %s (plan %s)", ref_id, plan)
        return {"created": False, "ref_id": ref_id, "plan": plan_existant}

    key = create_api_key(stripe_customer_id, ref_id, email, plan=plan)
    try:
        writer(key)
    except Exception as exc:
        # Une clé valide que le coffre ne connaît pas est un secret actif dont
        # personne n'a la trace : on la referme avant de remonter l'échec.
        deactivate_key_by_ref(ref_id)
        raise ProvisioningError(
            f"clé créée puis désactivée : écriture au coffre impossible ({exc})"
        ) from exc

    logger.info("provisioning: clé créée pour %s (plan %s)", ref_id, plan)
    return {"created": True, "ref_id": ref_id, "plan": plan}
