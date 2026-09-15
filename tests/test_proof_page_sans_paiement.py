"""Page preuve rendue depuis la vue publique : elle ne porte aucun frais de certification.

La page ne doit alors rien dire d'un paiement, et ne doit pas présenter la signature
ArkForge comme un témoin indépendant.
"""

from trust_layer.templates import render_proof_page


def _public_proof():
    # Forme de la vue publique servie par GET /v1/proof/{id} : pas de certification_fee.
    return {
        "proof_id": "prf_20260914_194825_a747d0",
        "spec_version": "3.1",
        "timestamp": "2026-09-14T19:48:25Z",
        "hashes": {"chain": "sha256:842240b6", "request": "sha256:2058278a", "response": "sha256:387dcaed"},
        "seller": "corpus.arkforge.tech",
        "arkforge_signature": "ed25519:AVSK8y8",
        "timestamp_authority": {"status": "verified"},
        "transparency_log": {"status": "verified", "log_index": 2834496977},
        "batch_anchor": {"status": "anchored"},
        "provider_payment": None,
        "transaction_success": True,
        "upstream_status_code": 200,
        "verification_url": "https://trust.arkforge.tech/v1/proof/prf_20260914_194825_a747d0",
    }


def test_proof_without_fee_says_nothing_about_payment():
    html = render_proof_page(_public_proof(), integrity_verified=True)

    assert "Stripe" not in html
    assert "Payment verified" not in html
    assert "confirms payment occurred" not in html
    assert '<span class="label">Payment</span>' not in html
    assert "Payment ID" not in html


def test_public_view_shows_the_service_called():
    html = render_proof_page(_public_proof(), integrity_verified=True)

    assert '<span class="label">Service</span><span class="val">corpus.arkforge.tech</span>' in html


def test_signature_is_not_listed_as_independent():
    html = render_proof_page(_public_proof(), integrity_verified=True)

    assert "Independent verification sources" not in html
    assert "You do not need to trust ArkForge" not in html
    assert "The signature relies on ArkForge’s key" in html
    assert "can be checked without ArkForge" in html
