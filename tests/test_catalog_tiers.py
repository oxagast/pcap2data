"""Tests for the catalog server's three-tier licensing model.

Covers ``CatalogDB.resolve_install_tier_with_customer_fanout`` and
the manual CLI commands that operators use to set / upgrade an
install's tier. The test loads ``ps-catalog.py`` as a module by file
path because the catalog is shipped as a single executable script,
not an importable package.

Fan-out rule under test (see
``CatalogDB.resolve_install_tier_with_customer_fanout`` docstring
in ps-catalog.py for the canonical description):

* An install with its own non-free tier returns that tier
  unchanged.
* An install with tier ``free`` and a non-empty
  ``paddle_customer_id`` inherits the highest non-free tier found
  among the other installs sharing that customer id.
* Otherwise the install resolves to ``free``.

Operator workflow under test (per the project's manual-update
directive — tiers are set by the operator when a customer
subscribes via Paddle, not by an automated webhook):

* ``set_install_tier(primary, enterprise, paddle_customer_id=ctm_X)``
  followed by ``set_install_tier(seat2, free,
  paddle_customer_id=ctm_X)`` should make ``seat2`` resolve to
  ``enterprise`` while still showing tier ``free`` in
  ``list_installs`` (so the primary row stays visible)."""

import importlib.util
import sys
import uuid
from pathlib import Path

import pytest


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _catalog_script() -> Path:
    return _project_root() / "src" / "PacketSnitch-Pro" / "Servers" / "Catalog" / "ps-catalog.py"


def _load_catalog_module():
    """Load ps-catalog.py as a module by file path. We do this rather
    than shelling out so the tests can call CatalogDB methods
    directly without paying the cost of starting an HTTP server.

    The catalog script is shipped as a single executable that
    imports a small number of third-party packages (notably
    ``paddle``) at the top. If any of those are missing on the
    test machine, the test class is skipped rather than failing
    the whole run — the goal is to verify the tier fan-out logic
    in isolation, not the Paddle SDK.

    The module is also registered in ``sys.modules`` under its
    declared name. Without that, the ``@dataclass`` decorator in
    Python 3.14 fails to look up the enclosing module via
    ``sys.modules`` and raises ``AttributeError: 'NoneType' object
    has no attribute '__dict__'`` during class creation."""
    spec = importlib.util.spec_from_file_location("ps_catalog_test_module", _catalog_script())
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog_module()


def _fresh_db(tmp_path: Path):
    """Return a CatalogDB backed by a fresh sqlite file. The
    ``CatalogDB`` constructor takes a ``pathlib.Path`` (not a
    string) — it runs a writable-preflight that calls
    ``path.exists()`` and friends, which a plain ``str`` doesn't
    have. We hand it the full Path so the test db is created
    inside ``tmp_path`` and cleaned up automatically."""
    db_path = tmp_path / f"catalog-{uuid.uuid4().hex}.sqlite3"
    return _catalog.CatalogDB(db_path), db_path


def _register(db, install_uuid, tier, *, customer_id=""):
    return db.set_install_tier(
        install_uuid=install_uuid,
        tier=tier,
        paddle_customer_id=customer_id,
        paddle_subscription_id="",
        notes="",
    )


@pytest.fixture
def fanout_db(tmp_path):
    db, _path = _fresh_db(tmp_path)
    try:
        yield db
    finally:
        db.close()


def test_unknown_install_resolves_to_free(fanout_db):
    """An empty / unregistered install must resolve to ``free`` so the
    desktop client always gets a deterministic answer on first
    launch. Regression guard: do not return ``None`` or raise."""
    assert fanout_db.resolve_install_tier_with_customer_fanout("") == "free"
    unknown = str(uuid.uuid4())
    assert fanout_db.resolve_install_tier_with_customer_fanout(unknown) == "free"


def test_own_tier_wins_over_customer_group(fanout_db):
    """An install that has been explicitly upgraded to
    ``professional`` on its own row should not be silently
    downgraded by a sibling enterprise install — the operator's
    explicit setting wins, and the customer group is only a
    fallback for free-tier seats."""
    primary = str(uuid.uuid4())
    professional = str(uuid.uuid4())
    _register(fanout_db, primary, "enterprise", customer_id="ctm_shared")
    _register(fanout_db, professional, "professional", customer_id="ctm_shared")
    assert (
        fanout_db.resolve_install_tier_with_customer_fanout(professional) == "professional"
    )


def test_free_seat_inherits_enterprise_from_customer_group(fanout_db):
    """The headline case: an enterprise customer buys one Paddle
    subscription, the operator upgrades the primary install to
    ``enterprise``, then every additional install that shares the
    same ``paddle_customer_id`` should resolve to ``enterprise``
    even though its own row is still ``free``."""
    primary = str(uuid.uuid4())
    seat_a = str(uuid.uuid4())
    seat_b = str(uuid.uuid4())
    _register(fanout_db, primary, "enterprise", customer_id="ctm_acme")
    # The secondary seats are registered as ``free`` because they
    # were auto-created by ``/licenses`` lazy registration. The
    # customer id is the only thing linking them to the primary.
    _register(fanout_db, seat_a, "free", customer_id="ctm_acme")
    _register(fanout_db, seat_b, "free", customer_id="ctm_acme")
    assert fanout_db.resolve_install_tier_with_customer_fanout(seat_a) == "enterprise"
    assert fanout_db.resolve_install_tier_with_customer_fanout(seat_b) == "enterprise"
    # The primary still resolves to its own explicit tier.
    assert fanout_db.resolve_install_tier_with_customer_fanout(primary) == "enterprise"


def test_free_install_without_customer_id_stays_free(fanout_db):
    """A free-tier install that has no Paddle customer id should
    stay free — fan-out is opt-in via the customer id column."""
    free_isolated = str(uuid.uuid4())
    _register(fanout_db, free_isolated, "free", customer_id="")
    assert (
        fanout_db.resolve_install_tier_with_customer_fanout(free_isolated) == "free"
    )


def test_fanout_ignores_unrelated_customer_groups(fanout_db):
    """Two customers' installs must not bleed tiers into each other
    even if they happen to share the catalog. The
    ``paddle_customer_id`` column is the only thing that links
    seats — no customer id, no fan-out, regardless of how many
    other installs sit in the table."""
    ctm_acme_primary = str(uuid.uuid4())
    ctm_acme_seat = str(uuid.uuid4())
    ctm_globex_primary = str(uuid.uuid4())
    _register(fanout_db, ctm_acme_primary, "enterprise", customer_id="ctm_acme")
    _register(fanout_db, ctm_acme_seat, "free", customer_id="ctm_acme")
    _register(fanout_db, ctm_globex_primary, "enterprise", customer_id="ctm_globex")
    # Acme seat inherits Acme enterprise. The Globex enterprise
    # install must not leak in.
    assert (
        fanout_db.resolve_install_tier_with_customer_fanout(ctm_acme_seat) == "enterprise"
    )
    # Sanity: an Acme install with no customer id at all stays free
    # even though Acme enterprise exists in the same table.
    acme_orphan = str(uuid.uuid4())
    _register(fanout_db, acme_orphan, "free", customer_id="")
    assert (
        fanout_db.resolve_install_tier_with_customer_fanout(acme_orphan) == "free"
    )


def test_fanout_prefers_enterprise_over_professional_in_group(fanout_db):
    """If a customer group somehow contains a professional and an
    enterprise sibling (e.g. a misconfigured row), every free seat
    in the group should resolve to ``enterprise`` — the highest
    non-free tier. This protects customers from silent downgrades
    caused by a stray row in the customer group."""
    enterprise_primary = str(uuid.uuid4())
    professional_sibling = str(uuid.uuid4())
    free_seat = str(uuid.uuid4())
    _register(fanout_db, enterprise_primary, "enterprise", customer_id="ctm_mixed")
    _register(fanout_db, professional_sibling, "professional", customer_id="ctm_mixed")
    _register(fanout_db, free_seat, "free", customer_id="ctm_mixed")
    assert (
        fanout_db.resolve_install_tier_with_customer_fanout(free_seat) == "enterprise"
    )


def test_per_install_tier_view_unchanged_after_fanout(fanout_db):
    """``list_installs`` is the operator's source of truth for which
    rows are primaries. The fan-out helper must NOT mutate any
    row's stored ``license_tier`` — only the resolved (effective)
    tier is affected. After fan-out, ``list_installs`` must still
    show the free seat as ``free`` so the operator can see which
    row was the explicit upgrade."""
    primary = str(uuid.uuid4())
    seat = str(uuid.uuid4())
    _register(fanout_db, primary, "enterprise", customer_id="ctm_keep")
    _register(fanout_db, seat, "free", customer_id="ctm_keep")
    # Trigger fan-out read.
    fanout_db.resolve_install_tier_with_customer_fanout(seat)
    rows = {row["install_uuid"]: row for row in fanout_db.list_installs()}
    assert rows[primary]["license_tier"] == "enterprise"
    assert rows[seat]["license_tier"] == "free"
    # And the legacy per-install view (used by ``list-installs``)
    # still reports ``free`` for the seat.
    assert fanout_db.resolve_install_tier(seat) == "free"


def test_set_install_tier_creates_row_for_new_uuid(fanout_db):
    """``set_install_tier`` is upsert semantics: it must be safe to
    call for a UUID that has never been seen by the catalog. This
    is the path the operator uses when provisioning a new
    enterprise customer who hasn't yet launched the desktop app."""
    new_uuid = str(uuid.uuid4())
    row = _register(fanout_db, new_uuid, "enterprise", customer_id="ctm_new")
    assert row["license_tier"] == "enterprise"
    assert row["paddle_customer_id"] == "ctm_new"


def test_set_install_tier_rejects_invalid_uuid(fanout_db):
    """Defensive: the operator-facing CLI command must not let
    arbitrary text into the ``installs.install_uuid`` primary key
    column. The DB layer enforces the UUID regex so a typo in a
    shell script fails loudly with a ValueError rather than
    silently creating a junk row."""
    with pytest.raises(ValueError):
        fanout_db.set_install_tier(
            install_uuid="not-a-uuid",
            tier="free",
            paddle_customer_id="",
            paddle_subscription_id="",
            notes="",
        )


def test_set_install_tier_rejects_invalid_tier(fanout_db):
    """Defensive: the ``license_tier`` CHECK constraint is also
    enforced at the Python boundary so the CLI fails with a clear
    error instead of a sqlite IntegrityError stack trace."""
    install_uuid = str(uuid.uuid4())
    with pytest.raises(ValueError):
        fanout_db.set_install_tier(
            install_uuid=install_uuid,
            tier="platinum",
            paddle_customer_id="",
            paddle_subscription_id="",
            notes="",
        )


def test_set_install_tier_preserves_existing_customer_id(fanout_db):
    """The upsert in ``set_install_tier`` is OR-not-replace for
    ``paddle_customer_id`` / ``paddle_subscription_id`` so a
    later ``set-install-tier <uuid> free`` (e.g. an accidental
    downgrade) doesn't wipe the customer link the operator
    carefully set when provisioning. Re-set with a fresh customer
    id explicitly to overwrite."""
    install_uuid = str(uuid.uuid4())
    _register(fanout_db, install_uuid, "enterprise", customer_id="ctm_keep")
    _register(fanout_db, install_uuid, "free", customer_id="")
    row = fanout_db.get_install(install_uuid)
    assert row["license_tier"] == "free"
    # The customer id must have been preserved because the new
    # value was empty, not because the operator intended to
    # clear it. OR-merge is the right semantic for an idempotent
    # "re-apply the same command" workflow.
    assert row["paddle_customer_id"] == "ctm_keep"
