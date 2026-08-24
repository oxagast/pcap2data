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


# ---------------------------------------------------------------------------
# Tier-grant ownership tests
# ---------------------------------------------------------------------------
# The catalog server ships a "tier grants every theme" feature so an
# install on the ``professional`` or ``enterprise`` plan is treated as
# owning every theme in the catalog without needing per-theme
# ``licenses`` rows. These tests cover the two new
# ``CatalogDB`` helpers that back the feature:
#
#   * ``effective_owned_theme_ids(install_uuid)`` — returns the full
#     union of (per-theme licenses) ∪ (every theme in the catalog)
#     for a Pro/Enterprise install, and just the per-theme licenses
#     otherwise. Drives ``/catalog`` and ``/licenses``.
#   * ``theme_is_effectively_owned(install_uuid, theme_id)`` — single-
#     theme equivalent that ``/themes/<id>/download`` uses to gate
#     the actual file fetch.
#
# Both helpers resolve the tier via ``resolve_install_tier_with_customer_fanout``
# so a free enterprise seat that shares a ``paddle_customer_id``
# with an enterprise primary also gets the grant — a single
# subscription can unlock every analyst's laptop, exactly the
# "primary + seats" model the customer-fanout feature supports.


def _seed_themes(db, theme_ids):
    """Bulk-insert a handful of theme rows so the tier-grant tests
    have a non-empty catalog to enumerate. ``upsert_theme`` is the
    same helper the CLI ``add-theme`` command uses, so the schema
    (and the ``paddle_*`` columns it expects) line up."""
    for theme_id in theme_ids:
        db.upsert_theme(
            theme_id=theme_id,
            name=theme_id,
            description="",
            price_cents=100,
            price_label="$1.00/month",
            paddle_product_id=f"prod_{theme_id}",
            paddle_price_id=f"pri_{theme_id}",
            preview_image="",
            preview_filename="",
            checkout_url="",
            hosted_checkout_url="",
            license_url="",
            theme_json="{}",
        )


@pytest.fixture
def tier_grant_db(tmp_path):
    """CatalogDB preloaded with a handful of theme rows. Tests
    that need a known catalog shape use this instead of the bare
    ``fanout_db`` fixture above so they can exercise the
    tier-grant path without juggling theme inserts inline."""
    db, _path = _fresh_db(tmp_path)
    try:
        _seed_themes(
            db,
            [
                "matrix-theme",
                "nilla-horizon-theme",
                "weebo-theme",
                "sub7-theme",
            ],
        )
        yield db
    finally:
        db.close()


def test_effective_owned_empty_for_free_install(tier_grant_db):
    """A free install with no per-theme licenses owns nothing —
    ``effective_owned_theme_ids`` must collapse to the legacy
    ``list_owned_theme_ids`` answer so the storefront shows every
    theme as ``owned: false`` and the operator doesn't see a
    surprise jump after the upgrade."""
    free_uuid = str(uuid.uuid4())
    _register(tier_grant_db, free_uuid, "free")
    owned = tier_grant_db.effective_owned_theme_ids(free_uuid)
    assert owned == []


def test_effective_owned_grants_every_theme_for_developer(tier_grant_db):
    """A ``developer`` install is treated like Pro/Enterprise for
    catalog access: every theme in the catalog is reported as
    owned. The operator assigns ``developer`` deliberately to a
    known dev / build / QA machine (the tier is ``manual-only`` —
    the Paddle webhook and lazy registration can never set it, see
    ``LICENSE_TIER_DEVELOPER`` in ps-catalog.py), and a dev
    machine that can't see the production storefront is the wrong
    default. The storefront shows the same Owned / Download
    affordances a Pro install sees, so build agents can install
    and exercise every theme without per-theme grant work."""
    dev_uuid = str(uuid.uuid4())
    _register(tier_grant_db, dev_uuid, "developer")
    owned = tier_grant_db.effective_owned_theme_ids(dev_uuid)
    assert sorted(owned) == [
        "matrix-theme",
        "nilla-horizon-theme",
        "sub7-theme",
        "weebo-theme",
    ]


def test_effective_owned_developer_still_dedupes_with_explicit_license(tier_grant_db):
    """Adding ``developer`` to the tier-grant set must not
    double-count: a dev install that ALSO holds an explicit
    per-theme ``licenses`` row (legal, e.g. a free-trial row from
    before the upgrade) should still see each id exactly once.
    The dedup guarantees the renderer's
    ``reconcileThemeLicenses`` cache write doesn't double-fetch
    the same theme file."""
    dev_uuid = str(uuid.uuid4())
    _register(tier_grant_db, dev_uuid, "developer")
    tier_grant_db.grant_license(dev_uuid, "matrix-theme")
    owned = tier_grant_db.effective_owned_theme_ids(dev_uuid)
    assert sorted(owned) == owned
    assert owned.count("matrix-theme") == 1
    assert len(owned) == 4


def test_effective_owned_grants_every_theme_for_professional(tier_grant_db):
    """Headline case: a ``professional`` install owns every theme
    in the catalog even if no per-theme ``licenses`` row exists.
    The renderer's ``reconcileThemeLicenses`` consumes this list
    to pre-populate the local theme cache, so a Pro upgrade
    lights up the whole storefront on the next refresh."""
    pro_uuid = str(uuid.uuid4())
    _register(tier_grant_db, pro_uuid, "professional")
    owned = tier_grant_db.effective_owned_theme_ids(pro_uuid)
    assert sorted(owned) == [
        "matrix-theme",
        "nilla-horizon-theme",
        "sub7-theme",
        "weebo-theme",
    ]


def test_effective_owned_grants_every_theme_for_enterprise(tier_grant_db):
    """Same headline case for ``enterprise`` — the storefront
    surfaces every theme as owned, regardless of which one the
    buyer actually clicked through Paddle to upgrade."""
    ent_uuid = str(uuid.uuid4())
    _register(tier_grant_db, ent_uuid, "enterprise")
    owned = tier_grant_db.effective_owned_theme_ids(ent_uuid)
    assert sorted(owned) == [
        "matrix-theme",
        "nilla-horizon-theme",
        "sub7-theme",
        "weebo-theme",
    ]


def test_effective_owned_fan_out_for_enterprise_seat(tier_grant_db):
    """Enterprise multi-seat support: the operator upgrades the
    primary install to ``enterprise`` and stamps the same
    ``paddle_customer_id`` on every additional seat. The
    fan-out logic that already feeds ``/licenses`` must also
    apply here, so a free seat that shares the customer id gets
    the same "all themes owned" answer the primary does."""
    primary = str(uuid.uuid4())
    seat = str(uuid.uuid4())
    _register(tier_grant_db, primary, "enterprise", customer_id="ctm_acme")
    _register(tier_grant_db, seat, "free", customer_id="ctm_acme")
    owned_seat = tier_grant_db.effective_owned_theme_ids(seat)
    assert sorted(owned_seat) == [
        "matrix-theme",
        "nilla-horizon-theme",
        "sub7-theme",
        "weebo-theme",
    ]


def test_effective_owned_unknown_install_is_empty(tier_grant_db):
    """An installUuid the catalog has never seen (no row in
    ``installs``) must not raise — the desktop client often polls
    ``/licenses`` before the install has registered. Returns an
    empty list so the storefront shows no owned themes until the
    first registration round-trip lands."""
    unknown = str(uuid.uuid4())
    assert tier_grant_db.effective_owned_theme_ids(unknown) == []
    # Empty / missing installUuid also short-circuits cleanly.
    assert tier_grant_db.effective_owned_theme_ids("") == []


def test_effective_owned_dedupes_license_plus_tier(tier_grant_db):
    """A Pro install that ALSO holds an explicit per-theme
    ``licenses`` row (legal, e.g. a free-trial row from before
    the upgrade) must still return each id exactly once. The
    sort + dedupe is the source of truth for the storefront's
    ``reconcileThemeLicenses`` cache, and a duplicate id would
    double-count the file write."""
    pro_uuid = str(uuid.uuid4())
    _register(tier_grant_db, pro_uuid, "professional")
    tier_grant_db.grant_license(pro_uuid, "matrix-theme")
    owned = tier_grant_db.effective_owned_theme_ids(pro_uuid)
    # Each id appears once; sort order is the canonical answer
    # so two back-to-back calls produce byte-identical lists.
    assert sorted(owned) == owned
    assert owned.count("matrix-theme") == 1
    assert len(owned) == 4


def test_theme_is_effectively_owned_grants_for_pro(tier_grant_db):
    """The single-theme helper is the auth gate on
    ``/themes/<id>/download``. A Pro install must be allowed
    through even though no per-theme ``licenses`` row exists —
    otherwise the catalog endpoint would report ``owned: true``
    and the download endpoint would 403 in the same session."""
    pro_uuid = str(uuid.uuid4())
    _register(tier_grant_db, pro_uuid, "professional")
    assert (
        tier_grant_db.theme_is_effectively_owned(pro_uuid, "matrix-theme")
        is True
    )
    # The theme must exist in the catalog — an unknown theme id
    # must NOT be silently "owned" just because the install is
    # on a paid tier.
    assert (
        tier_grant_db.theme_is_effectively_owned(pro_uuid, "no-such-theme")
        is False
    )


def test_theme_is_effectively_owned_free_install_needs_license(tier_grant_db):
    """A free install with no per-theme ``licenses`` row must
    get ``False`` for every theme — preserves the legacy
    auth-gate behaviour so the upgrade is observably the thing
    that flipped the answer from False to True."""
    free_uuid = str(uuid.uuid4())
    _register(tier_grant_db, free_uuid, "free")
    assert (
        tier_grant_db.theme_is_effectively_owned(free_uuid, "matrix-theme")
        is False
    )
    # Granting the license changes the answer — sanity check
    # that the helper is reading the licenses table, not just
    # caching a single False.
    tier_grant_db.grant_license(free_uuid, "matrix-theme")
    assert (
        tier_grant_db.theme_is_effectively_owned(free_uuid, "matrix-theme")
        is True
    )


def test_theme_is_effectively_owned_rejects_empty_inputs(tier_grant_db):
    """Defensive: an empty installUuid or theme id must return
    ``False`` rather than raising, because the request handlers
    in ``_handle_theme_download`` and friends treat the helper
    as a boolean gate and shouldn't crash on a malformed query
    string."""
    assert (
        tier_grant_db.theme_is_effectively_owned("", "matrix-theme") is False
    )
    assert (
        tier_grant_db.theme_is_effectively_owned(str(uuid.uuid4()), "") is False
    )
