"""A message carried across a redirect is one this deployment signed (#197).

The console's listing pages render `?error=` inside their own chrome. As plain
text that made a crafted link a way to put attacker-chosen words in a trusted
frame — autoescaped, so never script, but `/login?error=Your account is locked,
call 555-0100` reads exactly as though the console said it.

Signed rather than replaced by an enum of codes, because the API's own sentence
("base_url: is not a valid URL") is the useful part; and rather than a
server-side flash, because this deployment keeps no per-user state between
requests — the same reason the login state rides in a signed cookie.
"""

import uuid
from datetime import timedelta

from iceberg_api.auth.session import FLASH_TTL, issue_flash, issue_session, read_flash
from iceberg_core.config import ApiSettings


def test_a_message_survives_the_round_trip(api_settings: ApiSettings) -> None:
    token = issue_flash("base_url: is not a valid URL", api_settings)

    assert read_flash(token, api_settings) == "base_url: is not a valid URL"


def test_arbitrary_text_is_not_a_message(api_settings: ApiSettings) -> None:
    """The whole point: what a crafted link carries is not something this
    deployment said, so the page shows nothing rather than showing it."""
    assert read_flash("Your account is locked, call 555-0100", api_settings) is None


def test_nothing_at_all_is_not_a_message(api_settings: ApiSettings) -> None:
    assert read_flash(None, api_settings) is None
    assert read_flash("", api_settings) is None


def test_a_tampered_message_is_refused(api_settings: ApiSettings) -> None:
    """Signature over the payload, so editing the words breaks the token rather
    than producing a different valid one."""
    header, payload, signature = issue_flash("harmless", api_settings).split(".")

    assert read_flash(f"{header}.{payload}.{signature[:-4]}AAAA", api_settings) is None


def test_an_expired_message_is_refused(api_settings: ApiSettings) -> None:
    """A URL pasted into a chat an hour later should not still be complaining."""
    stale = issue_flash("stale complaint", api_settings, ttl=timedelta(seconds=-1))

    assert read_flash(stale, api_settings) is None
    assert read_flash(issue_flash("fresh", api_settings, ttl=FLASH_TTL), api_settings) == "fresh"


def test_a_session_cookie_is_not_a_message(api_settings: ApiSettings) -> None:
    """Both are signed with the same key, so the audience claim is the only thing
    keeping them apart — the same separation the login-state cookie relies on."""
    assert read_flash(issue_session(uuid.uuid4(), api_settings), api_settings) is None
