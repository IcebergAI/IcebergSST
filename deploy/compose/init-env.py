"""Create a development ``.env`` from ``.env.example`` with generated secrets.

Run through ``make init-env``. Every ``CHANGE_ME`` placeholder is replaced with a
value appropriate to its variable — random passwords, a real AES master key, and
a pepper sealed *with that key*, so the stack comes up configured correctly on the
first try instead of failing on a placeholder.

Deliberate choices:

* An existing ``.env`` is never overwritten. Losing the master key means every
  stored credential ref becomes undecryptable and every finding identity changes.
* The file is written ``0600``.
* Generated values are never printed. A secret echoed into a terminal ends up in
  shell history, scrollback, and CI logs.
"""

import argparse
import os
import secrets
import stat
import sys
from collections.abc import Callable
from pathlib import Path

from iceberg_core.secrets import EnvKeyBackend
from iceberg_core.secrets.env_key import decode_master_key, generate_master_key

PLACEHOLDER = "CHANGE_ME"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _password() -> str:
    return secrets.token_urlsafe(32)


#: Variables filled independently. The pepper ref is special-cased: it has to be
#: sealed with the master key generated in the same pass.
GENERATORS: dict[str, Callable[[], str]] = {
    "POSTGRES_PASSWORD": _password,
    "REDIS_PASSWORD": _password,
    "ICEBERG_MASTER_KEY": generate_master_key,
    # Signs session cookies; needs 32+ bytes for HS256 (RFC 7518 §3.2).
    "ICEBERG_SESSION_SECRET": _password,
}
# Deliberately not generated: an engine token is only valid once the API has
# minted it (`mint-engine-token` stores its hash), so a random value written here
# could only ever be rejected. It stays blank until an operator mints one.
PEPPER_VARIABLE = "ICEBERG_FINGERPRINT_PEPPER_REF"


def render(example: str) -> tuple[str, list[str]]:
    """Return the filled-in file plus the names of the variables that were set."""
    master_key = generate_master_key()
    filled: list[str] = []
    lines: list[str] = []

    for line in example.splitlines():
        name, _, value = line.partition("=")
        if not _ or value.strip() != PLACEHOLDER:
            lines.append(line)
            continue

        if name == "ICEBERG_MASTER_KEY":
            replacement = master_key
        elif name == PEPPER_VARIABLE:
            store = EnvKeyBackend(decode_master_key(master_key))
            replacement = store.generate_pepper_ref()
        elif name in GENERATORS:
            replacement = GENERATORS[name]()
        else:
            lines.append(line)
            continue

        lines.append(f"{name}={replacement}")
        filled.append(name)

    return "\n".join(lines) + "\n", filled


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", type=Path, default=REPO_ROOT / ".env.example")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / ".env")
    args = parser.parse_args(argv)

    if args.output.exists():
        print(f"{args.output} already exists; refusing to overwrite it", file=sys.stderr)
        return 1

    rendered, filled = render(args.example.read_text())
    # Created 0600 from the first byte: write-then-chmod leaves a window where the
    # master key sits world-readable on a shared machine.
    descriptor = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR
    )
    with os.fdopen(descriptor, "w") as output:
        output.write(rendered)

    remaining = [
        line.split("=", 1)[0] for line in rendered.splitlines() if line.endswith(f"={PLACEHOLDER}")
    ]
    print(f"wrote {args.output} with generated values for: {', '.join(filled)}", file=sys.stderr)
    if remaining:
        print(f"still needs a value: {', '.join(remaining)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
