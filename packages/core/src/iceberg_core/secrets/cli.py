"""Key-management CLI: ``python -m iceberg_core.secrets <command>``.

The bootstrap tooling an operator needs before the stack will start (see
``docs/security.md`` § Bootstrap and ``.env.example``):

* ``generate-master-key`` — a fresh ``ICEBERG_MASTER_KEY``.
* ``generate-pepper`` — a fresh fingerprint pepper, printed **only** as a sealed
  ref for ``ICEBERG_FINGERPRINT_PEPPER_REF``. The pepper itself is never
  displayed; it is not something a human needs to see or store.
* ``seal`` — seal a connector credential read from **stdin**, printing its ref.

Secrets are read from stdin, never from arguments: process arguments are visible
to every user on the host via ``ps``.
"""

import argparse
import sys
from collections.abc import Sequence

from iceberg_core.secrets.base import SecretPurpose, SecretStoreError
from iceberg_core.secrets.env_key import EnvKeyBackend, generate_master_key
from iceberg_core.secrets.factory import build_secret_store

PURPOSE_CHOICES = [SecretPurpose.CREDENTIAL.value, SecretPurpose.GENERIC.value]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m iceberg_core.secrets",
        description="IcebergSST key and secret bootstrap helpers.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "generate-master-key",
        help="print a fresh base64 master key for ICEBERG_MASTER_KEY",
    )
    commands.add_parser(
        "generate-pepper",
        help="print a sealed fingerprint-pepper ref for ICEBERG_FINGERPRINT_PEPPER_REF",
    )
    seal = commands.add_parser(
        "seal",
        help="seal a secret read from stdin and print its opaque ref",
    )
    seal.add_argument(
        "--purpose",
        choices=PURPOSE_CHOICES,
        default=SecretPurpose.CREDENTIAL.value,
        help="what the sealed ref is for (default: credential)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    try:
        match args.command:
            case "generate-master-key":
                print(generate_master_key())
            case "generate-pepper":
                store = build_secret_store()
                if not isinstance(store, EnvKeyBackend):
                    raise SecretStoreError(
                        "generate-pepper is specific to the env-key backend; "
                        "other backends generate the pepper in the store itself"
                    )
                print(store.generate_pepper_ref())
            case "seal":
                # At most one trailing newline is stripped — the one `echo` or a
                # heredoc appends. A credential that genuinely ends in newlines
                # must seal exactly as piped, or the connector authenticates with
                # a silently corrupted value.
                plaintext = sys.stdin.read().removesuffix("\n")
                if not plaintext:
                    raise SecretStoreError("nothing to seal: pipe the secret in on stdin")
                print(build_secret_store().seal(plaintext, purpose=SecretPurpose(args.purpose)))
    except SecretStoreError as exc:
        # The message describes configuration, never secret material.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover — exercised via __main__.py
    raise SystemExit(main())
