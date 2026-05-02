#!/usr/bin/env python3
# Copyright 2024 LLM Wall Authors.
"""Blockchain ledger integrity verification script.

Usage:
    python scripts/verify_ledger.py --path ./data/ledger.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure package is importable when run from project root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from llm_wall.ledger.blockchain import Blockchain  # noqa: E402


def verify(ledger_path: str) -> None:
    """Loads and verifies a persisted blockchain.

    Args:
        ledger_path: Path to the ledger JSON file.
    """
    path = Path(ledger_path)
    if not path.exists():
        print(f"❌ Ledger file not found: {path}")
        sys.exit(1)

    chain = Blockchain(node_id="verifier", persist_path=ledger_path)
    height = chain.height
    valid = chain.is_valid()

    print(f"\n{'═' * 50}")
    print(f"  Ledger: {path}")
    print(f"  Height: {height} blocks")
    print(f"  Valid:  {'✅ YES' if valid else '❌ NO — CHAIN TAMPERED!'}")

    if not valid:
        print("\n  Checking individual blocks…")
        for i in range(1, height):
            current = chain.chain[i]
            previous = chain.chain[i - 1]
            if current.previous_hash != previous.hash:
                print(f"  ❌ Block #{i}: previous_hash mismatch")
            expected = current._compute_hash()  # pylint: disable=protected-access
            if expected != current.hash:
                print(f"  ❌ Block #{i}: hash invalid (data tampered)")
        sys.exit(1)

    print(f"\n  Block Summary:")
    for block in chain.chain[-5:]:  # Show last 5 blocks
        print(
            f"    #{block.index:04d} | {block.timestamp[:19]} | "
            f"events={len(block.data.events):3d} | "
            f"hash={block.hash[:12]}…"
        )

    print(f"\n  Merkle roots intact. All {height} blocks verified. ✅")


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(description="Verify LLM Wall blockchain")
    parser.add_argument(
        "--path",
        default="./data/ledger.json",
        help="Path to ledger JSON file",
    )
    args = parser.parse_args()
    verify(args.path)


if __name__ == "__main__":
    main()
