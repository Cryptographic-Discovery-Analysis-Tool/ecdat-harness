"""TRAP-07 (harness §7.3): zero-crypto negative control. Correct ECDAT
behaviour on this target is zero crypto assets AND a coverage entry
confirming the target was actually scanned (not silently skipped) --
"zero assets" alone, with no coverage entry, is a failure per §7.3.

This module deliberately imports nothing from `hashlib`, `hmac`, `secrets`,
`ssl`, `cryptography`, or any crypto library, and contains no crypto-shaped
string literals (algorithm names, PEM markers, etc.).
"""
from __future__ import annotations


def add_totals(items: list[float]) -> float:
    return sum(items)


def format_receipt(customer_name: str, items: list[tuple[str, float]]) -> str:
    lines = [f"Receipt for {customer_name}"]
    for name, price in items:
        lines.append(f"  {name}: {price:.2f}")
    lines.append(f"Total: {add_totals([price for _, price in items]):.2f}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_receipt("Test Customer", [("Widget", 9.99), ("Gadget", 19.99)]))
