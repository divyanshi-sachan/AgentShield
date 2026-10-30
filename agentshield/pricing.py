"""List prices (USD per million tokens) for cost estimates in reports.

Snapshot of Anthropic first-party API list prices as of 2026-10-06. Estimates
ignore prompt-caching discounts and batch pricing; thinking tokens are billed
as output tokens and are already included in the API's `output_tokens`.
Haiku 5.5 prices are for prompts up to 100K tokens, which covers every
AgentShield request.
"""

from __future__ import annotations

PRICES_AS_OF = "2026-10-06"

PRICES: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (10.00, 50.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-haiku-4-5": (1.00, 5.00),
}


def estimate_cost(model: str | None, input_tokens: int, output_tokens: int) -> dict | None:
    if not model or model not in PRICES:
        return None
    price_in, price_out = PRICES[model]
    usd = input_tokens * price_in / 1e6 + output_tokens * price_out / 1e6
    return {
        "usd": round(usd, 4),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "price_per_mtok": {"input": price_in, "output": price_out},
        "prices_as_of": PRICES_AS_OF,
    }
