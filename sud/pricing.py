# sud/pricing.py
"""
Price comparison logic for FairRideApp.

Mapped design elements:
- PriceComparator class
- Hard goal: "Provide accurate and up-to-date trip prices"
- R3 – Fair Pricing Validation
"""

from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class TripOffer:
    provider: str
    price_eur: float
    eta_minutes: int


def select_best_offer(offers: Iterable[TripOffer]) -> TripOffer:
    """
    Choose the best offer given a list of TripOffer.

    Strategy:
    - Minimize price
    - Tie-break with shorter ETA
    """
    offers_list: List[TripOffer] = list(offers)
    if not offers_list:
        raise ValueError("No offers to compare")

    return min(offers_list, key=lambda o: (o.price_eur, o.eta_minutes))
