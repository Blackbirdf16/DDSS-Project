# sud/validation.py
"""
Input validation for trip requests.

Mapped design elements:
- DataValidator class
- Required Property: Integrity
- Security Pattern: Input Validation
"""

from dataclasses import dataclass


@dataclass
class TripRequest:
    origin: str
    destination: str
    battery_level: int  # 0–100
    max_wait_minutes: int


class ValidationError(ValueError):
    """Raised when the trip request is not acceptable."""


def validate_trip_request(trip: TripRequest) -> None:
    """Validate user input before sending to external providers / APIs."""
    if not trip.origin or not trip.destination:
        raise ValidationError("Origin and destination are required")

    if trip.origin == trip.destination:
        raise ValidationError("Origin and destination must be different")

    if not (0 <= trip.battery_level <= 100):
        raise ValidationError("Battery level must be between 0 and 100")

    if trip.max_wait_minutes <= 0 or trip.max_wait_minutes > 120:
        raise ValidationError("Max wait time must be between 1 and 120 minutes")
