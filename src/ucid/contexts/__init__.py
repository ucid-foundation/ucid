# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""UCID Contexts module.

This module provides the context scoring framework for UCID. Contexts are
pluggable algorithms that evaluate specific dimensions of urban quality.

Built-in contexts:
- 15MIN: 15-Minute City accessibility
- TRANSIT: Public transportation quality
- CLIMATE: Climate resilience
- VITALITY: Urban vibrancy
- EQUITY: Access equity
- WALK: Walkability

Example:
    >>> from ucid.contexts import ContextRegistry, BaseContext, ContextResult
    >>> registry = ContextRegistry()
    >>> context_cls = registry.get_context_class("15MIN")
    >>> result = context_cls().compute(lat=41.015, lon=28.979, timestamp="2026W01T12")
"""

from ucid.contexts.base import BaseContext, ContextResult
from ucid.contexts.climate import ClimateContext
from ucid.contexts.equity import EquityContext
from ucid.contexts.fifteen_minute import FifteenMinuteContext
from ucid.contexts.registry import ContextRegistry
from ucid.contexts.transit import TransitContext
from ucid.contexts.vitality import VitalityContext
from ucid.contexts.walkability import WalkabilityContext

__all__ = [
    "BaseContext",
    "ContextResult",
    "ContextRegistry",
    "FifteenMinuteContext",
    "TransitContext",
    "ClimateContext",
    "VitalityContext",
    "EquityContext",
    "WalkabilityContext",
]
