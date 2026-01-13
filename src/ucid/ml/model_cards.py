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

"""Model Card generator for UCID prediction models.

This module provides data structures and functions for generating
standardized model documentation following ML model card best practices.
Model cards document intended use, limitations, and ethical considerations.
"""

from dataclasses import dataclass, field


@dataclass
class ModelCard:
    """Structured documentation for a machine learning model.

    Model cards provide standardized documentation of ML models including
    their intended use, performance metrics, limitations, and ethical
    considerations.

    Attributes:
        model_id: Unique identifier for the model.
        description: Brief description of the model's purpose.
        metrics: Dictionary of performance metric names to values.
        limitations: List of known limitations or failure modes.
        ethical_considerations: Notes on ethical use and potential biases.

    Example:
        >>> card = ModelCard(
        ...     model_id="15min-predictor-v1",
        ...     description="Predicts 15-minute city scores",
        ...     metrics={"rmse": 5.2, "mae": 3.8},
        ...     limitations=["Trained only on European cities"],
        ...     ethical_considerations="May underestimate for rural areas",
        ... )
        >>> print(card.to_markdown())
    """

    model_id: str
    description: str
    metrics: dict[str, float] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    ethical_considerations: str = ""

    def to_markdown(self) -> str:
        """Generate a Markdown representation of the model card.

        Returns:
            Formatted Markdown string documenting the model.
        """
        lines = [
            f"# Model Card: {self.model_id}",
            "",
            "## Description",
            self.description,
            "",
            "## Performance Metrics",
        ]

        for metric_name, metric_value in self.metrics.items():
            lines.append(f"- **{metric_name}**: {metric_value:.4f}")

        lines.extend(
            [
                "",
                "## Limitations",
            ]
        )
        for limitation in self.limitations:
            lines.append(f"- {limitation}")

        lines.extend(
            [
                "",
                "## Ethical Considerations",
                self.ethical_considerations,
            ]
        )

        return "\n".join(lines)


def generate_card(model_id: str, metrics: dict[str, float]) -> ModelCard:
    """Generate a basic model card with default values.

    Creates a model card with auto-generated description and default
    limitations. Should be customized with actual model details before
    publishing.

    Args:
        model_id: Unique identifier for the model.
        metrics: Dictionary of performance metric names to values.

    Returns:
        A ModelCard instance with placeholder content.

    Example:
        >>> card = generate_card("transit-v1", {"rmse": 4.5})
        >>> print(card.model_id)
        transit-v1
    """
    return ModelCard(
        model_id=model_id,
        description="Auto-generated model card. Please update with actual details.",
        metrics=metrics,
        limitations=[
            "Trained on limited data.",
            "May not generalize to all cities.",
        ],
        ethical_considerations=("Verify fairness across demographic groups before deploying."),
    )
