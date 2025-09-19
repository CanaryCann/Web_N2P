from __future__ import annotations

import base64
import io
from typing import List, Sequence, Tuple

import matplotlib.pyplot as plt

NESSUS_COLORS = {
    "Critical": "#B90E0A",
    "High": "#D6453D",
    "Medium": "#F0A202",
    "Low": "#4DA1A9",
    "Info": "#67ACE1",
    "Accent": "#263746",
}
BACKGROUND_COLOR = "#efefef"
TEXT_COLOR = "#263746"


def severity_bar_chart(data: Sequence[Tuple[str, int]]) -> str:
    labels, values = _unpack(data)
    colors = [NESSUS_COLORS.get(label, NESSUS_COLORS["Accent"]) for label in labels]
    return _bar_chart(labels, values, colors, title="Findings by Severity")


def top_hosts_chart(data: Sequence[Tuple[str, int]]) -> str:
    return _horizontal_bar_chart(
        data,
        color=NESSUS_COLORS["Accent"],
        title="Top Hosts by Findings",
        xlabel="Findings",
    )


def top_families_chart(data: Sequence[Tuple[str, int]]) -> str:
    return _horizontal_bar_chart(
        data,
        color="#67ACE1",
        title="Top Plugin Families",
        xlabel="Findings",
    )


def risk_factor_chart(data: Sequence[Tuple[str, int]]) -> str:
    labels, values = _unpack(data)
    if not any(values):
        return _empty_chart("No risk factor data")

    colors = ["#D6453D", "#F0A202", "#4DA1A9", "#67ACE1", "#B0BEC5"]
    fig, ax = plt.subplots(figsize=(4.5, 4.5))
    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct="%1.0f%%",
        colors=colors[: len(values)],
        startangle=90,
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
        textprops={"color": TEXT_COLOR},
    )
    plt.setp(autotexts, color="white", weight="bold")
    ax.set_title("Risk Factor Distribution", color=TEXT_COLOR, fontsize=12, weight="bold")
    ax.axis("equal")
    return _encode_figure(fig)


def _bar_chart(labels: Sequence[str], values: Sequence[int], colors: Sequence[str], title: str) -> str:
    if not any(values):
        return _empty_chart("No findings available")

    fig, ax = plt.subplots(figsize=(6, 3.2))
    bars = ax.bar(labels, values, color=colors)
    ax.set_facecolor("white")
    fig.patch.set_facecolor(BACKGROUND_COLOR)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_ylabel("Findings", color=TEXT_COLOR)
    ax.set_title(title, color=TEXT_COLOR, fontsize=12, weight="bold")
    ax.tick_params(colors=TEXT_COLOR)
    ax.bar_label(bars, padding=3, color=TEXT_COLOR, fontsize=9)
    fig.tight_layout()
    return _encode_figure(fig)


def _horizontal_bar_chart(
    data: Sequence[Tuple[str, int]],
    color: str,
    title: str,
    xlabel: str,
) -> str:
    labels, values = _unpack(data)
    if not any(values):
        return _empty_chart("No data available")

    fig_height = max(2.5, 0.4 * len(labels) + 1.2)
    fig, ax = plt.subplots(figsize=(6, fig_height))
    y_positions = range(len(labels))
    bars = ax.barh(y_positions, values, color=color)
    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels, color=TEXT_COLOR)
    ax.invert_yaxis()
    ax.set_xlabel(xlabel, color=TEXT_COLOR)
    ax.set_title(title, color=TEXT_COLOR, fontsize=12, weight="bold")
    ax.tick_params(colors=TEXT_COLOR)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_facecolor("white")
    fig.patch.set_facecolor(BACKGROUND_COLOR)
    ax.bar_label(bars, padding=3, color=TEXT_COLOR, fontsize=9)
    fig.tight_layout()
    return _encode_figure(fig)


def _empty_chart(message: str) -> str:
    fig, ax = plt.subplots(figsize=(4.5, 3))
    fig.patch.set_facecolor(BACKGROUND_COLOR)
    ax.axis("off")
    ax.text(0.5, 0.5, message, ha="center", va="center", color=TEXT_COLOR, fontsize=12)
    return _encode_figure(fig)


def _unpack(data: Sequence[Tuple[str, int]]) -> Tuple[List[str], List[int]]:
    labels = [label for label, _ in data]
    values = [int(value) for _, value in data]
    return labels, values


def _encode_figure(fig: "plt.Figure") -> str:
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", bbox_inches="tight", dpi=150)
    plt.close(fig)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
