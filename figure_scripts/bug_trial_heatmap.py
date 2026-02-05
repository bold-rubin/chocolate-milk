import argparse
import json
import sys

import matplotlib.cm as cm
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap, Normalize

### HeatMap for comparing two fuzzers side by side on each trial bug distribution


def load_data(json_path: str) -> dict:
    """Load bug breakdown data from JSON file."""
    with open(json_path, "r") as f:
        return json.load(f)


def get_all_harnesses(data: dict) -> set:
    """Extract all unique harness names from the data."""
    harnesses = set()
    for bug_info in data.values():
        for harness_name in bug_info.get("harnesses", {}).keys():
            harnesses.add(harness_name)
    return harnesses


def filter_data_by_harness(data: dict, harness: str) -> dict:
    """Filter data to only include bugs that have the specified harness."""
    filtered = {}
    for bug_id, bug_info in data.items():
        if harness in bug_info.get("harnesses", {}):
            filtered[bug_id] = bug_info
    return filtered


def prepare_heatmap_data(data: dict, harness: str):
    """Prepare heatmap data for a specific harness. Returns None if no data."""
    filtered_data = filter_data_by_harness(data, harness)

    if not filtered_data:
        return None

    # First pass: find max trial count and compute per-trial totals
    raw_max_trials = 0
    trial_sums = {}
    for bug, info in filtered_data.items():
        trials = info["harnesses"][harness]["trials"]
        raw_max_trials = max(raw_max_trials, len(trials))
        for i, v in enumerate(trials, start=1):
            trial_sums[i] = trial_sums.get(i, 0) + float(v)

    # Find trials with actual data (non-zero sum)
    trials_with_data = sorted(
        [t for t in range(1, raw_max_trials + 1) if trial_sums.get(t, 0) > 0]
    )

    # Determine which trials to keep:
    # - If raw_max_trials <= 10: keep all trials (even blank ones)
    # - If raw_max_trials > 10: keep all non-blank + some blank to reach 10 total
    if raw_max_trials <= 10:
        trials_to_keep = list(range(1, raw_max_trials + 1))
    else:
        all_trials = set(range(1, raw_max_trials + 1))
        blank_trials = sorted(all_trials - set(trials_with_data))

        num_to_remove = raw_max_trials - 10

        if len(blank_trials) >= num_to_remove:
            trials_to_remove = set(blank_trials[-num_to_remove:])
        else:
            trials_to_remove = set(blank_trials)
            remaining_to_remove = num_to_remove - len(blank_trials)
            trials_to_remove.update(trials_with_data[-remaining_to_remove:])

        trials_to_keep = sorted(all_trials - trials_to_remove)

    if not trials_to_keep:
        return None

    # Create mapping from old trial numbers to new consecutive numbers
    trial_mapping = {old: new for new, old in enumerate(trials_to_keep, start=1)}

    # Build dataframe
    records = []
    for bug, info in filtered_data.items():
        trials = info["harnesses"][harness]["trials"]
        for old_trial_num in trials_to_keep:
            if old_trial_num <= len(trials):
                v = trials[old_trial_num - 1]
            else:
                v = 0.0
            new_trial_num = trial_mapping[old_trial_num]
            records.append({"bug": bug, "trial": new_trial_num, "reach": float(v)})

    if not records:
        return None

    df = pd.DataFrame(records)
    max_trials = len(trials_to_keep)

    # Per-trial totals and shares
    trial_range = range(1, max_trials + 1)
    trial_total = df.groupby("trial")["reach"].sum().reindex(trial_range).fillna(0.0)
    pivot = df.pivot_table(
        index="trial", columns="bug", values="reach", aggfunc="sum", fill_value=0.0
    ).reindex(trial_range, fill_value=0.0)
    shares = pivot.div(trial_total.replace(0, np.nan), axis=0).fillna(0.0)

    # Order bugs alphabetically
    bugs_order = sorted(df["bug"].unique())
    heat = shares[bugs_order].T  # rows=bugs, cols=trials

    # Dominant bug per trial for emphasis
    dominant_bug = shares.idxmax(axis=1)
    bug_to_row = {b: r for r, b in enumerate(bugs_order)}

    return {
        "heat": heat,
        "bugs_order": bugs_order,
        "trial_range": trial_range,
        "trial_total": trial_total,
        "dominant_bug": dominant_bug,
        "bug_to_row": bug_to_row,
        "max_trials": max_trials,
    }


def plot_side_by_side_heatmap(
    data1: dict,
    data2: dict,
    harness: str,
    fuzzer1_name: str,
    fuzzer2_name: str,
    output_dir: str = ".",
):
    """Generate side-by-side heatmap comparing two fuzzers for a specific harness."""

    # Prepare data for both fuzzers
    heatmap_data1 = prepare_heatmap_data(data1, harness)
    heatmap_data2 = prepare_heatmap_data(data2, harness)

    if heatmap_data1 is None and heatmap_data2 is None:
        print(f"⚠ No data found for harness: {harness}")
        return

    # Get union of all bugs from both datasets
    bugs1 = set(heatmap_data1["bugs_order"]) if heatmap_data1 else set()
    bugs2 = set(heatmap_data2["bugs_order"]) if heatmap_data2 else set()
    all_bugs = sorted(bugs1 | bugs2)
    num_bugs = len(all_bugs)

    if num_bugs == 0:
        print(f"⚠ No bugs found for harness: {harness}")
        return

    # =============================================================================
    # PUBLICATION-QUALITY HEATMAP DESIGN (Amber Sunset)
    # =============================================================================

    # --- Color Scheme: Amber Sunset (dual-mode compatible) ---
    COLORS = {
        "bg": "#FDFCFA",
        "cell_bg": "#FDF8F0",
        "text_primary": "#3D2E1F",
        "text_secondary": "#7A6B5A",
        "grid": "#EDE6DB",
        "cell_border": "#E5DDD0",
        "border": "#8B5A2B",
    }

    # Colormap: warm cream → deep brown
    cmap_colors = [
        "#FDF8F0",  # Warm cream
        "#FCE8C8",  # Light gold
        "#F9D08C",  # Soft amber
        "#F5B34A",  # Golden yellow
        "#E8922D",  # Bright orange
        "#D4701C",  # Deep orange
        "#A85215",  # Burnt sienna
        "#6B3410",  # Dark brown
    ]
    custom_cmap = LinearSegmentedColormap.from_list("amber_sunset", cmap_colors, N=256)

    # --- Typography Setup ---
    plt.rcParams.update(
        {
            "figure.dpi": 300,
            "figure.facecolor": COLORS["bg"],
            "axes.facecolor": COLORS["bg"],
            "font.family": ["Avenir Next", "Avenir", "Helvetica Neue", "sans-serif"],
            "font.weight": "normal",
            "axes.labelweight": "semibold",
            "axes.titleweight": "bold",
            "axes.labelcolor": COLORS["text_primary"],
            "axes.edgecolor": COLORS["grid"],
            "xtick.color": COLORS["text_primary"],
            "ytick.color": COLORS["text_primary"],
            "text.color": COLORS["text_primary"],
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.spines.bottom": False,
            "axes.spines.left": False,
        }
    )

    # --- Figure Setup ---
    # Dynamically size figure based on number of bugs
    if num_bugs <= 2:
        fig_height = 3.2 + num_bugs * 1.2
    elif num_bugs <= 5:
        fig_height = 3.0 + num_bugs * 1.0
    else:
        fig_height = 3.0 + num_bugs * 0.85

    fig_height = min(fig_height, 16)
    fig_width = 18  # Wider for side-by-side

    fig = plt.figure(figsize=(fig_width, fig_height), facecolor=COLORS["bg"])

    # Adjust margins based on bug count
    if num_bugs <= 2:
        bottom_margin = 0.22
        top_margin = 0.82
    elif num_bugs <= 5:
        bottom_margin = 0.16
        top_margin = 0.86
    else:
        bottom_margin = 0.12
        top_margin = 0.88

    # Create gridspec for two heatmaps + one shared colorbar
    gs = fig.add_gridspec(
        1,
        3,
        width_ratios=[1, 1, 0.04],
        wspace=0.15,
        left=0.08,
        right=0.88,
        top=top_margin,
        bottom=bottom_margin,
    )

    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])
    ax_cbar = fig.add_subplot(gs[0, 2])

    # --- Fixed scale at 100% ---
    max_share = 1.0

    # --- Helper function to draw heatmap on an axis ---
    def draw_heatmap(ax, heatmap_data, fuzzer_name, all_bugs, show_ylabel=True):
        if heatmap_data is None:
            # Draw empty placeholder
            ax.set_xlim(0, 10)
            ax.set_ylim(0, len(all_bugs))
            ax.set_facecolor(COLORS["cell_bg"])
            ax.text(
                5,
                len(all_bugs) / 2,
                "No Data",
                ha="center",
                va="center",
                fontsize=16,
                fontweight="bold",
                color=COLORS["text_secondary"],
            )
            ax.set_xticks([])
            ax.set_yticks([])
            # Add fuzzer name below
            ax.text(
                5,
                -0.8,
                fuzzer_name,
                ha="center",
                va="top",
                fontsize=18,
                fontweight="bold",
                color=COLORS["text_primary"],
            )
            return

        heat = heatmap_data["heat"]
        bugs_order = heatmap_data["bugs_order"]
        trial_range = heatmap_data["trial_range"]
        trial_total = heatmap_data["trial_total"]
        dominant_bug = heatmap_data["dominant_bug"]
        bug_to_row = heatmap_data["bug_to_row"]
        max_trials = heatmap_data["max_trials"]

        # Reindex heat to include all bugs (fill missing with 0)
        heat_full = pd.DataFrame(0.0, index=all_bugs, columns=list(trial_range))
        for bug in bugs_order:
            for t in trial_range:
                if bug in heat.index and t in heat.columns:
                    heat_full.loc[bug, t] = heat.loc[bug, t]

        # Draw heatmap
        sns.heatmap(
            heat_full,
            ax=ax,
            cmap=custom_cmap,
            vmin=0.0,
            vmax=max_share,
            cbar=False,
            linewidths=1.5,
            linecolor=COLORS["cell_border"],
            square=False,
            xticklabels=[f"{i}" for i in trial_range],
            yticklabels=all_bugs if show_ylabel else False,
        )

        # Y-axis styling
        if show_ylabel:
            ax.set_ylabel("", fontsize=0)
            ax.set_yticklabels(
                ax.get_yticklabels(),
                fontsize=13,
                fontweight="semibold",
                color=COLORS["text_primary"],
                rotation=0,
                ha="right",
            )
            ax.tick_params(axis="y", length=0, pad=12)
        else:
            ax.set_ylabel("")
            ax.tick_params(axis="y", length=0)

        # X-axis styling
        ax.set_xlabel("")
        ax.xaxis.tick_bottom()
        ax.set_xticklabels(
            ax.get_xticklabels(),
            fontsize=13,
            fontweight="semibold",
            color=COLORS["text_primary"],
        )
        ax.tick_params(axis="x", length=0, pad=10)

        # Add "Trial" label below x-axis
        trial_label_offset = 0.8 if num_bugs <= 2 else (1.0 if num_bugs <= 5 else 1.2)
        ax.text(
            max_trials / 2 + 0.5,
            len(all_bugs) + trial_label_offset,
            "Trial",
            ha="center",
            va="top",
            fontsize=16,
            fontweight="bold",
            color=COLORS["text_primary"],
        )

        # Add fuzzer name below the heatmap
        fuzzer_label_offset = 1.6 if num_bugs <= 2 else (1.8 if num_bugs <= 5 else 2.0)
        ax.text(
            max_trials / 2 + 0.5,
            len(all_bugs) + fuzzer_label_offset,
            fuzzer_name,
            ha="center",
            va="top",
            fontsize=18,
            fontweight="bold",
            color=COLORS["text_primary"],
        )

        # Mark zero-value cells with X
        for row_idx, bug in enumerate(all_bugs):
            for col_idx, t in enumerate(trial_range):
                val = heat_full.loc[bug, t] if t in heat_full.columns else 0
                if val == 0:
                    cx, cy = col_idx + 0.5, row_idx + 0.5
                    x_size = 0.25
                    ax.plot(
                        [cx - x_size, cx + x_size],
                        [cy - x_size, cy + x_size],
                        color=COLORS["text_secondary"],
                        linewidth=2,
                        zorder=5,
                    )
                    ax.plot(
                        [cx - x_size, cx + x_size],
                        [cy + x_size, cy - x_size],
                        color=COLORS["text_secondary"],
                        linewidth=2,
                        zorder=5,
                    )

        # Highlight dominant cells
        for col_idx, t in enumerate(trial_range):
            tot = trial_total.loc[t]
            if tot <= 0:
                continue
            b = dominant_bug.loc[t]
            if b not in all_bugs:
                continue
            r = all_bugs.index(b)

            rect = mpatches.FancyBboxPatch(
                (col_idx + 0.08, r + 0.08),
                0.84,
                0.84,
                boxstyle=mpatches.BoxStyle("Round", pad=0, rounding_size=0.08),
                linewidth=2.5,
                edgecolor=COLORS["border"],
                facecolor="none",
                zorder=10,
            )
            ax.add_patch(rect)

    # Draw both heatmaps
    draw_heatmap(ax1, heatmap_data1, fuzzer1_name, all_bugs, show_ylabel=True)
    draw_heatmap(ax2, heatmap_data2, fuzzer2_name, all_bugs, show_ylabel=False)

    # Add "Bug ID" label to the left of the first heatmap
    bug_label_offset = -1.5 if num_bugs <= 2 else (-1.8 if num_bugs <= 5 else -2.0)
    ax1.text(
        bug_label_offset,
        num_bugs / 2,
        "Bug ID",
        ha="center",
        va="center",
        fontsize=16,
        fontweight="bold",
        color=COLORS["text_primary"],
        rotation=90,
    )

    # --- Custom Colorbar ---
    norm = Normalize(vmin=0, vmax=max_share)
    sm = cm.ScalarMappable(cmap=custom_cmap, norm=norm)
    sm.set_array([])

    cbar = fig.colorbar(sm, cax=ax_cbar, orientation="vertical")
    cbar.outline.set_visible(False)

    num_ticks = 5
    tick_values = np.linspace(0, max_share, num_ticks)
    cbar.set_ticks(tick_values)
    cbar.ax.set_yticklabels(
        [f"{v * 100:.0f}%" for v in tick_values],
        fontsize=12,
        fontweight="medium",
        color=COLORS["text_primary"],
    )
    cbar.ax.tick_params(length=0, pad=8)

    cbar.ax.set_ylabel(
        "Energy Share",
        fontsize=14,
        fontweight="bold",
        color=COLORS["text_primary"],
        rotation=270,
        labelpad=24,
    )

    # --- Legend for indicators ---
    legend_x = 0.94
    legend_y = 0.935

    legend_patch = mpatches.FancyBboxPatch(
        (legend_x, legend_y - 0.014),
        0.014,
        0.028,
        boxstyle=mpatches.BoxStyle("Round", pad=0, rounding_size=0.004),
        linewidth=2,
        edgecolor=COLORS["border"],
        facecolor=COLORS["cell_bg"],
        transform=fig.transFigure,
    )
    fig.patches.append(legend_patch)

    fig.text(
        legend_x + 0.022,
        legend_y,
        "Dominant target",
        fontsize=11,
        fontweight="medium",
        color=COLORS["text_secondary"],
        ha="left",
        va="center",
    )

    legend_y_zero = legend_y - 0.045

    legend_patch_zero = mpatches.FancyBboxPatch(
        (legend_x, legend_y_zero - 0.014),
        0.014,
        0.028,
        boxstyle=mpatches.BoxStyle("Round", pad=0, rounding_size=0.004),
        linewidth=1,
        edgecolor=COLORS["cell_border"],
        facecolor=COLORS["cell_bg"],
        transform=fig.transFigure,
    )
    fig.patches.append(legend_patch_zero)

    x_center = legend_x + 0.007
    y_center = legend_y_zero
    x_size = 0.004
    fig.lines.extend(
        [
            plt.Line2D(
                [x_center - x_size, x_center + x_size],
                [y_center - x_size * 1.5, y_center + x_size * 1.5],
                color=COLORS["text_secondary"],
                linewidth=1.5,
                transform=fig.transFigure,
            ),
            plt.Line2D(
                [x_center - x_size, x_center + x_size],
                [y_center + x_size * 1.5, y_center - x_size * 1.5],
                color=COLORS["text_secondary"],
                linewidth=1.5,
                transform=fig.transFigure,
            ),
        ]
    )

    fig.text(
        legend_x + 0.022,
        legend_y_zero,
        "Zero energy",
        fontsize=11,
        fontweight="medium",
        color=COLORS["text_secondary"],
        ha="left",
        va="center",
    )

    # --- Export ---
    harness_clean = harness.replace("fuzzing_", "")

    pdf_path = f"{output_dir}/{harness_clean}_heatmap.pdf"
    fig.savefig(
        pdf_path, bbox_inches="tight", facecolor=COLORS["bg"], edgecolor="none", dpi=300
    )

    png_path = f"{output_dir}/{harness_clean}_heatmap.png"
    fig.savefig(
        png_path, bbox_inches="tight", facecolor=COLORS["bg"], edgecolor="none", dpi=300
    )

    plt.close(fig)

    print(f"✓ Exported: {pdf_path}")
    print(f"✓ Exported: {png_path}")
    print(f"  Harness: {harness} | Bugs: {num_bugs}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate side-by-side energy share heatmaps comparing two fuzzers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bug_trial_heatmap.py bug_breakdown.json afl_bug_breakdown.json --fuzzer1 IJON --fuzzer2 AFL
  python bug_trial_heatmap.py data1.json data2.json --fuzzer1 Fuzzer1 --fuzzer2 Fuzzer2 --output ./plots
  python bug_trial_heatmap.py data1.json data2.json --fuzzer1 A --fuzzer2 B --harness fuzzing_sqlite3_fuzz
        """,
    )
    parser.add_argument(
        "json_file1",
        type=str,
        help="Path to the first JSON file containing bug breakdown data",
    )
    parser.add_argument(
        "json_file2",
        type=str,
        help="Path to the second JSON file containing bug breakdown data",
    )
    parser.add_argument(
        "--fuzzer1",
        "-f1",
        type=str,
        required=True,
        help="Name of the first fuzzer (displayed under its heatmap)",
    )
    parser.add_argument(
        "--fuzzer2",
        "-f2",
        type=str,
        required=True,
        help="Name of the second fuzzer (displayed under its heatmap)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=".",
        help="Output directory for generated plots (default: current directory)",
    )
    parser.add_argument(
        "--harness",
        "-H",
        type=str,
        default=None,
        help="Generate plot for a specific harness only (default: all harnesses)",
    )

    args = parser.parse_args()

    # Load data
    print(f"Loading data from: {args.json_file1}")
    try:
        data1 = load_data(args.json_file1)
    except FileNotFoundError:
        print(f"Error: File not found: {args.json_file1}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}")
        sys.exit(1)

    print(f"Loading data from: {args.json_file2}")
    try:
        data2 = load_data(args.json_file2)
    except FileNotFoundError:
        print(f"Error: File not found: {args.json_file2}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}")
        sys.exit(1)

    print(f"Loaded {len(data1)} bugs from {args.fuzzer1}")
    print(f"Loaded {len(data2)} bugs from {args.fuzzer2}")

    # Get harnesses from both datasets
    harnesses1 = get_all_harnesses(data1)
    harnesses2 = get_all_harnesses(data2)
    all_harnesses = harnesses1 | harnesses2
    print(f"Found {len(all_harnesses)} harnesses: {sorted(all_harnesses)}")

    if args.harness:
        if args.harness not in all_harnesses:
            print(f"Error: Harness '{args.harness}' not found in data")
            print(f"Available harnesses: {sorted(all_harnesses)}")
            sys.exit(1)
        harnesses_to_plot = [args.harness]
    else:
        harnesses_to_plot = sorted(all_harnesses)

    print(f"\nGenerating plots for {len(harnesses_to_plot)} harness(es)...")
    print("=" * 60)

    for harness in harnesses_to_plot:
        print(f"\nProcessing: {harness}")
        plot_side_by_side_heatmap(
            data1, data2, harness, args.fuzzer1, args.fuzzer2, args.output
        )

    print("\n" + "=" * 60)
    print("Done!")


if __name__ == "__main__":
    main()
