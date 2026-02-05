#!/usr/bin/env python3
"""
Script to plot vulnerability detection times for MAGMA dataset.
Creates a timeline chart showing when different approaches detected each vulnerability.
Publication-quality version for research papers.
"""

import argparse
import sys
import pandas as pd
import matplotlib.pyplot as plt


def main(filename: str, ignore_aijon: bool = False, ignore_ijon: bool = False, ignore_aijon_nk: bool = False):
    # Set publication-quality style
    plt.style.use('seaborn-v0_8-paper')
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif']
    plt.rcParams['font.size'] = 11
    plt.rcParams['axes.labelsize'] = 12
    plt.rcParams['axes.titlesize'] = 13
    plt.rcParams['xtick.labelsize'] = 10
    plt.rcParams['ytick.labelsize'] = 10
    plt.rcParams['legend.fontsize'] = 11
    plt.rcParams['figure.titlesize'] = 14
    plt.rcParams['pdf.fonttype'] = 42  # TrueType fonts for PDF
    plt.rcParams['ps.fonttype'] = 42

    # Read the CSV file with automatic delimiter detection (supports both comma and tab)
    df = pd.read_csv(filename, sep=None, engine='python')

    # Convert time values from seconds to hours
    df_hours = df.copy()
    columns_to_convert = ['AFL++']
    if not ignore_ijon:
        columns_to_convert.append('IJON')
    if not ignore_aijon:
        columns_to_convert.append('AIJON')
    if not ignore_aijon_nk:
        columns_to_convert.append('AIJON-NK')
    for col in columns_to_convert:
        df_hours[col] = df[col] / 3600.0

    # Get the vulnerability IDs
    vuln_ids = df_hours['Vuln ID'].tolist()
    num_vulns = len(vuln_ids)

    # Create the figure with better proportions for papers
    fig, ax = plt.subplots(figsize=(10, max(10, num_vulns * 0.35)))

    # Use colorblind-friendly palette (Wong 2011)
    approaches = {
        'AFL++': {'color': '#0173B2', 'marker': 'o', 'label': 'AFL++', 'size': 80}
    }
    if not ignore_ijon:
        approaches['IJON'] = {'color': '#DE8F05', 'marker': 's', 'label': 'IJON', 'size': 80}
    if not ignore_aijon:
        approaches['AIJON'] = {'color': '#029E73', 'marker': '^', 'label': 'AIJON', 'size': 90}
    if not ignore_aijon_nk:
        approaches['AIJON-NK'] = {'color': '#CC78BC', 'marker': 'd', 'label': 'AIJON-NK', 'size': 85}

    # Track which approaches have been labeled for the legend
    labeled_approaches = set()

    # Plot each vulnerability as a horizontal timeline
    for i, vuln_id in enumerate(vuln_ids):
        y_pos = num_vulns - i - 1

        # Draw the timeline with subtle styling
        ax.plot([0, 24], [y_pos, y_pos], color='#CCCCCC', linewidth=1.5,
                zorder=1, alpha=0.6)

        # Plot detection times for each approach
        for approach_name, style in approaches.items():
            time_hours = df_hours.loc[i, approach_name]

            if pd.notna(time_hours):
                # Add label only the first time we plot this approach
                add_label = approach_name not in labeled_approaches
                if add_label:
                    labeled_approaches.add(approach_name)

                if time_hours <= 24:
                    ax.scatter(time_hours, y_pos,
                              color=style['color'],
                              marker=style['marker'],
                              s=style['size'],
                              zorder=3,
                              edgecolors='white',
                              linewidths=1.2,
                              alpha=0.9,
                              label=style['label'] if add_label else '')
                else:
                    # Mark vulnerabilities detected after 24 hours
                    ax.scatter(24, y_pos,
                              color=style['color'],
                              marker='>',
                              s=style['size'],
                              zorder=3,
                              edgecolors='white',
                              linewidths=1.2,
                              alpha=0.7,
                              label=style['label'] if add_label else '')
                    ax.text(24.3, y_pos, f'{time_hours:.1f}h',
                           fontsize=8, va='center', color=style['color'],
                           style='italic')

    # Set up the axes with publication-quality styling
    ax.set_xlim(-0.8, 26)
    ax.set_ylim(-0.5, num_vulns - 0.5)
    ax.set_yticks(range(num_vulns))
    ax.set_yticklabels([vuln_ids[num_vulns - i - 1] for i in range(num_vulns)],
                        fontfamily='monospace')
    ax.set_xlabel('Time (hours)', fontsize=12)
    ax.set_ylabel('Vulnerability ID', fontsize=12)

    # Add clean grid
    ax.set_xticks(range(0, 25, 4))
    ax.set_xticks(range(0, 25, 1), minor=True)
    ax.grid(True, axis='x', alpha=0.25, linestyle='-', linewidth=0.8, color='#DDDDDD')
    ax.grid(True, axis='x', which='minor', alpha=0.15, linestyle='-',
            linewidth=0.5, color='#EEEEEE')
    ax.grid(True, axis='y', alpha=0.1, linestyle='-', linewidth=0.5, color='#EEEEEE')

    # Remove top and right spines for cleaner look
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(0.8)
    ax.spines['bottom'].set_linewidth(0.8)

    # Create custom legend with better styling
    handles, labels = ax.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    legend = ax.legend(by_label.values(), by_label.keys(),
                       loc='upper right',
                       bbox_to_anchor=(0.93, 1.0),
                       frameon=True,
                       fancybox=False,
                       shadow=False,
                       framealpha=0.95,
                       edgecolor='#CCCCCC',
                       borderpad=0.8,
                       labelspacing=0.6,
                       handletextpad=0.5)
    legend.get_frame().set_linewidth(0.8)

    # Adjust layout
    plt.tight_layout()

    # Save the figure
    output_file = '/tmp/vulnerability_detection_timeline.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Chart saved to: {output_file}")

    # Also save as PDF for better quality
    output_pdf = '/tmp/vulnerability_detection_timeline.pdf'
    plt.savefig(output_pdf, bbox_inches='tight')
    print(f"Chart also saved to: {output_pdf}")

    # Display some statistics
    print("\n=== Detection Statistics ===")
    stats_approaches = ['AFL++']
    if not ignore_ijon:
        stats_approaches.append('IJON')
    if not ignore_aijon:
        stats_approaches.append('AIJON')
    if not ignore_aijon_nk:
        stats_approaches.append('AIJON-NK')
    for approach in stats_approaches:
        detected = df_hours[approach].notna().sum()
        within_24h = (df_hours[approach] <= 24).sum()
        print(f"{approach}: {detected} vulnerabilities detected ({within_24h} within 24 hours)")

    # Print comparison statistics
    print("\n=== Comparison Statistics ===")

    # Count rows where IJON < AFL++
    if not ignore_ijon:
        ijon_faster = ((df_hours['IJON'] < df_hours['AFL++']) &
                       df_hours['IJON'].notna() &
                       df_hours['AFL++'].notna()).sum()
        print(f"IJON faster than AFL++: {ijon_faster} vulnerabilities")
        aflpp_faster = ((df_hours['AFL++'] < df_hours['IJON']) &
                        df_hours['AFL++'].notna() &
                        df_hours['IJON'].notna()).sum()
        print(f"AFL++ faster than IJON: {aflpp_faster} vulnerabilities")

    # If AIJON is included, count rows where AIJON < both IJON and AFL++
    if not ignore_aijon:
        if not ignore_ijon:
            aijon_faster_than_both = ((df_hours['AIJON'] < df_hours['IJON']) &
                                       (df_hours['AIJON'] < df_hours['AFL++']) &
                                       df_hours['AIJON'].notna() &
                                       df_hours['IJON'].notna() &
                                       df_hours['AFL++'].notna()).sum()
            print(f"AIJON faster than both IJON and AFL++: {aijon_faster_than_both} vulnerabilities")
        else:
            aijon_faster = ((df_hours['AIJON'] < df_hours['AFL++']) &
                           df_hours['AIJON'].notna() &
                           df_hours['AFL++'].notna()).sum()
            print(f"AIJON faster than AFL++: {aijon_faster} vulnerabilities")

    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Plot vulnerability detection times for MAGMA dataset'
    )
    parser.add_argument('datafile', help='Path to the CSV data file')
    parser.add_argument('--ignore-aijon', action='store_true',
                        help='Exclude AIJON column from the plot and statistics')
    parser.add_argument('--ignore-ijon', action='store_true',
                        help='Exclude IJON column from the plot and statistics')
    parser.add_argument('--ignore-aijon-nk', action='store_true',
                        help='Exclude AIJON-NK column from the plot and statistics')

    args = parser.parse_args()
    main(args.datafile, ignore_aijon=args.ignore_aijon, ignore_ijon=args.ignore_ijon, ignore_aijon_nk=args.ignore_aijon_nk)
