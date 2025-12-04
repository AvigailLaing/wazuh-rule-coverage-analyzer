# src/main.py
from pathlib import Path

from wazuh_parser import parse_wazuh_rules
from wazuh_mapping import (
  load_mitre_techniques,
  map_rules_to_techniques,
  build_coverage_summary,
)


def write_reports(
  mapping_df,
  summary_df,
  output_dir: Path,
) -> None:
    """
    Save CSV files and a simple HTML report.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    mapping_csv = output_dir / "rule_technique_mapping.csv"
    summary_csv = output_dir / "coverage_summary.csv"
    html_file = output_dir / "coverage_report.html"

    mapping_df.to_csv(mapping_csv, index=False)
    summary_df.to_csv(summary_csv, index=False)

    # Debug: show shapes before converting to HTML
    print(f"mapping_df shape: {mapping_df.shape}")
    print(f"summary_df shape: {summary_df.shape}")

    # Build an improved, color-coded summary table (manual HTML)
    import pandas as pd

    s = summary_df.sort_values(["coverage_level", "tactic", "technique_id"]) 
    max_count = max(1, int(s["rule_count"].max()))

    summary_rows = []
    header_cols = ["Technique ID", "Technique Name", "Tactic", "Rule Count", "Coverage"]
    summary_rows.append("".join(f"<th>{c}</th>" for c in header_cols))

    for _, row in s.iterrows():
      tid = row["technique_id"]
      name = row["technique_name"]
      tact = row["tactic"]
      count = int(row["rule_count"]) if not pd.isna(row["rule_count"]) else 0
      level = row["coverage_level"]

      pct = int((count / max_count) * 100)
      bar_html = f"<div class='bar'><div class='fill' style='width: {pct}%;'></div></div>"

      summary_rows.append(
        "<tr class='coverage-{}'>".format(level)
        + f"<td>{tid}</td><td>{name}</td><td>{tact}</td><td style='text-align:center'>{count}</td><td>{bar_html} {level}</td>"
        + "</tr>"
      )

    summary_html = "<table class='summary'><thead><tr>" + summary_rows[0] + "</tr></thead><tbody>" + "\n".join(summary_rows[1:]) + "</tbody></table>"

    # mapping table: use pandas HTML but wrap in a container for styling
    mapping_html = mapping_df.to_html(index=False, classes='mapping')

    # Debug: short preview of generated HTML lengths
    print(f"summary_html length: {len(summary_html)}")
    print(f"mapping_html length: {len(mapping_html)}")

    html = f"""
    <html>
      <head>
        <title>Wazuh Rule Coverage Report</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Rubik:wght@400;600&display=swap" rel="stylesheet">
        <style>
          :root {{
            --bg: #f4f6f8;
            --card: #ffffff;
            --muted: #6b7280;
            --accent: #2563eb;
          }}
          html,body {{ height: 100%; margin: 0; padding: 0; background: var(--bg); font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; color: #0f172a }}
          .container {{ max-width: 1100px; margin: 28px auto; padding: 20px; }}
          header {{ display:flex; align-items:center; gap:16px; margin-bottom:18px }}
          .logo {{ width:56px; height:56px; border-radius:10px; background: linear-gradient(135deg,#2563eb,#7c3aed); box-shadow: 0 6px 18px rgba(12,18,36,0.08); display:flex; align-items:center; justify-content:center; color:white; font-weight:700 }}
          h1 {{ font-family: 'Rubik', 'Inter', sans-serif; font-size:22px; margin:0 }}
          p.lead {{ margin:6px 0 18px 0; color:var(--muted); font-size:14px }}

          .card {{ background: var(--card); border-radius:12px; padding:16px; box-shadow: 0 6px 20px rgba(15,23,42,0.06); margin-bottom:18px }}

          table {{ border-collapse: collapse; width: 100%; }}
          th, td {{ padding: 10px 12px; font-size:14px; border-bottom: 1px solid #eef2f7 }}
          thead th {{ text-align:left; font-size:13px; color:var(--muted); background:transparent; border-bottom: 2px solid #e6eef8 }}

          table.summary thead th {{ text-transform:uppercase; letter-spacing:0.4px }}
          table.summary tbody tr {{ transition: background .12s ease }}

          .coverage-none td {{ background: linear-gradient(90deg, rgba(248,113,113,0.06), transparent) }}
          .coverage-partial td {{ background: linear-gradient(90deg, rgba(251,146,60,0.04), transparent) }}
          .coverage-high td {{ background: linear-gradient(90deg, rgba(34,197,94,0.04), transparent) }}

          .bar {{ height: 12px; background: #f1f5f9; border-radius: 999px; display: inline-block; width: 220px; vertical-align: middle; margin-right: 10px; box-shadow: inset 0 1px 0 rgba(255,255,255,0.6) }}
          .bar .fill {{ height: 100%; border-radius: 999px; background: linear-gradient(90deg,#f97373,#fb923c); transition: width .3s ease }}
          .coverage-high .bar .fill {{ background: linear-gradient(90deg,#34d399,#10b981) }}
          .coverage-partial .bar .fill {{ background: linear-gradient(90deg,#fbbf24,#fb923c) }}
          .coverage-none .bar .fill {{ background: linear-gradient(90deg,#f87171,#ef4444) }}

          .badge {{ display:inline-block; padding:6px 10px; border-radius:999px; font-size:12px; font-weight:600; color:white }}
          .badge-none {{ background: linear-gradient(90deg,#ef4444,#f43f5e) }}
          .badge-partial {{ background: linear-gradient(90deg,#f59e0b,#fb923c) }}
          .badge-high {{ background: linear-gradient(90deg,#10b981,#059669) }}

          .mapping thead th {{ background:transparent }}
          .mapping tbody tr:nth-child(even) {{ background: rgba(2,6,23,0.02) }}
          .mapping td:first-child {{ font-family: 'Courier New', monospace; color: #0f172a; font-weight:600 }}

          @media (max-width:800px) {{ .bar {{ width: 120px }} }}
        </style>
      </head>
      <body>
        <div class='container'>
          <header>
            <div class='logo' aria-hidden="true">
              <!-- Improved shield SVG with gradient and white check mark -->
              <svg width="34" height="34" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <defs>
                  <linearGradient id="g1" x1="0" x2="1">
                    <stop offset="0" stop-color="#2563eb"/>
                    <stop offset="1" stop-color="#7c3aed"/>
                  </linearGradient>
                </defs>
                <!-- Shield base -->
                <path d="M12 2l6 3.5v5.3c0 4.6-3.2 8.9-6 9.9-2.8-1-6-5.3-6-9.9V5.5L12 2z" fill="url(#g1)" />
                <!-- Inner highlight -->
                <path d="M12 4.2l4 2.3v4.1c0 3.4-2.4 6.7-4 7.5-1.6-.8-4-4.1-4-7.5V6.5l4-2.3z" fill="rgba(255,255,255,0.06)" />
                <!-- Check mark -->
                <path d="M9.2 12.5l1.6 1.6 3-3.3" stroke="rgba(255,255,255,0.97)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" fill="none" />
              </svg>
            </div>
            <div>
              <h1>Wazuh Rule Coverage Report</h1>
              <p class='lead'>This report visualizes how Wazuh detection rules map to MITRE ATT&CK techniques.</p>
            </div>
          </header>

          <div class='card'>
            <h2 style='margin:0 0 12px 0; font-size:16px'>Technique Coverage Summary</h2>
            {summary_html}
          </div>

          <div class='card'>
            <h2 style='margin:0 0 12px 0; font-size:16px'>Rule to Technique Mapping</h2>
            {mapping_html}
          </div>
        </div>
      </body>
    </html>
    """

    html_file.write_text(html, encoding="utf-8")
    print(f"Saved {mapping_csv}")
    print(f"Saved {summary_csv}")
    print(f"Saved {html_file}")


def main() -> None:
    base_dir = Path(__file__).resolve().parent.parent
    data_dir = base_dir / "data"
    output_dir = base_dir / "output"

    rules_file = data_dir / "sample_rules.xml"
    mitre_file = data_dir / "mitre_attack.json"

    rules_df = parse_wazuh_rules(rules_file)
    mitre_df = load_mitre_techniques(mitre_file)

    mapping_df = map_rules_to_techniques(rules_df, mitre_df)
    summary_df = build_coverage_summary(mitre_df, mapping_df)

    write_reports(mapping_df, summary_df, output_dir)


if __name__ == "__main__":
    main()
