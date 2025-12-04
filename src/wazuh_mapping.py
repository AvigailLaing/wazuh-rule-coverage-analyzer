from pathlib import Path
import json
import pandas as pd


def load_mitre_techniques(mitre_path: Path) -> pd.DataFrame:
    """
    Load a small MITRE ATT&CK dataset from JSON.
    Expected format: list of dicts with
    technique_id, technique_name, tactic, keywords (list).
    """
    with open(mitre_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return pd.DataFrame(data)


def map_rules_to_techniques(
    rules_df: pd.DataFrame, mitre_df: pd.DataFrame
) -> pd.DataFrame:
    """
    For each rule, try to match it to one or more MITRE techniques
    based on simple keyword search in the rule description or group.
    Returns a DataFrame with one row per (rule, technique) match.
    """
    mappings = []

    for _, rule in rules_df.iterrows():
        desc = str(rule["description"]).lower()
        group = str(rule["group"]).lower()

        for _, tech in mitre_df.iterrows():
            keywords = tech.get("keywords", [])
            hit = False

            for kw in keywords:
                kw_lower = kw.lower()
                if kw_lower in desc or kw_lower in group:
                    hit = True
                    break

            if hit:
                mappings.append(
                    {
                        "rule_id": rule["rule_id"],
                        "rule_description": rule["description"],
                        "technique_id": tech["technique_id"],
                        "technique_name": tech["technique_name"],
                        "tactic": tech["tactic"],
                    }
                )

    mapped_df = pd.DataFrame(mappings)
    return mapped_df


def build_coverage_summary(
    mitre_df: pd.DataFrame, mapped_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Take the full MITRE list and the rule-to-technique mapping
    and compute coverage per technique.
    Coverage levels:
      - none:    0 rules
      - partial: 1 rule
      - high:    2 or more rules
    """
    coverage_counts = (
        mapped_df.groupby("technique_id")["rule_id"]
        .nunique()
        .reset_index(name="rule_count")
    )

    summary = mitre_df.merge(coverage_counts, on="technique_id", how="left")
    summary["rule_count"] = summary["rule_count"].fillna(0).astype(int)

    def coverage_label(n: int) -> str:
        if n == 0:
            return "none"
        if n == 1:
            return "partial"
        return "high"

    summary["coverage_level"] = summary["rule_count"].apply(coverage_label)
    return summary


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent
    mitre_file = base_dir / "data" / "mitre_attack.json"

    # tiny self test
    mitre = load_mitre_techniques(mitre_file)
    print(mitre)
