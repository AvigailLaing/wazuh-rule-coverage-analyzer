from pathlib import Path
import xml.etree.ElementTree as ET
import pandas as pd


def parse_wazuh_rules(rules_path: Path) -> pd.DataFrame:
    """
    Read a Wazuh XML rules file and return a DataFrame
    with rule_id, description, and group columns.
    """
    # Debug: confirm file exists and size before parsing
    print(f"Parsing XML: {rules_path}, exists={rules_path.exists()}, size={(rules_path.stat().st_size if rules_path.exists() else 'N/A')}")

    # Use the standard library XML parser for simplicity and to avoid
    # potential lxml parsing/environment issues in user environments.
    tree = ET.parse(str(rules_path))
    rules = []

    for rule in tree.findall(".//rule"):
        rule_id = rule.get("id", "").strip()
        description = (rule.findtext("description") or "").strip()
        group = (rule.findtext("group") or "").strip()

        rules.append(
            {
                "rule_id": rule_id,
                "description": description,
                "group": group,
            }
        )

    df = pd.DataFrame(rules)
    return df


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent
    rules_file = base_dir / "data" / "sample_rules.xml"
    df = parse_wazuh_rules(rules_file)
    print(df)
