import argparse
import logging
import sys
import re
from pathlib import Path
from typing import Dict, Optional
import cvss3
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Adjusts vulnerability severity scores based on user-defined rules and CVSS vectors.")

    # Required arguments
    parser.add_argument("-v", "--vector", required=True, help="CVSSv3 vector string (e.g., AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)")
    parser.add_argument("-s", "--severity-adjustments", required=True, help="JSON file containing severity adjustment rules. e.g. '{\"AV:N\": 0.5, \"AC:L\": -0.2}'")
    parser.add_argument("-o", "--override-base-score", type=float, help="Override the CVSSv3 base score with this value.", required=False)

    # Optional arguments
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output.")
    parser.add_argument("-r", "--report", type=str, help="Path to the report file to store the result.", required=False)


    return parser

def load_severity_adjustments(file_path: str) -> Dict[str, float]:
    """
    Loads severity adjustment rules from a JSON file.

    Args:
        file_path: Path to the JSON file.

    Returns:
        A dictionary containing the severity adjustment rules.
    """
    try:
        with open(file_path, "r") as f:
            adjustments = json.load(f)
            #Input validation
            if not isinstance(adjustments, dict):
                raise ValueError("Invalid format in severity adjustments file: Expected a dictionary.")

            for key, value in adjustments.items():
                # A boolean slips through the number check, again because bool is an int in Python. An adjustment written as true would add one point, and nothing in the output would say the rules file held a word instead of a number.
                if not isinstance(key, str) or not isinstance(value, (int, float)):
                    raise ValueError("Invalid format in severity adjustments file: Keys must be strings and values must be numbers.")

            return adjustments
    except FileNotFoundError:
        logging.error(f"Error: Severity adjustments file not found at {file_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error(f"Error: Invalid JSON format in severity adjustments file at {file_path}")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"Error: {e}")
        sys.exit(1)

def parse_vector_components(cvss_vector: str) -> Dict[str, str]:
    """Parses a CVSS vector string into a metric to value mapping."""
    text = cvss_vector.strip()
    if text.startswith("CVSS:"):
        text = text.split("/", 1)[1] if "/" in text else ""
    components = {}
    for part in text.split("/"):
        if ":" not in part:
            raise ValueError(f"Invalid vector component: {part}")
        metric, value = part.split(":", 1)
        components[metric] = value
    return components

def adjust_severity(cvss_vector: str, adjustments: Dict[str, float], override_base_score: Optional[float] = None) -> Optional[float]:
    """
    Adjusts the CVSSv3 base score based on user-defined rules.
    Rule keys must be a single metric:value component and match the
    parsed vector components exactly. When an override is given it
    replaces the base score before the adjustments are applied.
    """
    try:
        parsed_vector = cvss3.parse_vector(cvss_vector)
        components = parse_vector_components(cvss_vector)
        base_score = float(override_base_score) if override_base_score is not None else parsed_vector.base_score
        for component, adjustment in adjustments.items():
            if not re.fullmatch(r"[A-Z]+:[A-Z]+", component or ""):
                logging.error(f"Error: Adjustment rule key {component!r} is not a single metric:value component; the run was not scored.")
                return None
            metric, value = component.split(":", 1)
            if components.get(metric) == value:
                base_score += adjustment
        adjusted = round(base_score, 1)
        adjusted = max(0.0, min(10.0, adjusted))
        return round(adjusted, 1)
    except cvss3.exceptions.CVSS3Error as e:
        logging.error(f"Error: Invalid CVSS vector: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to execute the vulnerability severity adjustment tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging level based on arguments
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.ERROR)  # Only log errors
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Input validation for override base score
    if args.override_base_score is not None:
        if not (0.0 <= args.override_base_score <= 10.0):
            logging.error("Error: Override base score must be between 0.0 and 10.0.")
            sys.exit(1)


    # Load severity adjustments from file
    adjustments = load_severity_adjustments(args.severity_adjustments)

    if args.report and Path(args.report).resolve() == Path(args.severity_adjustments).resolve():
        logging.error("Error: Report path resolves to the severity adjustments file; refusing to overwrite it.")
        sys.exit(1)

    # Perform severity adjustment; the override, when given, replaces
    # the base score before adjustments are applied.
    adjusted_score = adjust_severity(args.vector, adjustments, args.override_base_score)

    if adjusted_score is not None:
        if args.override_base_score is not None:
            logging.info(f"Adjusted CVSS Base Score: {adjusted_score} (override base score {args.override_base_score} applied before adjustments)")
        else:
            logging.info(f"Adjusted CVSS Base Score: {adjusted_score}")
        if args.report:
            try:
                with open(args.report, "w") as f:
                    # The report is the bare number with no vector, no rules, and no newline. Anyone reading it later cannot tell which finding it belonged to, and a failed write here is only logged while the run still ends as success.
                    f.write(f"{adjusted_score}")
                logging.info(f"Report saved to {args.report}")

            except Exception as e:
                logging.error(f"Error writing to report file: {e}")
                sys.exit(1)

    else:
        sys.exit(1)  # Exit with an error code if adjustment failed

if __name__ == "__main__":
    # Example Usage
    # python vac-vuln-severity-Adjust.py -v "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -s severity_adjustments.json
    # severity_adjustments.json example:
    # {
    #   "AV:N": 0.5,
    #   "AC:L": -0.2
    # }
    main()
