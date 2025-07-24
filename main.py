import argparse
import logging
import sys
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

def adjust_severity(cvss_vector: str, adjustments: Dict[str, float]) -> Optional[float]:
    """
    Adjusts the CVSSv3 base score based on user-defined rules.

    Args:
        cvss_vector: The CVSSv3 vector string.
        adjustments: A dictionary containing severity adjustment rules.

    Returns:
        The adjusted CVSSv3 base score, or None if an error occurs.
    """
    try:
        # Parse the CVSSv3 vector
        parsed_vector = cvss3.parse_vector(cvss_vector)

        # Get the base score from the parsed vector
        base_score = parsed_vector.base_score

        # Apply adjustments based on vector components
        for component, adjustment in adjustments.items():
            if component in cvss_vector:
                base_score += adjustment

        # Ensure the adjusted score remains within the valid range (0.0-10.0)
        base_score = max(0.0, min(10.0, base_score))

        return base_score
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

    # Perform severity adjustment
    adjusted_score = adjust_severity(args.vector, adjustments)

    if adjusted_score is not None:
        if args.override_base_score is not None:
             adjusted_score = float(args.override_base_score)
        logging.info(f"Adjusted CVSS Base Score: {adjusted_score}")
        if args.report:
            try:
                with open(args.report, "w") as f:
                    f.write(f"{adjusted_score}")
                logging.info(f"Report saved to {args.report}")

            except Exception as e:
                logging.error(f"Error writing to report file: {e}")

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