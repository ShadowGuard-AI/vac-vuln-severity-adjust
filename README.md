# vac-vuln-severity-adjust

Adjusts a CVSSv3 base score based on user-defined rules. It parses the vector with the `cvss3` library, takes the parsed base score (or an operator supplied override), adds the adjustment for every rule whose single metric:value component matches the vector exactly, rounds to one decimal place, and clamps the result to the 0.0 to 10.0 range. It does not fetch, aggregate, or correlate vulnerability data from any external source.

A run with an invalid vector, a missing or malformed rules file, a rule key that is not a single metric:value component, a non-numeric or boolean rule value, an override outside 0.0 to 10.0, or a report path that resolves to the rules file exits non-zero.

## Install
`git clone https://github.com/ShadowGuard-AI/vac-vuln-severity-adjust`

## Usage
`python3 main.py -v "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -s severity_adjustments.json [-o 5.0] [-r report.json]`

The rules file is a JSON object mapping one metric:value component to a numeric adjustment, for example `{"AV:N": 0.5, "AC:L": -0.2}`. Boolean values are rejected, even though JSON `true` would otherwise parse as a number in Python.

## Parameters
- `-h`: Show help message and exit
- `-v`: CVSSv3 vector string (required), for example `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- `-s`: JSON file containing severity adjustment rules (required)
- `-o`: Override the CVSSv3 base score with this value (0.0 to 10.0). The override replaces the base score before adjustments are applied.
- `-d`: Enable debug logging.
- `-q`: Suppress informational output.
- `-r`: Path to the report file. The report is JSON containing the vector, the rules, the override (or null), and the adjusted score. It must not resolve to the rules file.

## License
Copyright (c) ShadowGuardAI
