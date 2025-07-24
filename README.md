# vac-vuln-severity-Adjust
Adjusts vulnerability severity scores based on user-defined rules using CVSS vectors. Allows overriding CVSSv3 base scores to better reflect the organization's specific risk profile. Uses the `cvss3` library to parse the CVSS vector and modify the base score accordingly. - Focused on Aggregates vulnerability data from multiple sources (e.g., NVD, ExploitDB) and correlates it based on CPE or product names, presenting a unified view of potential risks. Prioritizes vulnerabilities based on common metrics and provides a summary of potential impact.

## Install
`git clone https://github.com/ShadowGuardAI/vac-vuln-severity-adjust`

## Usage
`./vac-vuln-severity-adjust [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-s`: JSON file containing severity adjustment rules. e.g. 
- `-o`: Override the CVSSv3 base score with this value.
- `-d`: Enable debug logging.
- `-q`: Suppress informational output.
- `-r`: Path to the report file to store the result.

## License
Copyright (c) ShadowGuardAI
