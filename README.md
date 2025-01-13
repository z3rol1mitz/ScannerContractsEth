Smart Contract Vulnerability Scanner

This tool allows you to scan cryptocurrency and memecoin smart contracts for security vulnerabilities.

Features

Contract analysis using Slither and Mythril
Support for analyzing contracts by address or file
Detailed report generation
Classification of vulnerabilities by severity
Export of results to a file
Requirements
pip install -r requirements.txt

You will also need to install solc:
solc-select install 0.8.19
solc-select use 0.8.19

Usage
To scan a contract by its address:
python smart_contract_scanner.py 0x123...abc

To scan a contract file:
python smart_contract_scanner.py path/to/contract.sol

Report
The scanner will generate a detailed report that includes:

Date and time of the analysis
Details of the analyzed contract
List of vulnerabilities found
Severity of each vulnerability
Detailed description of each issue
![Captura de pantalla 2025-01-13 152500](https://github.com/user-attachments/assets/023a5767-862f-4e9c-b058-e8b132ef95a8)
