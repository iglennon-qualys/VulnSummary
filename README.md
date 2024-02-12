# Vulnerability Summary

## Overview

This script will read an input file containing a list of hostnames in column 0 (i.e. the first column in the CSV input).
For each hostname in the input file, the script will write the hostname and a summary of the vulnerability counts
per QDS category (Critical, High, Medium and Low).  A Totals line is included at the last line of the output file
containing totals for each of the four categories.

## Usage

>python vuln_summary.py -h 
usage: vuln_summary.py [-h] [-f INPUT_FILE] [-u USER] [-p PASSWORD] [-a API_URL] [-P PROXY_URL] [-o OUTPUT_FILE] [-d]

options:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --input_file INPUT_FILE
                        CSV file containing hostnames to summarize
  -u USER, --user USER  Qualys username
  -p PASSWORD, --password PASSWORD
                        Qualys password, or '-' for safe interactive prompt
  -a API_URL, --api_url API_URL
                        Qualys API Base URL (e.g. https://qualysapi.qualys.com
  -P PROXY_URL, --proxy_url PROXY_URL
                        Proxy URL (optional)
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        CSV output filename
  -d, --debug           Enable debug output for API calls
