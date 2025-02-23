# DNS Firewall Checker

A Python utility that checks if DNS queries for a list of websites (FQDNs) are being blocked by DNS firewall services such as Quad9 and Cloudflare Malware Blocking. The script leverages DNS over HTTPS (DoH) to bypass interference from local security services like enterprise DNS servers or network firewalls.

## Features

- Reads a list of fully qualified domain names (FQDNs) from a text file (`fqdns.txt`).
- Performs DNS queries using DoH endpoints for enhanced privacy and to bypass local DNS restrictions.
- Supports testing against multiple DNS providers:
  - Quad9
  - Cloudflare Security service
- Supports retrieving additional DNS resolution information (e.g., Google and Cloudflare IPs).
- Outputs results in a CSV format with semicolon (;) separated values.

## Output Format

The output is a CSV file with the following format:

query;quad9;cloudflare_security;google_ips;cloudflare_ips  
example.com;OK;OK;1.2.3.4,1.2.3.5;4.5.6.7,4.5.6.8

- **query** – Domain name queried.
- **quad9** – Result of the DNS query through Quad9's DoH service.
- **cloudflare_security** – Result through Cloudflare's security focused DoH endpoint.
- **google_ips** – Comma-separated list of IPs returned from Google (if used).
- **cloudflare_ips** – Comma-separated list of IPs returned from Cloudflare (if used).

## Requirements

- Python 3.6 or higher
- Required Python packages:
  - `requests` for making HTTP requests to DoH endpoints.

Install the dependencies using pip:

  pip install requests

## Usage

1. **Prepare the fqdns.txt file**

   Create a file named `fqdns.txt` in the project directory. Add one fully qualified domain name per line. For example:

       example.com
       example.org
       google.com

2. **Configure or customize DoH endpoints**

   The script is pre-configured to use specific DoH endpoints for Quad9, Cloudflare, Google, etc. You can edit the script to add or modify endpoints as needed.

3. **Run the Script**

   Execute the script from the command line:

       python dns_firewall_checker.py

   The script will read the domains from `fqdns.txt` and output CSV format results (either to the terminal or as a file, depending on your modifications).

## How It Works

- The script reads each domain from the `fqdns.txt` file.
- For each domain, the script sends DNS queries via DoH to pre-configured endpoints for:
  - Quad9
  - Cloudflare Security (and optionally others like Google)
- The responses are analyzed to determine if the query was successful (output "OK") or if it was blocked or tampered with.
- Finally, the results for each domain are compiled into a semicolon-separated CSV format.

## Example

Assuming `fqdns.txt` contains:

    example.com
    example.net

The resulting output may look like:

    query;quad9;cloudflare_security;google_ips;cloudflare_ips
    example.com;OK;OK;1.2.3.4,1.2.3.5;4.5.6.7,4.5.6.8
    example.net;OK;BLOCKED;1.2.3.6,1.2.3.7;4.5.6.9,4.5.6.10

## Customization

- **Logging and Error Handling:**  
  Modify the script to enhance logging, add exception handling, or write output to a file.
  
- **Additional Endpoints:**  
  You can expand the script to include additional DoH endpoints. Update the code to send queries and parse responses accordingly.

- **Output Format:**  
  While the default is CSV, you can modify the script to output JSON or any other preferred format.

## Contributing

Contributions are welcome! If you have ideas for improvements or bug fixes, feel free to fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This script is provided for informational and educational purposes only. The authors are not responsible for any misuse or damage caused by running this script.

Happy querying!
