# Auto_Nuclei
Tool, that runs custom nuclei scripts on a target automatically. Collects Subdomains and endpoints prior.

# Requirements
The following tools need to be installed:
- [reconftw](https://github.com/six2dez/reconftw)
- [urldedupe](https://github.com/ameenmaali/urldedupe)
- [pathi_generator]()
- [waymore](https://github.com/xnl-h4ck3r/waymore)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [gf](https://github.com/tomnomnom/gf)
- [payloads_generator]()
- discord webhook for notifications

  # Setup
  Add your discord ID and Token to the variable section at the top of the script. You might change the directory structure as well to fit your needs and preferences.
  Make sure the nuclei templates and wordlists are in the right place.

  # What does it do?
  1. Collect endpoints from reconftw. If reconftw was not run before, it runs waymore to collect them (faster). Sorts endpoints after.
  2. Sets up a custom file with endpoints to run custom nuclei on, sorted by vuln type.
  3. Sends results to discord webhook.
