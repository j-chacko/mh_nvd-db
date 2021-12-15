# Export CVE's from http://nvd.nist.gov

1. Uses the [nvdlib module](https://nvdlib.com/en/latest/)
2. nvdcpe.py - Returns a list of CPE strings that matches the keywords passed, as CSV
3. nvdcpe.py - Returns CVE's announced for a given date range that matches the CPE string provided
4. xlsxtojson.py - Converts a given XLSX file to JSON format
