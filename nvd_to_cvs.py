import nvdlib
import pandas as pd

pubStart_Date = "2021-09-26 00:00"
pubEnd_Date = "2021-10-25 23:59"

# Query the CVE's for the application from NVD DB and export to a CSV file
def nvd_to_csv(CPE_Name, FileName):
	r = nvdlib.searchCVE(pubStartDate = pubStart_Date, pubEndDate = pubEnd_Date, cpeName = CPE_Name)

	for eachCVE in r:
		dictionary = {'CVE ID': eachCVE.id, 'CVE Score': str(eachCVE.score[0]), 'CVE Version': eachCVE.score[1], 'Published Date': eachCVE.publishedDate, 'URL': eachCVE.url}

	df= pd.DataFrame()
	for x in range(len(r)):
		df_2 = pd.DataFrame(dictionary, index=[x])
		df = df.append(df_2, ignore_index=True)

	df.to_csv(FileName)

# For each CPE that needs to be searched  pass the required parameters to the nvd_to_csv function
Win10_CPE = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
Win10_FileName = "2021-10-25_win10.csv"
nvd_to_csv(Win10_CPE, Win10_FileName)

WinXP_CPE = "cpe:2.3:o:microsoft:windows_xp:*:*:*:*:*:*:*:*"
WinXP_FileName = "2021-10-25_winXP.csv"
nvd_to_csv(WinXP_CPE, WinXP_FileName)



# REFERENCES
# - https://pythonguides.com/python-write-a-list-to-csv/
# - https://stackoverflow.com/questions/17839973/constructing-pandas-dataframe-from-values-in-variables-gives-valueerror-if-usi
# - https://stackoverflow.com/questions/59775512/why-is-my-output-only-one-row-when-i-try-outputting-my-dataframe-to-a-csv-filep
# - https://nvdlib.com/en/latest/
# - https://nvd.nist.gov/developers/vulnerabilities