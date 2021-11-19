import nvdlib
import pandas as pd
from datetime import datetime

AssEnd_Date = 2021-10-25
AssStart_Date = AssEnd_Date - 30

PubStart_Date = AssStart_Date + "00:00"
PubEnd_Date = AssEnd_Date.strftime("%Y-%m-%d") + "23:59"

# Query the CVE's for the application from NVD DB and export to a CSV file
def nvd_to_csv(CPE_Name, FileName):
	r = nvdlib.searchCVE(pubStartDate = PubStart_Date, pubEndDate = PubEnd_Date, cpeName = CPE_Name)

	for eachCVE in r:
		dictionary = {'CVE ID': eachCVE.id, 'CVE Score': str(eachCVE.score[0]), 'CVE Version': eachCVE.score[1], 'Published Date': eachCVE.publishedDate, 'URL': eachCVE.url}

	DF= pd.DataFrame()
	for x in range(len(r)):
		DF_2 = pd.DataFrame(dictionary, index=[x])
		DF = DF.append(DF_2, ignore_index=True)

	DF.to_csv(FileName)

# For each CPE that needs to be searched  pass the required parameters to the nvd_to_csv function
Win10_CPE = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
Win10_FileName = AssEnd_Date.strftime("%Y-%m-%d") + "_win10.csv"
nvd_to_csv(Win10_CPE, Win10_FileName)

WinXP_CPE = "cpe:2.3:o:microsoft:windows_xp:*:*:*:*:*:*:*:*"
WinXP_FileName = AssEnd_Date.strftime("%Y-%m-%d") + "_winXP.csv"
nvd_to_csv(WinXP_CPE, WinXP_FileName)



# REFERENCES
# - https://nvdlib.com/en/latest/
# - https://nvd.nist.gov/developers/vulnerabilities