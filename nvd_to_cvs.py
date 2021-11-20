import nvdlib
import csv
from datetime import datetime, timedelta, date


# The date has to be imported as a datetime object to be able to subtract days.
AssStart_Date = date(2021, 9, 26)
AssEnd_Date = date(2021, 10, 25)
# AssStart_Date = AssEnd_Date - timedelta(days=30)  # Subtract 30 days


PubStart_Date = AssStart_Date.strftime("%Y-%m-%d") + " 00:00"  # Added space in time string
PubEnd_Date = AssEnd_Date.strftime("%Y-%m-%d") + " 23:59"


# Query the CVE's for the application from NVD DB and export to a CSV file
def nvd_to_csv(CPE_Name, FileName):
    r = nvdlib.searchCVE(pubStartDate=PubStart_Date, pubEndDate=PubEnd_Date, cpeName=CPE_Name)

    # A place to store all the dictionaries that will be made next
    listOfDicts = []

    for eachCVE in r:
        # Making the dictioanary
        dictionary = {'CVE ID': eachCVE.id, 'CVE Score': str(eachCVE.score[0]), 'CVE Version': eachCVE.score[1],
                      'Published Date': eachCVE.publishedDate, 'URL': eachCVE.url}
        listOfDicts.append(dictionary)  # Adding the dictionary to the list to store them.

    # Open/create the file using the filename variable
    with open(FileName, 'w', newline='') as file:

        # Define the first row / column headers
        headers = [
            'CVE ID',
            'CVE Score',
            'CVE Version',
            'Published Date',
            'URL'
        ]

        writer = csv.DictWriter(file,
                                fieldnames=headers)  # Use dictWriter on the open file and assign the column headers
        writer.writeheader()  # Write the header row

        if r:  # If the request actually returns results then continue (the windows XP request does not return any results)
            for eachDict in listOfDicts:  # Iterate through the list that contains all of the dictionaries we made
                writer.writerow(eachDict)  # Write each dictionary to the file as a CSV


# For each CPE that needs to be searched  pass the required parameters to the nvd_to_csv function
Win10_CPE = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
Win10_FileName = AssEnd_Date.strftime("%Y-%m-%d") + "_win10.csv"
nvd_to_csv(Win10_CPE, Win10_FileName)

WinXP_CPE = "cpe:2.3:o:microsoft:windows_xp:-:*:*:*:*:*:*:*"
WinXP_FileName = AssEnd_Date.strftime("%Y-%m-%d") + "_winXP.csv"
nvd_to_csv(WinXP_CPE, WinXP_FileName)

Win2012R2_CPE = "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*"
Win2012R2_FileName = AssEnd_Date.strftime("%Y-%m-%d") + "_win2012R2.csv"
nvd_to_csv(Win2012R2_CPE, Win2012R2_FileName)

# REFERENCES
# - https://nvdlib.com/en/latest/
# - https://nvd.nist.gov/developers/vulnerabilities