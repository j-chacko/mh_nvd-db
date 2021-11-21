import nvdlib
import csv
from datetime import datetime


# Query the CVE's for the application from NVD DB and export to a CSV file
def nvdToCSV(startDate, endDate, cpeName, fileName):
    r = nvdlib.searchCVE(pubStartDate=startDate.strftime("%Y-%m-%d") +" 00:00",
                         pubEndDate=endDate.strftime("%Y-%m-%d") + " 23:59", cpeName=cpeName)

    # A place to store all the dictionaries that will be made next
    listOfDicts = []

    for eachCVE in r:
        # Making the dictioanary
        dictionary = {'CVE ID': eachCVE.id, 'CVE Score': str(eachCVE.score[0]), 'CVE Version': eachCVE.score[1],
                      'Published Date': eachCVE.publishedDate, 'URL': eachCVE.url}
        listOfDicts.append(dictionary)  # Adding the dictionary to the list to store them.

    # Open/create the file using the filename variable
    with open(fileName, 'w', newline='') as file:

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


# Read the variable file with the CPE list
with open('var.csv', newline='') as csvfile:
    file = csv.reader(csvfile, delimiter=',')
    for line in file:
        startDate = datetime.strptime(line[0], "%Y-%m-%d")
        endDate = datetime.strptime(line[1], "%Y-%m-%d")
        cpeName = line[2]
        fileName = line[3] + endDate.strftime("%Y-%m-%d") + ".csv"
        nvdToCSV(startDate, endDate, cpeName, fileName)


# REFERENCES
# - https://nvdlib.com/en/latest/
# - https://nvd.nist.gov/developers/vulnerabilities
