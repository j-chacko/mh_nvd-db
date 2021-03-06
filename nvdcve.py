import nvdlib
import csv
import argparse
import os
from datetime import datetime


# Query the CVE's for the application from NVD DB and export to a CSV file
def nvdCVESearch(startDate, endDate, cpeName, fileName):
    r = nvdlib.searchCVE(pubStartDate=startDate.strftime("%Y-%m-%d") +" 00:00",
                         pubEndDate=endDate.strftime("%Y-%m-%d") + " 23:59", cpeName=cpeName, cpe_dict=True)

    # A place to store all the dictionaries that will be made next
    listOfDicts = []

    for eachCVE in r:
        # Making the dictionary
        dictionary = {'CVE ID': eachCVE.id, 'v3 Severity': eachCVE.v3severity, 'CVE Score': str(eachCVE.score[0]),
                      'CVE Version': eachCVE.score[1], 'CVE Description': eachCVE.cve.description.description_data[0].value,
                      'Published Date': eachCVE.publishedDate, 'URL': eachCVE.url,
                      'CPE Name': eachCVE.configurations.nodes[0].cpe_match}
        listOfDicts.append(dictionary)  # Adding the dictionary to the list to store them.

    # Open/create the file using the filename variable
    with open(fileName, 'w', newline='') as file:

        # Define the first row / column headers
        headers = [
            'CVE ID',
            'v3 Severity',
            'CVE Score',
            'CVE Version',
            'CVE Description',
            'Published Date',
            'URL',
            'CPE Name'
        ]

        writer = csv.DictWriter(file,
                                fieldnames=headers)  # Use dictWriter on the open file and assign the column headers
        writer.writeheader()  # Write the header row

        if r:  # If the request actually returns results then continue (the windows XP request does not return any results)
            for eachDict in listOfDicts:  # Iterate through the list that contains all of the dictionaries we made
                writer.writerow(eachDict)  # Write each dictionary to the file as a CSV


def validate_file(f):
    if not os.path.exists(f):
        # Argparse uses the ArgumentTypeError to give a rejection message like:
        # error: argument input: x does not exist
        raise argparse.ArgumentTypeError("{0} does not exist".format(f))
    return f


inputFile = ''
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search the NVD DB and return CVE's")
    parser.add_argument("-i", "--input", dest="inputFile", required=True, type=validate_file,
                        help="input file", metavar="FILE")
    args = parser.parse_args()
    inputFile = args.inputFile

# Read the variable file with the parameters
with open(inputFile, newline='') as csvFile:
    file = csv.reader(csvFile, delimiter=',')
    for line in file:
        startDate = datetime.strptime(line[0], "%Y-%m-%d")
        endDate = datetime.strptime(line[1], "%Y-%m-%d")
        cpeName = line[2]
        fileName = line[3] + "_" + endDate.strftime("%Y-%m-%d") + ".csv"
        nvdCVESearch(startDate, endDate, cpeName, fileName)


# REFERENCES
# - https://nvdlib.com/en/latest/
# - https://nvd.nist.gov/developers/vulnerabilities
