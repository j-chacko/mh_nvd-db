import nvdlib
import csv
import argparse, os
from datetime import datetime


# Query the keywords from the NVD DB to return the CPE Names and export to a CSV file
def nvdCPESearch(fileName, keyWord):
    r = nvdlib.searchCPE(keyword=keyWord, includeDeprecated=True, cves=True)

    # A place to store all the dictionaries that will be made next
    listOfDicts = []

    for eachCPE in r:
        # Making the dictionary
        dictionary = {'CPE Name': eachCPE.name}
        listOfDicts.append(dictionary)  # Adding the dictionary to the list to store them.

    # Open/create the file using the filename variable
    with open(fileName, 'w', newline='') as file:

        # Define the first row / column headers
        headers = [
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


todayDate = datetime.today()
fileName = "CPENames_" + datetime.strftime(todayDate, "%Y%m%d%H%M%S") + ".csv"


inputFile = ''
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search the NVD DB and return CVE's")
    parser.add_argument("-i", "--input", dest="inputFile", required=True, type=validate_file,
                        help="input file", metavar="FILE")
    args = parser.parse_args()
    inputFile = args.inputFile

# Read the variable file with the paramters
with open(inputFile, newline='') as csvFile:
    file = csv.reader(csvFile, delimiter=',')
    for line in file:
        keyWord = line[0]
        nvdCPESearch(fileName, keyWord)


# REFERENCES
# - https://nvdlib.com/en/latest/
# - https://nvd.nist.gov/developers/vulnerabilities
