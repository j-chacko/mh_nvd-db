import sys
import argparse
import xml.etree.ElementTree as ET


def main(argv):
    inputfile = ''
    outputfile = ''
    parser = argparse.ArgumentParser(description="Parse Nmap XML output and create CSV")
    parser.add_argument('inputfile', help='The XML File')
    parser.add_argument('outputfile', help='The output csv filename')
    parser.add_argument('-n', '--noheaders', action='store_true',
                        help='This flag removes the header from the CSV output File')
    args = parser.parse_args()
    inputfile = args.inputfile
    outputfile = args.outputfile

    try:
        tree = ET.parse(inputfile)
        root = tree.getroot()
    except ET.ParseError as e:
        print("Parse error({0}): {1}".format(e.errno, e.strerror))
        sys.exit(2)
    except IOError as e:
        print("IO error({0}): {1}".format(e.errno, e.strerror))
        sys.exit(2)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(2)

    fo = open(outputfile, 'w+')
    if (args.noheaders != True):
        out = "ip" + ',' + "hostname" + ',' + "osver" + '\n'
        fo.write(out)

    for host in root.findall('host'):
        ip = host.find('address').get('addr')
        osver = ""
        isUp = host.find('status').get('state')
        hostname = ""
        if isUp != "down":
            if host.find('hostnames') is not None:
                if host.find('hostnames').find('hostname') is not None:
                    hostname = host.find('hostnames').find('hostname').get('name')
                for child in host:
                    for children in child.findall('.//'):
                        osver = str(children.text)

        out = ip + ',' + hostname + ',' + osver + '\n'
        fo.write(out)

    fo.close()


if __name__ == "__main__":
    main(sys.argv)

# Credits for the code:
# - https://github.com/AccentureTVM/Python-Nmap-XML-to-CSV