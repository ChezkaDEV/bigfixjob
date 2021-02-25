'''
BigFix Data Pull
Chezka Eusebio
Sept 2018: VERSION 1

Description: This script gets the BigFix computer IDs, retreives computer ID information and pushes to RDS
'''

# libraries used
import requests
import sys
import json
import xml.etree.ElementTree as ET
import urllib3
import io
from DBconn import BFDatabaseUpsert
from DBconn import dbInfo
from ADLookup import getInfo
from ADLookup import ADConn

# Warning Silenter: Change once CA has proper ssl: 
# https://urllib3.readthedocs.io/en/latest/user-guide.html#ssl
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# nested list of all computers
matrix = []
        
def generalBFData(user, passwd):
    print("Getting General Big Fix Data...")

    # massive
    queryURL = 'https://xx.xx.xx.xxx:00000/api/query?output=json&relevance=(id of it, name of it | "[name not reported]", last report time of it, (concatenation " " of values of result (it, bes properties "IP Address") | "[ip address not reported]"), (operating system of it | "[operating system not reported]"), (concatenation " " of values of result (it, bes properties "Symantec AntiVirus Client Version") | "[AV not reported]"), (concatenation " " of values of result (it, bes properties "Symantec State") | "[SEP not running]"), (concatenation " " of values of result (it, bes properties "SEP Definitions") | "[No Updates Found]"), (concatenation " " of values of result (it, bes properties "BitLocker - Encryption Status") | "[No Encryption Found]"), (concatenation " " of values of result (it, bes properties "BitLocker Protection Status") | "[No Encryption Found]"), (concatenation " " of values of result (it, bes properties "BitLocker - Unlock Method") | "[No Encryption Found]"), (concatenation " " of values of result (it, bes properties "Deep Instinct Version") | "[DI not installed]"), (concatenation " " of values of result (it, bes properties "Deep Instinct Service State") | "[DI not installed]"), (concatenation " " of values of result (it, bes properties "MS Fixlets Missing") | "[Not Windows]"), (concatenation " " of values of result (it, bes properties "User Name") | "[Not Windows]"), (concatenation " " of values of result (it, bes properties "_BESClient_Installer") | "[None]"), (concatenation " " of values of result (it, bes properties "Is Windows Laptop?") | "[None]")) of bes computers'

    # get response and put in a json obj
    try:
        computersJSON = requests.get(queryURL, auth=(user, passwd), verify = False).text
        CompJSONObj = json.loads(computersJSON)    
        print("Got the response from Bigfix!")
    except Exception as e:
        print(e)

    # returns a JSON object and parses through to single out each entry
    count = 0
    print("Oject parsing started...")
    for x in CompJSONObj:
        try:
            for eachComp in CompJSONObj[x]:
                count = count + 1
                # print(eachComp)
                # print()
                try:
                    # get all general BF Data
                    computerID = eachComp[0]
                    computerName = eachComp[1]
                    computerLastReportTime = eachComp[2]
                    computerIPAddress = eachComp[3]
                    computerOSType = eachComp[4]

                    SEPAV_Version = eachComp[5]                    
                    SEPServiceState = eachComp[6]
                    SEPDefinitions = eachComp[7]

                    bitLockerEncryptionStatus = eachComp[8]
                    bitLockerProtectionStatus = eachComp[9]
                    bitLockerUnlockMethod = eachComp[10]

                    DI_Version = eachComp[11]
                    DI_ServiceState = eachComp[12]

                    MS_FixletsMissing = eachComp[13]
                    coreID = eachComp[14]
                    acquisition = eachComp[15]
                    isWindows = eachComp[16]

                    # append to matrix with assigned variable
                    # [2576556, 'NLYON-LT', 'Thu, 31 Oct 2019 11:28:44 -0400', '000.000.0.0 000.000.0.0 000.000.0.0 000.000.0.0', 'Win8 6.2.15063', '<Not Installed>', 'Not Installed', '', 'Fully Encrypted', 'BitLocker Encrypted', 'Numeric Password', 'Does not exist', 'Not Installed', '29', 'nlyon', 'Spillman', 'Yes']
                    matrix.append([
                        "computerID=" + str(computerID), 
                        "computerName=" + computerName, 
                        "computerLastReportTime=" + str(computerLastReportTime), 
                        "computerIPAddress=" + str(computerIPAddress), 
                        "computerOSType=" + computerOSType,

                        "SEPAV_Version=" + str(SEPAV_Version),
                        "SEPServiceState=" + SEPServiceState,
                        "SEPDefinitions=" + SEPDefinitions,

                        "bitLockerEncryptionStatus=" + bitLockerEncryptionStatus,
                        "bitLockerProtectionStatus=" + bitLockerProtectionStatus,
                        "bitLockerUnlockMethod=" + bitLockerUnlockMethod,

                        "DI_Version=" + DI_Version,
                        "DI_ServiceState=" + DI_ServiceState,

                        "MS_FixletsMissing=" + MS_FixletsMissing,
                        "coreID=" + coreID,
                        "acquisition=" + acquisition,
                        "isWindows=" + isWindows
                    ])
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)
    print("count= ", count)
    print("... completed.")

def main():
    # BF user creds; will need to encrypt
    user = "Asset_Tools_API"
    passwd = "***************"
    
    # call Query to get general BF data
    generalBFData(user, passwd)

    c = ADConn()
    # get AD information for the specific coreID
    matrixWithADInfo = getInfo(matrix, c) # function inside ADLookup.py

    # get connection to DB
    cnx = dbInfo()
    
    # call database and upsert information from the matrix list
    BFDatabaseUpsert(matrixWithADInfo, cnx) # function inside DBConn.py

    print("...bigFixJob.py Completed. Ending Script.")

# main()
