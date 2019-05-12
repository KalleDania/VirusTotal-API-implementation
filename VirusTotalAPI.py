import socket, json, time, re, json, requests, urllib.request

#Kilde: https://www.virustotal.com/da/documentation/public-api/#getting-url-scans

resultCategories = [[], [], [], [], []]
dateOfAttack = "20190407"
destAdrressesToCheck = ["10.0.180.239","104.16.40.2","104.24.104.237", "104.24.105.237", "104.254.150.11", "104.254.150.4", "104.254.150.77", "104.254.66.40", "104.27.162.228", "104.27.163.228", "104.31.64.30", "104.31.65.30", "104.31.78.58", "104.47.10.33", "104.47.41.33", "106.10.248.75", "127.0.0.1", "13.32.178.154", "13.32.205.17", "13.32.252.149", "13.32.252.28", "13.35.125.117", "13.35.125.46", "13.35.125.70", "13.35.127.136", "136.243.39.81", "143.204.133.61", "143.204.134.35", "144.160.159.21", "144.76.67.119", "146.148.42.217", "148.251.15.115", "151.101.52.133", "157.230.29.77", "169.254.169.123", "169.254.169.254", "172.16.109.112", "172.16.130.107", "172.16.140.251", "172.16.218.196", "172.16.76.114", "172.217.0.35", "172.217.0.36", "172.217.14.195", "172.217.14.202", "172.217.14.232", "172.217.14.238", "172.217.164.106", "172.217.164.116", "172.217.164.99", "172.217.3.163", "172.217.3.170", "172.217.3.174", "172.217.3.200", "172.217.5.99", "172.217.6.72", "172.217.6.78", "172.31.0.2", "172.31.32.1", "172.31.88.0", "178.23.177.40", "184.26.80.228", "184.26.81.37", "185.167.164.37", "185.167.164.42", "192.168.126.231", "192.168.128.217", "192.168.214.226", "192.168.26.145", "192.225.158.1", "192.225.158.2", "192.225.158.3", "192.35.177.64", "194.117.213.1", "204.141.42.120", "213.186.33.3", "216.58.193.74", "216.58.194.163", "216.58.194.164", "216.58.194.180", "216.58.194.202", "216.58.195.66", "216.58.217.46", "23.111.9.35", "23.194.213.147", "23.35.177.46", "23.35.180.233", "23.59.190.19", "34.218.161.20", "34.243.21.190", "34.250.8.69", "35.166.112.39", "35.190.69.156", "37.157.4.23", "52.216.144.91", "52.35.250.5", "52.39.131.77", "54.191.212.171", "54.192.118.44", "54.229.134.158", "54.230.117.2854.72.116.84", "54.77.113.74", "62.107.153.238", "62.75.165.112", "65.20.0.49", "72.21.81.240", "72.21.91.29", "74.125.195.156", "74.208.5.22", "77.66.39.43", "91.214.22.48", "91.214.22.65", "91.214.22.66", "91.214.22.75", "91.223.235.23", "93.191.155.240", "94.130.15.89", "98.136.96.73", "99.84.226.36", "99.84.231.109", "99.84.239.104", "99.84.239.123", "99.84.239.90"]
API_KEY = "Your VirusTotal API key here!"

def retrive_VirusTotal_report_for_domain(_Domain):
    import json
    import urllib.request
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': _Domain, 'apikey': API_KEY}
    response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
    response_dict = json.loads(response)
    #print("Response dict: ", response_dict)
    return response_dict

def retrive_VirusTotal_report_for_IP(_IP):
    import json
    import urllib.request
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': _IP, 'apikey': API_KEY}
    response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
    response_dict = json.loads(response)
    #print ("Response dict: ", response_dict)
    return response_dict


def DNSlookup(_ip, _domain):
    if _domain is not None:
        addr = socket.gethostbyname(_domain)
    elif _ip is not None:
        addr = socket.gethostbyaddr(_ip)
    else:
        return
    #print(addr)
    return addr

def remove_duplicates(_list):
    uniqueList = []
    for item in _list:
        if item not in uniqueList:
            uniqueList.append(item)
    return uniqueList

def retrive_VirusTotal_report_for_IOC(_IOC, _Type):
    url = ""
    if _Type is "ip":
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    if _Type is "domain":
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'

    parameters = {_Type: _IOC, 'apikey': API_KEY}
    response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
    response_dict = json.loads(response)
    return response_dict

def date_difference(_IOCdate):
    # Basic sammenligner. Tager ikke højde for månedsskift eller længde.
    _IOCdate = _IOCdate.replace("-", "")
    difference = int(dateOfAttack) - int(_IOCdate)
    # Sikre det et positivt tal.
    difference = abs(difference)
    #print("IOCDATE:{0} Difference:{1}".format(_IOCdate, difference))
    return difference

def check_IOC_for(_IOCdata, _IOC, _checkFor):
    syntaxToMatch = ""
    if "Downloads" in _checkFor:
        syntaxToMatch = "detected_downloaded_samples"
    elif "Communicates" in _checkFor:
        syntaxToMatch = "detected_communicating_samples"
    elif "URL" in _checkFor:
        syntaxToMatch = "detected_urls"
    elif "domain" in _checkFor:
        syntaxToMatch = "resolutions"

    try:
        for i in range(len(_IOCdata[syntaxToMatch])):

            # Tjek set 3 eller flere gange
            if _IOCdata[syntaxToMatch][i]["positives"] >= 3:

                # Get dato
                cleanDateAsString = _IOCdata[syntaxToMatch][i]["date"]

                # Fjern hour-min-secs så vi kan compare med angrebets dato.
                cleanDateAsString = cleanDateAsString[0:10]

                thisDateDifference = date_difference(cleanDateAsString)

                if cleanDateAsString is dateOfAttack:
                    resultCategories[0].append(_IOC + " " + _checkFor)
                    continue

                elif (thisDateDifference > 0 and thisDateDifference < 3):
                    resultCategories[1].append(_IOC + " " + _checkFor)
                    continue

                elif (thisDateDifference > 2 and thisDateDifference < 6):
                    resultCategories[2].append(_IOC + " " + _checkFor)
                    continue

                elif (thisDateDifference > 5):
                    resultCategories[3].append(_IOC + " " + _checkFor)
                    continue

                else:
                    print("Couldnt compare dates...")
                    pass

    except Exception as exception:
        #print("Exception: ", str(exception), " Probably because IOC was clean and there was no findings returned.")
        resultCategories[4].append(_IOC + " Probably clean.")
        pass




def check_all_IOCs_by(_type):

    for i in range(len(destAdrressesToCheck)):
        # Med den gratis Virustotal API må jeg max lave 4 kald i minuttet, derfor vent mellem opslag.
        time.sleep(15)
        try:
            if _type is "ip":
                print("Checking IOC {0} of {1}: ".format(i, len(destAdrressesToCheck)), destAdrressesToCheck[i])
                IOCdata = retrive_VirusTotal_report_for_IOC(destAdrressesToCheck[i], _type)
                IOC_name = str(destAdrressesToCheck[i])
                check_IOC_for(IOCdata, IOC_name, "Downloads malware.")
                check_IOC_for(IOCdata, IOC_name, "Communicates with malware.")
                check_IOC_for(IOCdata, IOC_name, "Has hosted malicious URL.")
                check_IOC_for(IOCdata, IOC_name, "Has malicious domain resolved to.")

            if _type is "domain":
                domain = DNSlookup(destAdrressesToCheck[i], None)
                print("Checking IOC {0} of {1}: ".format(i, len(destAdrressesToCheck)), destAdrressesToCheck[i], " ", domain)
                IOCdata = retrive_VirusTotal_report_for_IOC(domain , _type)
                IOC_name = str(destAdrressesToCheck[i]) + str(domain)
                check_IOC_for(IOCdata, IOC_name, "Downloads malware.")
                check_IOC_for(IOCdata, IOC_name, "Communicates with malware.")
                check_IOC_for(IOCdata, IOC_name, "Has hosted malicious URL.")
                check_IOC_for(IOCdata, IOC_name, "Has malicious domain resolved to.")
        except Exception as exception:
            pass




check_all_IOCs_by("ip")
check_all_IOCs_by("domain")

print("\n ########## CHECKING DONE, PRINTING RESULTS! ########## \n")


for j in range(len(resultCategories)):
    # Because we might have multiple malware trigger on the same IP/Domain, we clear these duplicates
    resultCategories[j] = remove_duplicates(resultCategories[j])
    resultCategories[j].sort()

    if j is 0:
        print("\nFound on the exact date of attack d. 2019-04-07 :{0} \n".format(len(resultCategories[j])))
    elif j is 1:
        print("\nFound within 2 days of attack:{0} \n".format(len(resultCategories[j])))
    elif j is 2:
        print("\nFound within 5 days of attack:{0} \n".format(len(resultCategories[j])))
    elif j is 3:
        print("\nFound more than 5 days from attack:{0} \n".format(len(resultCategories[j])))
    else:
        print("\nNothing found on IOC. Its probably clean:{0} \n".format(len(resultCategories[j])))

    for k in range(len(resultCategories[j])):
        print(resultCategories[j][k])

