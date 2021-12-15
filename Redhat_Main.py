import requests
import getpass
import re
import openpyxl
import time
import argparse
import os
import urllib3
import urllib.parse
urllib3.disable_warnings()

os.system('title RedHat')
parser = argparse.ArgumentParser(description='URI encode your password. If you password contains ampersand(&) or pipe symbol(|) then wrap your input around double quotes')
parser = argparse.ArgumentParser(description='')
parser.add_argument('-u', '--userid', type=str, metavar='',required=True, help='Enter your UserID')
args = parser.parse_args()

os.system('cls')

def uriEncode(pwd):
    res = urllib.parse.quote(pwd)
    return res

pwd = uriEncode(getpass.getpass())
#proxies = {"http": f"http://{args.userid}:{uriEncode(args.password)}@pfgproxy.principal.com:80", "https": f"http://{args.userid}:{uriEncode(args.password)}@pfgproxy.principal.com:443"}
proxies = {"http": f"http://{args.userid}:{pwd}@pfgproxy.principal.com:80", "https": f"http://{args.userid}:{pwd}@pfgproxy.principal.com:443"}
def main():
    menu()
    menu_choice= int(input("\n>> Select your choice  "))
    if menu_choice == 1:
        scraper()
    elif menu_choice == 2:
        prepSheet()
    elif menu_choice ==3:
        vulndb_api()
    elif menu_choice ==4:
        vlookup()
    elif menu_choice ==5:
        print("Adios! have a great day")
    else:
        print("Not a valid selection, please choose from options 1-5")
        main()
    while menu_choice ==5:
        break
    else:
        continue_menu()

def menu():
    print('''\nRedHat Menu
        \t1. Scrape the web for Advisory
        \t2. Prepare sheet for VulnDB
        \t3. Fetch info from VulnDB
        \t4. Do a Vlookup
        \t5. Exit''')

def continue_menu():
    continue_input = input("\nWould you like to continue? Y/N: ")
    while continue_input.lower() != 'y':
        print("Adios! have a great day")
        break
    else:
        main()

def scraper():
    print("Running RH_scraper.py")
    os.system('python RH_scraper.py')
    continue_input = input("\nContinue to Step 2? Y/N: ")
    if continue_input.lower() == 'y':
        prepSheet() 
    else:
        main()

def prepSheet():
    print("Running RH_prepSheet.py")
    os.system('python RH_prepSheet.py')
    
    continue_input = input("\nContinue to Step 3? Y/N: ")
    if continue_input.lower() == 'y':
        vulndb_api() 
    else:
        main()
        
def vulndb_api():
    t1 = time.perf_counter()
    counter = 1
    newwb = openpyxl.load_workbook('Redhat Updates.xlsx')
    w_sheet = newwb['Master CVE']

    for i in range(1, w_sheet.max_row + 1):
        input_cve = w_sheet['A' + str(i + 1)].value
        if input_cve is not None:
            if bool(re.match('^A', input_cve)) == True:
                print(">>\t" + input_cve)

            else:
                sliced_cve = input_cve[4:]
                cve_url = f'http://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/{sliced_cve}/find_by_cve_id'
                access_token = received_token['access_token']
                api_call_headers = {'Authorization': 'Bearer ' + access_token}
                response = requests.get(cve_url, headers=api_call_headers, proxies= proxies, verify=False)
                details_json = response.json()
                if response.status_code == 200:
                    print(f'>>\t{counter}. Got {input_cve} in {response.elapsed.total_seconds()} seconds')
                    # Fetch CVSS Score
                    for cvssmetrics in details_json['results']:
                        metrics = (cvssmetrics['cvss_metrics'])
                        for cvss in metrics:
                            cvss_score = str(cvss['score'])
                            # print("CVSS Score: " + cvss_score)
                            w_sheet['B' + str(i + 1)].value = cvss_score

                    # Fetch location
                    for clfction in details_json['results']:
                        classification = (clfction['classifications'])
                        for ids in classification:
                            if ids['id'] == 2 or ids['id'] == 46 or ids['id'] == 4:
                                location = ids['longname']
                                # print("Location: " + location)
                                w_sheet['C' + str(i + 1)].value = location

                    # Fetch Exploit
                    for clfction in details_json['results']:
                        classification = (clfction['classifications'])
                        for ids in classification:
                            if ids['id'] == 21 or ids['id'] == 55 or ids['id'] == 24 or ids['id'] == 63:
                                exploit = ids['longname']
                                # print("Exploit: " + exploit)
                                w_sheet['D' + str(i + 1)].value = exploit

                    # Fetch Description
                    for desc in details_json['results']:
                        description = (desc['description'])
                        # print("description : " + description)
                        w_sheet['E' + str(i + 1)].value = description

                else:
                    # code for 400 goes here
                    print(f"\t{counter}. Couldn't get {input_cve}")

        else:
            print(">> None detected")
            continue
        counter = counter+1
    newwb.save('Redhat Updates.xlsx')
    t2 = time.perf_counter()
    deltaT = t2 - t1
    if deltaT < 60:
        print(f'>> Finished in {t2-t1} seconds')
    else:
        print(f'>> Finished in {int(deltaT/60)} minutes')

    continue_input = input("\nContinue to Step 4? Y/N: ")
    if continue_input.lower() == 'y':
        vlookup() 
    else:
        main()

def vlookup():
    print("Running RH_vlookup.py")
    os.system('python RH_vlookup.py')
    


print("Contacting VulnDB to fetch access token")
# Required URLs
token_url = 'https://vulndb.cyberriskanalytics.com/oauth/token'
usage_url = 'https://vulndb.cyberriskanalytics.com/api/v1/account_status'
# GET AUTHENTICATION TOKEN FROM VULNDB
data = {
        'grant_type': 'client_credentials',
        'client_id': 'v51hERlYm9BjYCjS0KEdmk91LuDdXMV1NRyBZSzI',
        'client_secret': 'UuO3du6YXTRRHU2WTMj41MtN5gnjtkPcHNv8LWVf'
        }

access_token_response = requests.post(token_url, data=data, proxies= proxies, verify=False)
# token received as a json object
received_token = access_token_response.json()
if access_token_response.status_code ==200:
   print("Great! Access token received with status "+ str(access_token_response.status_code) + " OK\n" )
   main()

else:
    print("Unable to get the token")
