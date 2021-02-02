"""
SQL injection attack on webpage.


Autorzy: Michał Degowski i Maciej Milewski
"""


import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint


def get_all_forms(url, s):
    ''' Load all forms from given URL '''
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    ''' Extracts usefull information about form '''
    details = {}

    try:
        action = form.attrs.get("action").lower()
    except:
        action = None

    method = form.attrs.get("method", "get").lower()

    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    ''' Returns true if page is vulnerable to SQL injection based on response from header '''
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True

    return False


def scan_sql_injection(url, s):
    ''' Scanning webpage for potential SQL injection vulnerabilities '''
    for c in "\"'":
        probe_url = f"{url}{c}"
        print("[!] Trying", probe_url)
        res = s.get(probe_url)

        if is_vulnerable(res):
            print("Potential SQL injection vulnerability detected! link:", probe_url)
            return

    all_forms = get_all_forms(url, s)
    print(f"Detected {len(all_forms)} forms on {url}.")
    for form in all_forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)

            if is_vulnerable(res):
                print("SQL injection vulnerability detected, link:", url)
                print("[Form:")
                pprint(form_details)
                break


def main(): 
    ''' Running SQL ijection attack on localhost '''
    session = requests.Session()
    browsers_list = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
    session.headers["User-Agent"] = browsers_list

    URL_1 = "http://localhost/"
    URL_2 = "http://localhost:3000/#/login/"

    scan_sql_injection(URL_1, session)
    scan_sql_injection(URL_2, session)


if __name__ == "__main__":
    main()