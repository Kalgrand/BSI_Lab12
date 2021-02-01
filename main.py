import requests
from requests.auth import HTTPBasicAuth
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
for verb in verbs:
    req = requests.request(verb, 'http://127.0.0.1:65412/')
    print(verb, req.status_code, req.reason)
    if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
        print('Possible Cross Site Tracing vulnerability found')

req = requests.get('http://127.0.0.1:65412/')
headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']

for header in headers:
    try:
        result = req.headers[header]
        print('%s: %s' % (header, result))
    except Exception as error:
        print('%s: Not found' % header)

with open('passwords.txt') as passwords:
    for password in passwords.readlines():
        password = password.strip()
        req = requests.get('http://127.0.0.1:65412/',
                           auth=HTTPBasicAuth('admin', password))
        if req.status_code == 401:
            print(password, 'failed.')
        elif req.status_code == 200:
            print('Login successful, password:', password)
            break
        else:
            print('Error occurred with', password)
            break

urls = open("urls.txt", "r")
for url in urls:
    url = url.strip()
    req = requests.get(url)
    print(url, 'report:')
    try:
        xssprotect = req.headers['X-XSS-Protection']
        if xssprotect != '1; mode=block':
            print('X-XSS-Protection not set properly, XSS may be possible:', xssprotect)
    except:
        print('X-XSS-Protection not set, XSS may be possible')
    try:
        contenttype = req.headers['X-Content-Type-Options']
        if contenttype != 'nosniff':
            print('X-Content-Type-Options not set properly:', contenttype)
    except:
        print('X-Content-Type-Options not set')
    try:
        hsts = req.headers['Strict-Transport-Security']
    except:
        print('HSTS header not set, MITM attacks may be possible')
    try:
        csp = req.headers['Content-Security-Policy']
        print('Content-Security-Policy set:', csp)
    except:
        print('Content-Security-Policy missing')
print('----')

def get_all_forms(url):

    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):

    details = {}
    # get the form action (target url)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):

    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

def scan_xss(url):

    # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            # won't break because we want to print other available vulnerable forms
    return is_vulnerable

if __name__ == "__main__":
    url = "http://127.0.0.1:65412/"
    print(scan_xss(url))