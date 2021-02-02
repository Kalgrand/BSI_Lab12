# Penetration Testing - OWASP Juice Shop & DSVW

Penetration testing of two popular unsecure web application OWASP Juice Shop and DSVW. Tests written in Python 3 include:

  - checking HTTP headers for potential vulnerabilities
  - checking HTTP methods 
  - authentication attempt with popular logins&passwords from .txt file
  - checking HTTP request headers for protection againt XSS attacks
  - scanning web application for XSS vulnerabilities
  - scanning web application for SQL injection vulnerability

# Applications used for testing:

 - [OWASP Juice Shop](https://github.com/bkimminich/juice-shop/)
 - [DSVW](https://github.com/stamparm/DSVW/)

### Installation [![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/)

```sh
$ git clone https://github.com/Kalgrand/BSI_Lab12.git
$ cd BSI_Lab12
$ pip install -r requirements.txt
$ python .\src\main.py  
```
### Authors
Maciej Milewski & Michał Degowski

