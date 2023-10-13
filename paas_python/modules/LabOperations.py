import modules.RequestOperations as request
import modules.Variables as Variables
import modules.ExitProgram as ExitProgram
from bs4 import BeautifulSoup
import time

def is_lab_solved():
    time.sleep(1)
    response = request.session.get(Variables.url, verify=False, proxies=Variables.proxies)
    if "Congratulations, you solved the lab!" in response.text:
        ExitProgram.success()
    else:
        ExitProgram.fail()


def get_csrf_token(path=""):
    response = request.session.get(Variables.url + path, verify=False, proxies=Variables.proxies)
    soup = BeautifulSoup(response.text, "html.parser")
    csrf_token = soup.find("input", {'name': 'csrf'})['value']
    return csrf_token



            