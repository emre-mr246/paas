import warnings
import requests

url = None
login_url = None
myaccount_url = None
check_stock_url = None
submit_solution_url = None

selected_lab = None
menu_header = None

localhost_8080 = "http://127.0.0.1:8080"
proxies = {"http": localhost_8080, "https": localhost_8080}
proxy = localhost_8080


def set_url_variables():
    global login_url
    login_url = url + "/login"
    global myaccount_url
    myaccount_url = url + "/my-account"
    global check_stock_url
    check_stock_url = "/product/stock"
    global submit_solution_url
    submit_solution_url = url + "/submitSolution"
    return 1

session = requests.Session()
warnings.filterwarnings("ignore")
