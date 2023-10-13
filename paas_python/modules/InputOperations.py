import modules.VisualEffects as VisualEffects
import modules.Variables as Variables
import sys
import paas
import signal

input_type = {
    1: "any_input",
    2: "menu_input",
    3: "url_input" 
}

user_input = None
invalid_input_try_count = 0

def get_input(input_header, input_type, menu_option_count=None):
    global user_input
    global invalid_input_try_count

    user_input = input(f"\n{input_header}")
    check_exit_command(user_input)
    user_input = check_input(user_input, input_type, menu_option_count)
    
    VisualEffects.paas_ascii_art()

    invalid_input_try_count = 0

    return user_input


def check_exit_command(user_input):
        if user_input == "exit":
            print("\nGoodbye :D")
            sys.exit(-1)


def check_input(user_input, input_type, menu_option_count):
    try:
        if (input_type == "menu_input"):
            if not 1 <= int(user_input) <= menu_option_count:
                 return invalid_input(menu_option_count)

        if (input_type == "url_input"):
            if not(("http" or "https") and "web-security-academy.net" in user_input):
                return invalid_input()

            if user_input.count("/") >= 3:
                user_input = "/".join(user_input.split("/")[:3])

        if (str(user_input).isnumeric()):
            user_input = int(user_input)

        return user_input
    
    except Exception:
        return invalid_input(input_type, menu_option_count)


def invalid_input(input_type, menu_option_count=None):
        global invalid_input_try_count

        invalid_input_try_count += 1
        VisualEffects.loading_effect("Invalid input!", 1)
        if invalid_input_try_count >= 4:
           paas.exit_program(0)
        return get_input(f"try again({invalid_input_try_count}/3): ", input_type, menu_option_count)


def encode_all(input_to_encode):
    return "".join("%{0:0>2x}".format(ord(char)) for char in input_to_encode)


def press_any_key():
    VisualEffects.loading_effect("...", 1)
    get_input("\npress enter to continue...")
    VisualEffects.paas_ascii_art()


def initialize_signal_handler():
     signal.signal(signal.SIGINT, signal_handler_text)


def signal_handler_text(signal, frame):
    print("\nPlease write \"exit\" to exit!")


def get_lab_url_from_user():
    print("example: https://lab-id.web-security-academy.net/")
    Variables.url = get_input("URL: ", input_type[3])
