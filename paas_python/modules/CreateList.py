import modules.InputOperations as InputOperations
import modules.VisualEffects as VisualEffects


def user_list(lab_name):
    InputOperations.get_input("\npress any key to see user list...")

    VisualEffects.loading_effect("creating user list...", 2)

    VisualEffects.paas_ascii_art()
    print("userlist successfully created!\n")

    print("==== USER LIST ====")
    if lab_name == "Auth3":
        for i in range(150):
            if i % 3:
                print("carlos")
            else:
                print("wiener")
    print("==== THE END OF THE USER LIST ====")

    InputOperations.get_input("\npress any key to continue")
    VisualEffects.paas_ascii_art()


def password_list(lab_name):
    InputOperations.get_input("\npress any key to see password list...")

    VisualEffects.loading_effect("creating password list...", 2)

    VisualEffects.paas_ascii_art()
    print("password list successfully created!\n")

    print("==== PASSWORD LIST ====")
    if lab_name == "Auth3":
        with open("passlist", "r") as p:
            passwords = p.readlines()

        i = 0
        for pwd in passwords:
            if i % 3:
                print(pwd.strip("\n"))
            else:
                print("peter")
                print(pwd.strip("\n"))
                i += 1
            i += 1
    print("==== THE END OF THE PASSWORD LIST ====")

    InputOperations.press_any_key()