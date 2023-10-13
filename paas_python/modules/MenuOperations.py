import modules.InputOperations as InputOperations
import modules.VisualEffects as VisualEffects

import modules.LabSolutions.AccessControl as Access_Control_Labs
import modules.LabSolutions.Authentication as Authentication_Labs
import modules.LabSolutions.DirectoryTraversal as Directory_Traversal_Labs
import modules.LabSolutions.OSCommandInjection as OSCi_Labs
import modules.LabSolutions.ServerSideRequestForgery as SSRF_Labs

lab_solution_menu_to_be_called = None
lab_solution_to_be_called = None


def paas_menu():
    global menu_to_be_called

    vulnerabilities_menu()
    eval(lab_solution_menu_to_be_called)
    eval(lab_solution_to_be_called)


def vulnerabilities_menu():
    menu_name = "Vulnerabilities"
    menu_options = {
        1: "Authentication_Labs",
        2: "Directory_Traversal_Labs",
        3: "OS_Command_Injection_Labs",
        4: "Access_Control_Vulnerabilities_Labs",
        5: "Server_Side Request_Forgery_Labs"
    }

    print_menu(menu_name, menu_options)

    convert_input_to_menu_function(menu_name, menu_options)


def vulnerability_labs_menu(menu_name, menu_options):
    print_menu(menu_name, menu_options)
    convert_user_input_to_solution_name(menu_name, menu_options)

    print_menu_header(menu_name, menu_options, InputOperations.user_input)


# example; input: 1 -> output: Authentication_Labs.menu()
def convert_input_to_menu_function(menu_name, menu_options):
    global lab_solution_menu_to_be_called
    InputOperations.get_input("Select Vulnerability: ", InputOperations.input_type[2], len(menu_options))
    lab_solution_menu_to_be_called = menu_options[InputOperations.user_input] + ".menu" + "()"


# example; input: 1 -> output: Authentication_Labs.solve_lab_1()
def convert_user_input_to_solution_name(menu_name, menu_options):
    global lab_solution_to_be_called
    InputOperations.get_input("Select Lab: ", InputOperations.input_type[2], len(menu_options))
    lab_solution_to_be_called = menu_name + "_Labs.solve_lab_" + str(InputOperations.user_input) + "()"


def print_menu(menu_name, menu_options):
    VisualEffects.paas_ascii_art()

    print(f"== {menu_name} Menu ".ljust(77, "="))
    for key, value in menu_options.items():
        print(f"[{key}] {value}")
    print("=============================================================================")


def print_menu_header(menu_name, menu_options, user_input):
    VisualEffects.paas_ascii_art()
    menu_header = f"{menu_name}/{menu_options[user_input]}"
    print(f"== {menu_header} ".ljust(77, "="))

    