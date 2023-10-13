#!/usr/bin/python3
import modules.InputOperations as InputOperations
import modules.MenuOperations as MenuOperations
import modules.VisualEffects as VisualEffects
import modules.LabOperations as LabOperations
import modules.Variables as Variables
import modules.ExitProgram as ExitProgram


def main():
    VisualEffects.paas_ascii_art()
    VisualEffects.loading_bar()

    InputOperations.initialize_signal_handler()

    try: 
        InputOperations.get_lab_url_from_user()
        Variables.set_url_variables()
        MenuOperations.paas_menu()
        LabOperations.is_lab_solved()

    except Exception as e:
       VisualEffects.paas_ascii_art()
       print(e)
       ExitProgram.fail()


if __name__ == "__main__":
    main()