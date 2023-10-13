import modules.VisualEffects as VisualEffects

def success():
    print("[+] enjoy! ", end="")

    VisualEffects.random_emoji("positive")

    print("\n[+] see you later in the another lab! :D")
    return 1

    
def fail():
    print("[-] something went wrong!")
        
    print("\n[-] exploit failed! ", end="")
    VisualEffects.random_emoji("negative")

    return 0