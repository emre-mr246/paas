 # [P]ortswigger [A]cademy [A]utomatic [S]olver
#### With this tool, you can solve the labs in PortSwigger Academy with a few commands.
 - For now, PAAS only available for seven categories: Authentication, Directory Traversal, OSCi, Access Control Vulnerabilities, SSRF (Python) and SQLi (C)
 - I'm still developing the tool. More labs will be added in the future.
 
#### Usage for Python Script
 - [x] Burp Suite or any proxy listener (on 127.0.0.1:8080) must be open while the PAAS is running.
 - [x] Run the tool with the command `./python paas_linux.py`.
 - [x] Type `exit` to exit the tool, and `menu` to return to the main menu.

 #### Usage for C Code
 - [x] Burp Suite or any proxy listener (on 127.0.0.1:8080) must be open while the PAAS is running.
 - [x] You can download the curl library for compile the code with this command: `sudo apt-get install libcurl4-openssl-dev`.
 - [x] For compile the c code, you can do it with the following command: `gcc paas_linux.c -o paas_linux_c -lcurl`.
 - [x] Run the tool with the command `./paas_linux_c`.
 
#### 10.09.2023 Update Notes
- [x] SQLi labs added (for the first eleven SQLi lab in the PortSwigger Academy).
- [x] Since Paas is written in C, it can now run faster.
- [x] You only provide the URL to the C code, and it finds the appropriate solution for you and solves the lab.

#### 07.07.2023 Update Notes
- [x] new labs added.
- [x] some functions have been made asynchronous.
- [x] with asynchronous attack feature, paas can resolve the "2FA bypass using a brute-force attack" lab 100x faster than PortSwigger Academy's own solution and any other community solutions.
