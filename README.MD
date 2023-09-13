 # [P]ortswigger [A]cademy [A]utomatic [S]olver
#### With this tool, you can easily solve labs in PortSwigger Academy using just a few commands.
 - PAAS available for seven categories: Authentication, Directory Traversal, OSCi, Access Control Vulnerabilities, SSRF (Python) and SQLi (C)
 - PAAS is designed for Linux and may not work properly on other operating systems.
 - Burp Suite or any proxy listener (on 127.0.0.1:8080) must be open while the PAAS is running.
 - You can see requests through the Burp Suite's HTTP history.
 - I'm preparing for Ecole 42, and since for loops are prohibited there, I use mostly while loops instead.
 
#### for Python Script
 - [x] Run the tool with the command `./python paas_linux.py`.
 - [x] Type `exit` to exit the tool, and `menu` to return to the main menu.

#### for C Code
 - [x] Run the tool with the command `./paas_linux_c`.
 - [x] You can download the curl library for compile the code with this command: `sudo apt-get install libcurl4-openssl-dev`.
 - [x] For compile the c code, you can do it with the following command: `gcc paas_linux.c -o paas_linux_c -lcurl`.

#### 13.09.2023 Update Notes (for C Code)
- [x] With binary search, the lab called 'Blind SQL injection with conditional errors' can be solved with approximately 60% fewer requests compared to normal brute force attacks.
- [x] Code has been made more secure.

#### 11.09.2023 Update Notes (for C Code)
- [x] Since Paas is written in C, it can now run faster.
- [x] You only provide the URL to the C code, and it finds the appropriate solution for you and solves the lab.

#### 07.07.2023 Update Notes (for Python Script)
- [x] some functions have been made asynchronous.
- [x] with asynchronous attack feature, paas can resolve the "2FA bypass using a brute-force attack" lab 100x faster than PortSwigger Academy's own solution and any other community solutions.
