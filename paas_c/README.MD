 # [P]ortswigger [A]cademy [A]utomatic [S]olver
 - PAAS C is available exclusively for SQLi labs.

#### Instructions for C Code
 - [x] You can download the curl library for compile the code with this command: `sudo apt-get install libcurl4-openssl-dev`.
 - [x] For compile the c code, `gcc paas_linux.c -o paas_linux_c -lcurl`.
 - [x] Run the tool with the command `./paas_linux_c`.

#### 17.09.2023 Update Notes (for C Code)
- [x] The code has been made more clear and secure.

#### 13.09.2023 Update Notes (for C Code)
- [x] With binary search, the labs called 'Blind SQL injection with conditional errors' and 'Blind SQL injection with conditional responses' can be solved with approximately 60% fewer requests compared to regular brute force attacks.
- [x] Various improvements have been made to the code

#### 11.09.2023 Update Notes (for C Code)
- [x] Since Paas is written in C, it can now run faster.
- [x] You only provide the URL to the C code, and it finds the appropriate solution for you and solves the lab.
