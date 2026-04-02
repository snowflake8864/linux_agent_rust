#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>

#define PORT 62201
#define MAX_PACKET_SIZE 1024
#define MAGIC "SECV"
#define VERSION 0x01
#define KEY_SIZE 32

static const uint8_t g_key[KEY_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

typedef struct {
    uint8_t s[256];
} Rc4Context;

static void rc4_init(Rc4Context *ctx, const uint8_t *key, size_t key_len) {
    for (int i = 0; i < 256; i++) {
        ctx->s[i] = i;
    }
    
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + ctx->s[i] + key[i % key_len];
        uint8_t tmp = ctx->s[i];
        ctx->s[i] = ctx->s[j];
        ctx->s[j] = tmp;
    }
}

static void rc4_crypt(Rc4Context *ctx, uint8_t *data, size_t len) {
    uint8_t i = 0, j = 0;
    
    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + ctx->s[i]) % 256;
        
        uint8_t tmp = ctx->s[i];
        ctx->s[i] = ctx->s[j];
        ctx->s[j] = tmp;
        
        uint8_t t = ctx->s[(ctx->s[i] + ctx->s[j]) % 256];
        data[k] ^= t;
    }
}

static uint32_t calculate_checksum(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static int parse_protocol_header(const uint8_t *data, size_t len, 
                                 uint8_t *version, uint8_t *msg_type, 
                                 uint16_t *seq, uint32_t *timestamp, 
                                 uint32_t *checksum, uint8_t *enc_type) {
    if (len < 20 || memcmp(data, MAGIC, 4) != 0) {
        printf("[DEBUG] 协议头长度不足或Magic错误, len=%zu\n", len);
        return -1;
    }
    
    *version = data[4];
    *msg_type = data[5];
    *seq = ntohs(*(uint16_t*)(data + 6));
    *timestamp = ntohl(*(uint32_t*)(data + 8));
    *checksum = ntohl(*(uint32_t*)(data + 12));
    *enc_type = data[16];
    
    printf("[DEBUG] 收到数据包: version=%u, msg_type=%u, seq=%u, enc_type=%u\n", 
           *version, *msg_type, *seq, *enc_type);
    
    uint8_t header_data[16];
    memcpy(header_data, data, 4);
    header_data[4] = *version;
    header_data[5] = *msg_type;
    memcpy(header_data + 6, data + 6, 6);
    memcpy(header_data + 12, data + 16, 4);
    
    uint32_t calc_crc = calculate_checksum(header_data, 16);
    if (calc_crc != *checksum) {
        printf("[DEBUG] CRC校验失败: calc=0x%08x, expected=0x%08x\n", calc_crc, *checksum);
        return -1;
    }
    
    return 0;
}

static void parse_security_eval_request(const uint8_t *data, size_t len,
                                         uint8_t *ip_type, char *ip_str,
                                         char *mac_str, uint32_t *score) {
    if (len < 27) return;
    
    *ip_type = data[0];
    
    if (*ip_type == 4) {
        sprintf(ip_str, "%d.%d.%d.%d", data[1], data[2], data[3], data[4]);
    } else {
        sprintf(ip_str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16]);
    }
    
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", 
            data[17], data[18], data[19], data[20], data[21], data[22]);
    
    *score = ntohl(*(uint32_t*)(data + 23));
}

static void build_security_eval_response(uint8_t *output, size_t *out_len,
                                          uint16_t seq, const char *message) {
    uint8_t header[20] = {0};
    memcpy(header, MAGIC, 4);
    header[4] = VERSION;
    header[5] = 0x02;
    *(uint16_t*)(header + 6) = htons(seq);
    *(uint32_t*)(header + 8) = htonl(time(NULL));
    
    uint8_t payload[256];
    int msg_len = strlen(message);
    *(int*)(payload) = htonl(0);
    payload[4] = (uint8_t)msg_len;
    memcpy(payload + 5, message, msg_len);
    
    uint8_t header_for_crc[16];
    memcpy(header_for_crc, header, 4);
    header_for_crc[4] = header[4];
    header_for_crc[5] = header[5];
    memcpy(header_for_crc + 6, header + 6, 6);
    memcpy(header_for_crc + 12, header + 16, 4);
    
    uint32_t checksum = calculate_checksum(header_for_crc, 16);
    *(uint32_t*)(header + 12) = htonl(checksum);
    
    Rc4Context ctx;
    rc4_init(&ctx, g_key, KEY_SIZE);
    rc4_crypt(&ctx, payload, 5 + msg_len);
    
    memcpy(output, header, 20);
    memcpy(output + 20, payload, 5 + msg_len);
    *out_len = 20 + 5 + msg_len;
}

static void handle_security_eval(const uint8_t *data, size_t len, 
                                 struct sockaddr_in *client_addr, int sockfd,
                                 uint8_t *response_buf) {
    uint8_t version, msg_type, enc_type;
    uint16_t seq;
    uint32_t timestamp, checksum;
    
    printf("[DEBUG] 收到数据包, len=%zu\n", len);
    
    if (parse_protocol_header(data, len, &version, &msg_type, &seq, &timestamp, &checksum, &enc_type) != 0) {
        printf("[ERROR] 解析头部失败\n");
        return;
    }
    
    if (len < 20 + 27) {
        printf("[ERROR] 消息体长度不足, len=%zu, expected=%d\n", len, 20 + 27);
        return;
    }
    
    printf("[DEBUG] 开始解密, payload_len=%zu\n", len - 20);
    
    uint8_t encrypted_payload[256];
    size_t payload_len = len - 20;
    memcpy(encrypted_payload, data + 20, payload_len);
    
    Rc4Context ctx;
    rc4_init(&ctx, g_key, KEY_SIZE);
    rc4_crypt(&ctx, encrypted_payload, payload_len);
    
    printf("[DEBUG] 解密完成, 开始解析请求\n");
    
    uint8_t ip_type;
    char ip_str[64] = {0};
    char mac_str[32] = {0};
    uint32_t score = 0;
    
    parse_security_eval_request(encrypted_payload, payload_len, &ip_type, ip_str, mac_str, &score);
    
    printf("[INFO] 收到安全评估请求 - IP: %s, MAC: %s, Score: %u\n", ip_str, mac_str, score);
    
    build_security_eval_response(response_buf, &len, seq, "success");
    
    sendto(sockfd, response_buf, len, 0, (struct sockaddr*)client_addr, sizeof(*client_addr));
    
    char client_ip[16];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));
    printf("发送响应 to %s\n", client_ip);
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    uint8_t buf[MAX_PACKET_SIZE];
    uint8_t response_buf[MAX_PACKET_SIZE];
    int port = PORT;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [-p port]\n", argv[0]);
            return 0;
        }
    }
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }
    
    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }
    
    printf("服务端启动，监听端口 %d\n", port);
    
    while (1) {
        int len = recvfrom(sockfd, buf, MAX_PACKET_SIZE, 0, 
                          (struct sockaddr*)&client_addr, &client_len);
        if (len < 0) {
            perror("recvfrom");
            continue;
        }
        handle_security_eval(buf, len, &client_addr, sockfd, response_buf);
    }
    
    close(sockfd);
    return 0;
}
