#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include "lib/sha256.c"
#include "lib/md5.c"

#define MAX_PATTERNS 102000
#define MAX_PATTERN_LEN 1024

typedef struct {
    uint8_t data[MAX_PATTERN_LEN];
    uint8_t mask[MAX_PATTERN_LEN];
    size_t length;
    char original[512];
} BytePattern;

BytePattern patterns[MAX_PATTERNS];
int num_patterns = 0;
int score = 0;

int check_polymorphic(const uint8_t* code, size_t len) {
    const uint8_t xor_pattern[] = {0x67, 0x80, 0x30, 0x00}; 
    for (size_t i = 0; i < len - 3; i++) {
        if ((code[i] == xor_pattern[0] && code[i+1] == xor_pattern[1] && code[i+2] == xor_pattern[2])) {
            return 1;
        }
    }
    return 0;
}

void hexdump(char *buf, int len) {
    int pos;
    char line[80];
    while (len > 0) {
        int cnt = (len > 16) ? 16 : len;
        pos = 0;

        for (int i = 0; i < cnt; i++) {
            pos += snprintf(&line[pos], sizeof(line) - pos, "%02x", (unsigned char)buf[i]);
        }
        //printf("%s\n", line);

        buf += cnt;
        len -= cnt;
    }
}

uint8_t rot13_left(uint8_t a){
    //printf("%02x ", (a-0xD+0x100) % 0x100);
    return (a-0xD+0x100) % 0x100;
}

uint8_t rot13_right(uint8_t a){
    //printf("%02x ", (a+0xD+0x100) % 0x100);
    return (a+0xD+0x100) % 0x100;
}

char* ya_gomoseksualist_md5(uint8_t *hash) {
    int pos=0;
    char *result = (char*)malloc(33);
    for (int i = 0; i < 32; i++) {
        pos += snprintf(&result[pos], 33 - pos, "%02x", hash[i]);
    }
    result[32] = '\0';
    return result;
}

char* ya_gomoseksualist_sha256(uint8_t *hash) {
    int pos=0;
    char *result = (char*)malloc(65);
    for (int i = 0; i < 64; i++) {
        pos += snprintf(&result[pos], 65 - pos, "%02x", hash[i]);
    }
    result[64] = '\0';
    return result;
}

int parse_pattern(const char *str, BytePattern *pattern) {
    size_t len = 0;
    size_t i = 0;
    memset(pattern, 0, sizeof(BytePattern));
    strncpy(pattern->original, str, sizeof(pattern->original));

    while (str[i] && len < MAX_PATTERN_LEN) {
        if (isspace(str[i])) {
            i++;
            continue;
        }

        if (str[i] == '?' && str[i+1] == '?') {
            pattern->mask[len] = 0;
            i += 2;
            len++;
        } 
        else if (isxdigit(str[i]) && isxdigit(str[i+1])) {
            char byte_str[3] = {str[i], str[i+1], '\0'};
            if (sscanf(byte_str, "%2hhx", &pattern->data[len]) != 1) {
                return 0;
            }
            pattern->mask[len] = 1;
            i += 2;
            len++;
        }
        else {
            return 0;
        }
    }
    pattern->length = len;
    return len > 0;
}

int load_patterns(const char *filename) {
    FILE *fp = fopen(filename, "r");

    char line[512];
    while (fgets(line, sizeof(line), fp) && num_patterns < MAX_PATTERNS) {
        line[strcspn(line, "\r\n")] = 0;
        if (parse_pattern(line, &patterns[num_patterns])) {
            num_patterns++;
        }
    }
    fclose(fp);
    return 1;
}


int find_pattern(const uint8_t *buffer, size_t buf_len, const BytePattern *pattern) {
    if (pattern->length == 0 || buf_len < pattern->length) return 0;
    const size_t limit = buf_len - pattern->length;
    for (size_t i = 0; i <= limit; i++) {
        int match = 1;
        for (size_t j = 0; j < pattern->length; j++) {
            if (pattern->mask[j] && (buffer[i + j] != pattern->data[j])) {
                match = 0;
                break;
            }
        }
        if (match) {
            score = 5;
            printf("match at address: 0x%08zx\n", i);
            printf("found pattern: %s\n", pattern->original);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    FILE *f = fopen(argv[1], "rb");

    MD5Context ctx;
    md5Init(&ctx);

    uint8_t buffer[4096];
    size_t total_bytes = 0;
    sha256_context sha_ctx;
    sha256_init(&sha_ctx);

    while (!feof(f)) {
        size_t bytes_read = fread(buffer, 1, 4096, f);
        if (bytes_read > 0) {
            md5Update(&ctx, buffer, bytes_read);
            sha256_hash(&sha_ctx, buffer, bytes_read);
            int k = check_polymorphic(buffer, bytes_read);
            if (k==1){
                score = 3;
                printf("------------\n");
                printf("SCORE IS %d\n", score);
                printf("We recommend to run this file on your own risk bc there's small risk of being virus\n");
                printf("------------\n");
                printf("ur file is polymorphic virus\n");
                fclose(f);
                return 0;
            }
            total_bytes += bytes_read;
        }
    }

    uint8_t hash[16];
    md5Finalize(&ctx);
    memcpy(hash, ctx.digest, 16);

    //printf("read: %d\n", total_bytes);
    char* result = ya_gomoseksualist_md5(hash);
    fclose(f);
    uint8_t hash_sha256[32];
    sha256_done(&sha_ctx, hash);
    
    char* res = ya_gomoseksualist_sha256(hash);
    printf("SHA256 hash is %s\n", res);
    free(res);

    FILE* file_md5 = fopen("hashes&sigs\\md5.txt", "a+");
    FILE* file_sha256 = fopen("hashes&&sigs\\sha256.txt", "a+");
    char buff[256];
    printf("MD5 result is %s\n", result);

    while (fgets(buff, sizeof(buff), file_md5)) {
        if (strncmp(buff, result, 32)==0){
            score = 10;
            printf("------------\n");
            printf("SCORE IS %d\n", score);
            printf("Your file is virus it can shut down the whole your OS\n");
            printf("------------\n");
            fclose(file_md5);
            //printf("ur file seems to be virus file\n");
            return 0;
        }
    }

    while (fgets(buff, sizeof(buff), file_sha256)) {
        if (strncmp(buff, res, 64)==0){
            score = 10;
            printf("------------\n");
            printf("SCORE IS %d\n", score);
            printf("Your file is virus it can shut down the whole your OS\n");
            printf("------------\n");
            fclose(file_sha256);
            //printf("ur file seems to be virus file\n");
            return 0;
        }
    }
    fclose(file_sha256);
    fclose(file_md5);
    //printf("argc is %d and argv is %s\n", argc, argv[2]);
    if (argc==3 && strcmp(argv[2], "--deep")==0){
        load_patterns("bytes.txt");
        uint8_t *file_content = (uint8_t*)malloc(100000);
        uint8_t *temp = (uint8_t*)malloc(100000);
        FILE *target_file = fopen(argv[1], "rb");
        while (!feof(target_file)){
            size_t bytes_r = fread(file_content, 1, 100000, target_file);
            //printf("%d\n", bytes_r);

            int found = 0;
            for (int i = 0; i < num_patterns; i++) {
                if (find_pattern(file_content, bytes_r, &patterns[i])) {
                    free(file_content);
                    score = 4;
                    printf("------------\n");
                    printf("SCORE IS %d\n", score);
                    printf("We recommend to run it in safe enviroment bc it can be potential threat for ur OS\n");
                    printf("------------\n");
                    return 0;
                }
            }
            for (int i = 0; i < bytes_r; i++){
                temp[i] = rot13_left(file_content[i]);
            }
            for (int i = 0; i < num_patterns; i++) {
                if (find_pattern(temp, bytes_r, &patterns[i])) {
                    free(file_content);
                    free(temp);
                    score = 5;
                    printf("File contains malicious byte pattern which has been encoded via rot13 in left\n");
                    printf("------------\n");
                    printf("SCORE IS %d\n", score);
                    printf("We recommend to run it in safe enviroment bc it can be potential threat for ur OS\n");
                    printf("------------\n");
                    return 0;
                }
            }

            for (int i = 0; i < bytes_r; i++){
                temp[i] = rot13_right(file_content[i]);
            }
            for (int i = 0; i < num_patterns; i++) {
                if (find_pattern(temp, bytes_r, &patterns[i])) {
                    free(file_content);
                    free(temp);
                    score = 5;
                    printf("File contains malicious byte pattern which has been encoded via rot13 in right\n");
                    printf("------------\n");
                    printf("SCORE IS %d\n", score);
                    printf("We recommend to run it in safe enviroment bc it can be potential threat for ur OS\n");
                    printf("------------\n");
                    return 0;
                }
            }
        }
        fclose(target_file);
        free(file_content);
    }
    
    score = 0;
    printf("------------\n");
    printf("SCORE IS %d\n", score);
    printf("File is safe so u can run it without any concerns\n");
    printf("------------\n");
    return 0;
}
