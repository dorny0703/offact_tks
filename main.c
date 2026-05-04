/* Headless offact - reads target from /user/temp/uid.txt and /user/temp/id.txt
   Based on https://github.com/ps5-payload-dev/offact by John Törnblom (GPL v3) */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "offact.h"

static int read_hex64(const char *path, uint64_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[64] = {0};
    fgets(buf, sizeof(buf), f);
    fclose(f);
    /* strip newline */
    buf[strcspn(buf, "\r\n")] = 0;
    if (strlen(buf) != 16) return -2;
    if (sscanf(buf, "%lx", out) != 1) return -3;
    return 0;
}

int main(void) {
    char account_type[ACCOUNT_TYPE_MAX] = "np";
    int  account_flags = 4098;
    uint64_t old_id = 0;
    uint64_t new_id = 0;
    uint64_t cur_id = 0;
    int rc;

    /* uid.txt = old account ID of the target user (search key) */
    rc = read_hex64("/user/temp/uid.txt", &old_id);
    if (rc == -1) {
        printf("[設定ID錯誤: 找不到 uid.txt]\n");
        return 1;
    }
    if (rc < 0) {
        printf("[設定ID錯誤: uid.txt 內容非16進制]\n");
        return 1;
    }

    /* id.txt = new account ID to apply */
    rc = read_hex64("/user/temp/id.txt", &new_id);
    if (rc == -1) {
        printf("[設定ID錯誤: 找不到 id.txt]\n");
        return 1;
    }
    if (rc < 0) {
        printf("[設定ID錯誤: id.txt 內容非16進制]\n");
        return 1;
    }

    /* search account_numb 1-16 for the one whose current ID matches old_id */
    for (int n = 1; n <= ACCOUNT_NUMB_MAX; n++) {
        if (OffAct_GetAccountId(n, &cur_id) != 0) continue;
        if (cur_id != old_id) continue;

        OffAct_SetAccountId(n, new_id);
        OffAct_SetAccountType(n, account_type);
        OffAct_SetAccountFlags(n, account_flags);
        printf("[設定ID成功，新帳號ID: 0x%016lx]\n", new_id);
        return 0;
    }

    printf("[設定ID錯誤: 找不到匹配的當前帳號ID]\n");
    return 1;
}
