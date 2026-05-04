/* Headless offact - targets user by UID via username matching
   Based on https://github.com/ps5-payload-dev/offact by John Törnblom (GPL v3) */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include "offact.h"

typedef uint32_t SceUserServiceUserId;

int sceUserServiceInitialize(void *params);
int sceUserServiceTerminate(void);
int sceUserServiceGetUserName(SceUserServiceUserId userId, char *name, size_t size);

typedef struct {
    int  type;
    int  unk1;
    char message[1024];
    int  unk2;
    int  unk3;
} SceNotificationRequest;

int sceKernelSendNotificationRequest(int, SceNotificationRequest *, size_t, int);

#define SCE_USER_SERVICE_USER_NAME_MAX 128

static void notify(const char *fmt, ...) {
    SceNotificationRequest req = {0};
    req.type = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static int read_hex32(const char *path, uint32_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[64] = {0};
    fgets(buf, sizeof(buf), f);
    fclose(f);
    buf[strcspn(buf, "\r\n")] = 0;
    if (sscanf(buf, "%x", out) != 1) return -2;
    return 0;
}

static int read_hex64(const char *path, uint64_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[64] = {0};
    fgets(buf, sizeof(buf), f);
    fclose(f);
    buf[strcspn(buf, "\r\n")] = 0;
    if (strlen(buf) != 16) return -2;
    if (sscanf(buf, "%lx", out) != 1) return -3;
    return 0;
}

int main(void) {
    char account_type[ACCOUNT_TYPE_MAX] = "np";
    int  account_flags = 4098;
    uint32_t target_uid = 0;
    uint64_t new_id = 0;
    int rc;

    rc = read_hex32("/user/temp/uid.txt", &target_uid);
    if (rc != 0) {
        printf("[設定ID錯誤: 無法讀取 uid.txt]\n");
        notify("設定ID錯誤：無法讀取 uid.txt");
        return 1;
    }

    rc = read_hex64("/user/temp/id.txt", &new_id);
    if (rc == -1) {
        printf("[設定ID錯誤: 找不到 id.txt]\n");
        notify("設定ID錯誤：找不到 id.txt");
        return 1;
    }
    if (rc < 0) {
        printf("[設定ID錯誤: id.txt 內容非16進制]\n");
        notify("設定ID錯誤：id.txt 內容非16進制");
        return 1;
    }

    sceUserServiceInitialize(NULL);
    char target_name[SCE_USER_SERVICE_USER_NAME_MAX + 1] = {0};
    rc = sceUserServiceGetUserName((SceUserServiceUserId)target_uid,
                                    target_name, sizeof(target_name));
    sceUserServiceTerminate();

    if (rc != 0 || target_name[0] == 0) {
        printf("[設定ID錯誤: 找不到使用者 0x%08x]\n", target_uid);
        notify("設定ID錯誤：找不到使用者 0x%08x", target_uid);
        return 1;
    }

    char account_name[ACCOUNT_NAME_MAX];
    for (int n = 1; n <= ACCOUNT_NUMB_MAX; n++) {
        if (OffAct_GetAccountName(n, account_name) != 0) continue;
        if (account_name[0] == 0) continue;
        if (strcmp(account_name, target_name) != 0) continue;

        OffAct_SetAccountId(n, new_id);
        OffAct_SetAccountType(n, account_type);
        OffAct_SetAccountFlags(n, account_flags);
        printf("[設定ID成功，帳號 #%d (%s): 0x%016lx]\n", n, account_name, new_id);
        notify("設定ID成功\n%s\n0x%016lx", account_name, new_id);
        return 0;
    }

    printf("[設定ID錯誤: 找不到帳號 \"%s\"]\n", target_name);
    notify("設定ID錯誤：找不到帳號 \"%s\"", target_name);
    return 1;
}
