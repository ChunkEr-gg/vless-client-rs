#pragma once
#include <stdint.h>
enum { VLESS_START_OK, VLESS_START_INVALID_PROFILE, VLESS_START_ALREADY_RUNNING, VLESS_START_FAILED };
int32_t vless_proxy_start(const char *link, uint16_t port);
void vless_proxy_stop(void);
char *vless_profiles_import(const char *input);
void vless_profiles_free(char *json);
