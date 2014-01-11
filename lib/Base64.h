#include <stdint.h>
extern int Base64Encode(const uint8_t* buffer, size_t length, char** b64text);
extern int Base64Decode(char* b64message, uint8_t** buffer, size_t* length);
