#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdint.h>

int Base64Encode(const uint8_t* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
        BIO_write(bio, buffer, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
		*b64text = (char*)malloc(bufferPtr->length+1);
		memcpy(*b64text, bufferPtr->data, bufferPtr->length);
		(*b64text)[bufferPtr->length] = '\0';

        //BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        //*b64text=(*bufferPtr).data;

        return (0); //success
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
        size_t len = strlen(b64input),
                padding = 0;

        if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
                padding = 2;
        else if (b64input[len-1] == '=') //last char is =
                padding = 1;

        return (size_t)len*0.75 - padding;
}

int Base64Decode(char* b64message, uint8_t** buffer, size_t* length) { //Decodes a base64 encoded string
        BIO *bio, *b64;

        int decodeLen = calcDecodeLength(b64message);
        *buffer = (uint8_t*)malloc(decodeLen);

        bio = BIO_new_mem_buf(b64message, -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
        *length = BIO_read(bio, *buffer, strlen(b64message));
        BIO_free_all(bio);

        return (0); //success
}