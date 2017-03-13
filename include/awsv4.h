#ifndef AWSV4_H
#define AWSV4_H

#include "global.h"

extern const gchar ENDL[];
extern const gchar POST[];
extern const gchar STRING_TO_SIGN_ALGO[];
extern const gchar AWS4[];
extern const gchar AWS4_REQUEST[];

typedef struct{
    gchar * key;
    gchar * value;
} KeyValuePair;

void sha256(const char *str, unsigned length, unsigned char outputBuffer[SHA256_DIGEST_LENGTH]);
gchar* sha256_base16(const char *str, unsigned length);

gchar *map_headers_string(const unsigned int len, const KeyValuePair **header_key2val);
gchar* map_signed_headers(const unsigned int len, const KeyValuePair **header_key2val);

gchar* canonicalize_uri(const struct evhttp_uri* uri);
gchar* canonicalize_query(const struct evhttp_uri* uri);
KeyValuePair **canonicalize_headers(const unsigned  num_headers, const char** headers);
gchar *canonicalize_request(
                                const gchar *http_request_method,
                                const gchar *canonical_uri,
                                const gchar *canonical_query_string,
                                const gchar *canonical_headers,
                                const gchar *signed_headers,
                                const gchar *payload_sha256);

gchar *string_to_sign(
                        const gchar *algorithm,
                        const time_t *request_date,
                        const gchar *credential_scope,
                        const gchar *hashed_canonical_request) ;

gchar* ISO8601_date(const time_t *t);
gchar* utc_yyyymmdd(const time_t *t);

gchar *credential_scope(
                            const time_t *request_date,                                        
                            const gchar *region,
                            const gchar *service) ;

gchar *calculate_signature(
                            const time_t *request_date, 
                            const gchar* secret,
                            const gchar* region,
                            const gchar* service,
                            const gchar* string_to_sign) ;
   
void free_kvp_array(KeyValuePair** array, unsigned int num_entries);

#endif
