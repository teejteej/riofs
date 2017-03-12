#include "awsv4.h"
#include "urltools.h"
#include "utils.h"
#include <glib-2.0/glib/gbookmarkfile.h>


const gchar ENDL[] = "\n";
const gchar POST[] = "POST";
const gchar STRING_TO_SIGN_ALGO[] = "AWS4-HMAC-SHA256";
const gchar AWS4[] = "AWS4";
const gchar AWS4_REQUEST[] = "aws4_request";

int kvparraycompare(const void* a, const void* b)
{
    return strcmp((*(const KeyValuePair **)a)->key, (*(const KeyValuePair **)b)->key);
}

int strarraycompare(const void* a, const void* b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}
    
    // http://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
void sha256(const char *str, unsigned int length, unsigned char outputBuffer[SHA256_DIGEST_LENGTH]) 
{
    SHA256_CTX sha256;   
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int i;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, length);
    SHA256_Final(hash, &sha256);
    
    
    for (i=0;i<SHA256_DIGEST_LENGTH;i++) 
    {
        outputBuffer[i] = hash[i];
    }
 
}

gchar* sha256_base16(const char* str, unsigned int length) 
{ 
    unsigned char *hashOut; 
    char* _buffer;

    hashOut = (unsigned char *)malloc((SHA256_DIGEST_LENGTH)* sizeof(unsigned char));

    _buffer = g_malloc(sizeof(char)*(length));
    memcpy(_buffer, str, length);

    sha256(_buffer, length, hashOut);
        
    g_free(_buffer);
    return HexEncode(hashOut, SHA256_DIGEST_LENGTH);
}

    
// -----------------------------------------------------------------------------------
// TASK 1 - create a canonical request
// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
// uri should be normalize()'d before calling here, as this takes a const ref param and we don't 
// want to normalize repeatedly. the return value is not a uri specifically, but a uri fragment,
// as such the return value should not be used to initialize a uri object
gchar *canonicalize_uri(const GURI* uri) 
{
    gchar* _result;
    char* _path;
    GURI* _tmp;

    if(uri == NULL) return NULL;

    _path = uri->path;
    if (_path == NULL || strlen(_path) == 0) return g_strdup("/");

    return url_encode(uri->path, false);
}

gchar* canonicalize_query(const GURI* uri)
{
    const char* query_delim = "&";
    unsigned int _numentries, _numentries2;
    unsigned int _index;
    gchar* _query;
    gchar* _str;
    gchar* _str2;
    gchar* _result;
    gchar** tok;
    gchar** tok2;
    GURI* _tmp;

    if (uri == NULL) return NULL;

    _query = uri->query;    
    if (_query == NULL || strlen(_query) == 0) { return g_strdup("");  } 

    tok = str_split(_query, query_delim, (unsigned int*)&_numentries, false);

    if (tok[0] != NULL)
    {        
        // make parameters confirm to AWS expectations...
        for(_index = 0; _index< _numentries; _index++)
        {
            _str = tok[_index];
            tok2 = str_split(tok[_index],"=", (unsigned int*)&_numentries2, false);
            if(_numentries2 == 2)
            {
                _str2 = url_decode(tok2[1]);
                g_free(tok2[1]);
                tok2[1] = _str2;

                _str2 = url_encode(tok2[1], true); //, (strcicmp(tok2[0], "prefix") != 0)
                tok[_index] = g_strdup_printf("%s=%s",tok2[0], _str2);

                g_free(_str2);
                g_free(tok2[1]);
            }
            else
            {
                tok[_index] = g_strdup_printf("%s%s", tok2[0], "=");
            }
            g_free(_str);

            g_free(tok2[0]);
            g_free(tok2);
        }

        qsort(tok, _numentries, sizeof(gchar*), strarraycompare);
        
        _result = g_strjoinv(query_delim, tok);

        for(_index = 0; _index< _numentries; _index++){ g_free(tok[_index]); }
        free(tok);
    }
    else
    {
        _result = (gchar*)calloc(1, sizeof(gchar));
    }

    return _result;
}

// create a map of the "canonicalized" headers
// will return empty map on malformed input.
KeyValuePair **canonicalize_headers(const unsigned int num_headers, const char** headers)
{
    const gchar* header_delim = ":";
    KeyValuePair *kvp;
    gchar* p;
    unsigned int i;    
    unsigned int _numentries = 0;
    KeyValuePair** header_key2val;
    
    header_key2val = g_malloc(num_headers * sizeof(KeyValuePair*));        
    for(i=0; i< num_headers; i++) 
    {
        gchar** h = str_split((gchar *)headers[i], header_delim, (unsigned int*)&_numentries, true);

        header_key2val[i] = g_malloc(sizeof(KeyValuePair));
        kvp = (KeyValuePair *)header_key2val[i];
        
        p = (gchar *)h[0];
        for ( ; *p; ++p) *p = tolower(*p);

        (*kvp).key = g_strdup(h[0]);
        if(_numentries > 1)
        {
            (*kvp).value = g_strdup((char*)g_strstrip((gchar *)h[1]));                        
            g_free(h[1]);        
        }
        else
        {
            (*kvp).value = g_strdup((const char*)"");
        }

        g_free(h[0]);
        g_free(h);
    }    
    
    qsort(header_key2val, num_headers, sizeof(KeyValuePair*), kvparraycompare);
    
    return header_key2val;
}

    
// get a string representation of header:value lines
gchar* map_headers_string(const unsigned int len, const KeyValuePair **header_key2val) 
{
    const gchar *pair_delim = ":";
    gchar *result = NULL;
    gchar* newresult = NULL;
    gchar *tmp = NULL;
    unsigned int i;    
    
    for (i = 0; i<len; i++) 
    {
        KeyValuePair *_kv = (KeyValuePair *)header_key2val[i];
        
        tmp = g_strconcat((*_kv).key, pair_delim, (*_kv).value, ENDL, (gchar *)0);
        if(result == NULL)
        {
            result = tmp;
        }
        else 
        {
            newresult = g_strconcat(result, tmp, (gchar *)0);
            g_free(result);
            g_free(tmp);
            
            result = newresult;
        }
    }
    
    return result;
}

    // get a string representation of the header names
gchar* map_signed_headers(const unsigned int len, const KeyValuePair **header_key2val)
{
    const gchar* pair_delim = ";";
    gchar* result;
    gchar* newresult;
    gchar *tmp;
    unsigned int i;    

    result = NULL;
    
    for (i = 0; i<len; i++) 
    {
        KeyValuePair *_kv = (KeyValuePair *)header_key2val[i];
        
        tmp = (*_kv).key;
        if(result == NULL)
        {
            result = g_strdup(tmp);
        }
        else 
        {
            newresult = g_strconcat(result, pair_delim, tmp, (gchar *)0);
            g_free(result);
            
            result = newresult;
        }        
    }

    return result;
}
    
gchar *canonicalize_request(
                                const gchar *http_request_method,
                                const gchar *canonical_uri,
                                const gchar *canonical_query_string,
                                const gchar *canonical_headers,
                                const gchar *signed_headers,
                                const gchar* payload_sha256) 
{
    gchar* sha256_payload;
    gchar* result;

    if(
        http_request_method == NULL ||
        canonical_uri == NULL || 
        canonical_query_string == NULL ||
        canonical_headers == NULL ||
        signed_headers == NULL
      )
      {
          return NULL;
      }

    if(payload_sha256 == NULL || strcmp(payload_sha256, "") == 0) 
    {
        sha256_payload = sha256_base16("", 0);
    }
    else
    {
        sha256_payload = g_strdup(payload_sha256);
    }

    result = g_strconcat(
                                    http_request_method, ENDL,
                                    canonical_uri, ENDL,
                                    canonical_query_string, ENDL, 
                                    canonical_headers, ENDL, 
                                    signed_headers, ENDL,
                                    sha256_payload,
                                    (gchar *)0);

    g_free(sha256_payload);
    
    return result;
}

// -----------------------------------------------------------------------------------
// TASK 2 - create a string-to-sign
// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
gchar *string_to_sign(
                        const gchar *algorithm,
                        const time_t *request_date,
                        const gchar *credential_scope,
                        const gchar *hashed_canonical_request) 
{
    gchar* datestr = ISO8601_date(request_date);
    gchar* result = g_strconcat(
                            algorithm, ENDL, 
                            ISO8601_date(request_date), ENDL,
                            credential_scope, ENDL, 
                            hashed_canonical_request,
                            (gchar *)0);

    g_free(datestr);
    
    return result;        
}


gchar *credential_scope(
                            const time_t *request_date,                                        
                            const gchar *region,
                            const gchar *service) 
{
    const gchar* delim = "/";
    gchar* datestr;
    gchar* result; 
    
    datestr = utc_yyyymmdd(request_date);
    result = g_strconcat(
                            datestr, delim, 
                            region, delim,
                            service, delim,
                            AWS4_REQUEST, 
                            (gchar *)0); 
    

    g_free(datestr);
    
    return result;
        
}

// time_t -> 20131222T043039Z
gchar* ISO8601_date(const time_t *t) 
{
    gchar* buf;
    int len;
    
    if(t == NULL) return NULL;

    len = strlen("20111008T070709Z")+2;
    buf = g_malloc(len);
    
    strftime(buf, len, "%Y%m%dT%H%M%SZ", gmtime(t));
    return buf;
}


// time_t -> 20131222
gchar *utc_yyyymmdd(const time_t  *t) 
{
    int len;
    gchar *buf;

    if(t == NULL)return NULL;

    len = 9;// strlen("20111008")+1;
    buf = g_malloc(len * sizeof(gchar));
            
    strftime(buf, len, "%Y%m%d", gmtime(t));
    return buf;
}

    
// -----------------------------------------------------------------------------------
// TASK 3
// http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
gchar *calculate_signature(
                            const time_t *request_date, 
                            const gchar* secret,
                            const gchar* region,
                            const gchar* service,
                            const gchar* string_to_sign) 
{
    unsigned char* kDate;
    unsigned char *kRegion;
    unsigned char *kService;
    unsigned char *kSigning;
    unsigned char *kSig;

    gchar*  c_yyyymmdd;
    const gchar*  c_aws4_request;
    gchar* k1;

    gchar* _result;

    c_yyyymmdd = utc_yyyymmdd(request_date);
    c_aws4_request = "aws4_request";
    k1 = g_strconcat(AWS4, secret, NULL);


    kDate = HMAC(EVP_sha256(), k1, strlen(k1), 
                    (unsigned char*)c_yyyymmdd, strlen(c_yyyymmdd), NULL, NULL); 

    kRegion = HMAC(EVP_sha256(), kDate, SHA256_DIGEST_LENGTH, 
                    (unsigned char*)region, strlen(region), NULL, NULL); 

    kService = HMAC(EVP_sha256(), kRegion, SHA256_DIGEST_LENGTH, 
                    (unsigned char*)service, strlen(service), NULL, NULL); 
    
    kSigning = HMAC(EVP_sha256(), kService, SHA256_DIGEST_LENGTH, 
                    (unsigned char*)c_aws4_request, strlen(c_aws4_request), NULL, NULL); 

    kSig = HMAC(EVP_sha256(), kSigning, SHA256_DIGEST_LENGTH, 
                    (unsigned char*)string_to_sign, strlen(string_to_sign), NULL, NULL); 
    
    _result = HexEncode(kSig, SHA256_DIGEST_LENGTH);

    g_free(c_yyyymmdd);
    g_free(k1);
    
    return _result;
}


void free_kvp_array(KeyValuePair** array, unsigned int num_entries)
{
    unsigned int _index;
    for(_index = 0; _index < num_entries; _index++)
    {
        g_free(array[_index]);
    }
    g_free(array);

    array = NULL;
}
