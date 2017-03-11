#include <stdio.h>
#include <stdbool.h>
#include "awsv4.h"

bool HexEncode_verify()
{
    gchar* _input;
    gchar* _expected;
    gchar* _actual;
    int i;
    unsigned char _result[SHA256_DIGEST_LENGTH];

    // first case - try simple...
    _input = g_strdup("Hi there!");
    _expected = g_strdup("486920746865726521");
    
    _actual = HexEncode(_input, strlen(_input));

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    // first case - try empty...
    _input = g_strdup( "");
    _expected = g_strdup("");
    
    _actual = HexEncode(_input, strlen(_input));

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    // try null...
    _input = NULL;
    _expected = NULL;
    
    _actual = HexEncode(NULL, 0);

    if(_actual != NULL)
    {
        return false;
    }

    return true;
}

bool strsplit_verify()
{
    gchar* _input = NULL;
    unsigned int _numentries;
    gchar** _actual = NULL;
    gchar* _actual1;
    gchar* _actual2;
    gchar* _expected1;
    gchar* _expected2;

    // test easy case
    _input = g_strdup("test1:result1");
    _expected1 = g_strdup("test1");
    _expected2 = g_strdup("result1");

    _actual = str_split(_input, ":", (unsigned int*)&_numentries, false);
    _actual1 = (gchar *)_actual[0];
    _actual2 = (gchar *)_actual[1];

    if(strcmp(_actual1, _expected1) != 0 || strcmp(_actual2, _expected2) != 0 || _numentries != 2)
    {
        return false;
    }

    // now try stop at first hit...
    _input = g_strdup("test1:Sat Mar 21 18:00:00 GMT");
    _expected1 = g_strdup("test1");
    _expected2 = g_strdup("Sat Mar 21 18:00:00 GMT");

    _actual = str_split(_input, ":", (unsigned int*)&_numentries, true);
    _actual1 = (gchar *)_actual[0];
    _actual2 = (gchar *)_actual[1];

    if(strcmp(_actual1, _expected1) != 0 || strcmp(_actual2, _expected2) != 0 || _numentries != 2)
    {
        return false;
    }

    // now try delimiter at beginning
    _input = g_strdup(":result1");
    _expected1 = g_strdup("result1");
    _expected2 = NULL;

    _actual = str_split(_input, ":", (unsigned int*)&_numentries, false);
    _actual1 = (gchar *)_actual[0];
    _actual2 = (gchar *)_actual[1];

    if(strcmp(_actual1, _expected1) != 0 || _actual2 != NULL || _numentries != 1)
    {
        return false;
    }


    // now try delimiter at beginning
    _input = g_strdup("result1:");
    _expected1 = g_strdup("result1");
    _expected2 = NULL;

    _actual = str_split(_input, ":", (unsigned int*)&_numentries, false);
    _actual1 = (gchar *)_actual[0];
    _actual2 = (gchar *)_actual[1];

    if(strcmp(_actual1, _expected1) != 0 || _actual2 != NULL || _numentries != 1)
    {
        return false;
    }


    // now try without delimiter present...
    _input = g_strdup("result1");
    _expected1 = g_strdup("result1");
    _expected2 = NULL;

    _actual = str_split(_input, ":", (unsigned int*)&_numentries, false);
    _actual1 = (gchar *)_actual[0];
    _actual2 = (gchar *)_actual[1];

    if(strcmp(_actual1, _expected1) != 0 || _actual2 != NULL || _numentries != 1)
    {
        return false;
    }



    // now try with empty string..
    _input = g_strdup("");
    _expected1 = g_strdup("");
    _expected2 = NULL;

    _actual = str_split(_input, ":", (unsigned int*)&_numentries, false);
    _actual1 = (gchar *)_actual[0];
    _actual2 = (gchar *)_actual[1];

    if(strcmp(_actual1, _expected1) != 0 || _actual2 != NULL || _numentries != 1)
    {
        return false;
    }



    // now try with null...
    _input = NULL;
    _expected1 = NULL;
    _expected2 = NULL;

    _actual = str_split(_input, ":", (unsigned int*)&_numentries, false);
    if(_actual != NULL || _numentries != 0)
    {
        return false;
    }

    

    return true;
}

bool ISO8601_date_verify()
{
    time_t _input;
    struct tm _t;
    gchar* _expected;
    gchar* _actual;

    // first case - try simple...
    _t.tm_sec = 0;
    _t.tm_min = 36;
    _t.tm_hour = 14;
    _t.tm_mon = 5;
    _t.tm_year = 2007 - 1900;
    _t.tm_mday = 23;   

    _input = timegm(&_t);

    _expected = "20070623T143600Z";
    _actual = ISO8601_date(&_input);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    
    // try with null
    _actual = ISO8601_date(NULL);
    if(_actual != NULL)
    {
        return false;
    }


    return true;
}

bool utc_yyyymmdd_verify()
{
    time_t _input;
    struct tm _t;
    gchar* _expected;
    gchar* _actual;

    // first case - try simple...
    _t.tm_hour = 2;
    _t.tm_min = 0;
    _t.tm_sec = 0;
    _t.tm_mon = 5;
    _t.tm_year = 2007 - 1900;
    _t.tm_isdst = -1; 
    _t.tm_mday = 23;   

    _input = timegm(&_t);

    _expected = "20070623";
    _actual = utc_yyyymmdd(&_input);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    
    // try with null
    _actual = utc_yyyymmdd(NULL);
    if(_actual != NULL)
    {
        return false;
    }


    return true;
}

bool sha256_verify()
{
    gchar* _input;
    gchar* _expected;
    gchar* _actual;
    int i;
    unsigned char _result[SHA256_DIGEST_LENGTH];

    // first case - try simple...
    _input = g_strdup("Hi there!");
    _expected = g_strdup("d451d2a79e0a1f87270b313ca7d9e589359cb3d2aa906594529dcbc0535fd0f3");
    
    sha256(_input, strlen(_input), _result);
    _actual = HexEncode(_result, SHA256_DIGEST_LENGTH);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    // first case - try empty...
    _input =g_strdup( "");
    _expected = g_strdup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    
    sha256(_input, strlen(_input),  _result);
    _actual = HexEncode(_result, SHA256_DIGEST_LENGTH);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    // try null...
    _input = g_strdup(NULL);
    _expected = g_strdup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    
    sha256(NULL, 0, _result);
    _actual = HexEncode(_result, SHA256_DIGEST_LENGTH);


    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    return true;
}

bool canonicalize_uri_verify()
{
    // try normal 
    gchar* _expected = NULL;
    gchar* _actual = NULL;

    GURI* _uri;

    _uri = gnet_uri_new("http://testproject.com/testpath/somepage with spaces.php?firstparam=6 and 8&secondparam=8");

    _expected = g_strdup("/testpath/somepage%20with%20spaces.php");
    _actual = canonicalize_uri(_uri);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    // try empty
    _uri = gnet_uri_new("http://testproject.com");
    _expected = g_strdup("/");
    _actual = canonicalize_uri(_uri);
    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }   

    // null
    _actual = canonicalize_uri(NULL);
    if(_actual != NULL)
    {
        return false;
    }

    return true;
}

bool canonicalize_query_verify()
{
    // try normal 
    gchar* _expected = NULL;
    gchar* _actual = NULL;

    GURI* _uri;

    _uri = gnet_uri_new("http://testproject.com/testpath/somepage with spaces.php?lastparam=6 and 8&firstparam=8");

    _expected = g_strdup("firstparam=8&lastparam=6%20and%208");
    _actual = canonicalize_query(_uri);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    // check if we add = at the end
    _uri = gnet_uri_new("http://testproject.com/testpath/somepage with spaces.php?lastparam");

    _expected = g_strdup("lastparam=");
    _actual = canonicalize_query(_uri);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }
    // try empty
    _uri = gnet_uri_new("http://testproject.com");
    _expected = g_strdup("");
    _actual = canonicalize_query(_uri);
    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }   

    // null
    _actual = canonicalize_query(NULL);
    if(_actual != NULL)
    {
        return false;
    }

    return true;
}

bool canonicalize_headers_verify()
{
    // try normal 
    unsigned int _numheaders = 2;
    

    KeyValuePair** _expected = NULL;
    KeyValuePair** _actual = NULL;

    char** _inputheaders = g_malloc(sizeof(char*)*(_numheaders+1));
    _inputheaders[_numheaders] = NULL;
    
    _inputheaders[0] = "KEY2: VALUE_2 ";
    _inputheaders[1] = "key1:value1";

    _actual = canonicalize_headers(_numheaders, _inputheaders);


    _expected = g_malloc(sizeof(KeyValuePair*)*(_numheaders+1));

    _expected[0] = g_malloc(sizeof(KeyValuePair));    
    _expected[0]->key = "key1";
    _expected[0]->value = "value1";

    _expected[1] = g_malloc(sizeof(KeyValuePair));
    _expected[1]->key = "key2";
    _expected[1]->value = "VALUE_2";

    if(
        strcmp(_actual[0]->key, _expected[0]->key) != 0 ||
        strcmp(_actual[1]->key, _expected[1]->key) != 0 ||
        strcmp(_actual[0]->value, _expected[0]->value) != 0 ||
        strcmp(_actual[1]->value, _expected[1]->value) != 0        
        )
    {
        return false;
    }


    // null
    _numheaders = 0;
    _actual = canonicalize_headers(_numheaders, NULL);
    if(_actual != NULL)
    {
        return false;
    }

    return true;
}

bool sha256_base16_verify()
{
    gchar* _input;
    gchar* _expected;
    gchar* _actual;
    unsigned char _result[SHA256_DIGEST_LENGTH];

    // first case - try simple...
    _input = g_strdup("Hi there!");
    _expected = g_strdup("d451d2a79e0a1f87270b313ca7d9e589359cb3d2aa906594529dcbc0535fd0f3");
    _actual = sha256_base16(_input, strlen(_input));

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    // try empty...
    _input = "";
    _expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    
    _actual = sha256_base16(_input, strlen(_input));

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    // try null...
    _input = NULL;
    _expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";    
    _actual = sha256_base16(NULL, 0);

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    return true;
}

bool map_headers_string_verify()
{
    gchar* _input;
    gchar* _expected;
    gchar* _actual;
    unsigned int _numheaders = 2;

    KeyValuePair** _inputheaders = g_malloc(sizeof(KeyValuePair*)*(_numheaders+1));

    _inputheaders[_numheaders] = NULL;
    
    _inputheaders[0] = g_malloc(sizeof(KeyValuePair));
    _inputheaders[0]->key = "key1";
    _inputheaders[0]->value = "value1";

    _inputheaders[1] = g_malloc(sizeof(KeyValuePair));
    _inputheaders[1]->key = "key2";
    _inputheaders[1]->value = "value_2";

    _expected = "key1:value1\nkey2:value_2\n";
    _actual = map_headers_string(_numheaders, _inputheaders);
    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    return true;
}

bool map_signed_headers_verify()
{
    gchar* _input;
    gchar* _expected;
    gchar* _actual;
    unsigned int _numheaders = 2;

    KeyValuePair** _inputheaders = g_malloc(sizeof(KeyValuePair*)*(_numheaders+1));

    _inputheaders[_numheaders] = NULL;
    
    _inputheaders[0] = g_malloc(sizeof(KeyValuePair));
    _inputheaders[0]->key = "key1";
    _inputheaders[0]->value = "value1";

    _inputheaders[1] = g_malloc(sizeof(KeyValuePair));
    _inputheaders[1]->key = "key2";
    _inputheaders[1]->value = "value_2";

    _expected = "key1;key2";
    _actual = map_signed_headers(_numheaders, _inputheaders);
    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }

    return true;
}

bool canonicalize_request_verify()
{
    gchar* _actual = NULL;
    gchar* _expected = NULL;

    const gchar* _http_request_method = "GET";
    const gchar* _url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08";
    const gchar* _payload = "payload";
    gchar** _headers_string;
    gchar* _canonical_uri;
    gchar* _canonical_query;
    unsigned int _headers_count = 2;

    GURI* _uri;
    KeyValuePair** _canonical_headers;

    _headers_string = g_malloc((_headers_count+1)*sizeof(gchar*));
    _headers_string[0] = g_strdup("x-amz-date: 20150830T123600Z");
    _headers_string[1] = g_strdup("host: iam.amazonaws.com");
    _headers_string[_headers_count] = NULL;

    _uri = gnet_uri_new(_url);
    _canonical_uri = canonicalize_uri(_uri);
    _canonical_query = canonicalize_query(_uri);
    _canonical_headers = canonicalize_headers(_headers_count, _headers_string);

    _expected = g_strconcat(
                    _http_request_method, ENDL,
                    _canonical_uri, ENDL,
                    _canonical_query, ENDL, 
                    map_headers_string(_headers_count, _canonical_headers), ENDL,
                    map_signed_headers(_headers_count, _canonical_headers), ENDL,
                    sha256_base16(_payload, strlen(_payload)),
                    (gchar*)0);

    _actual = canonicalize_request(
                                    _http_request_method,
                                    _canonical_uri,
                                    _canonical_query,
                                    map_headers_string(_headers_count, _canonical_headers),
                                    map_signed_headers(_headers_count, _canonical_headers),
                                    sha256_base16(_payload, strlen(_payload))
                                );

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    // now try NULL variants...
    _actual = canonicalize_request(
                                    NULL,
                                    _canonical_uri,
                                    _canonical_query,
                                    map_headers_string(_headers_count, _canonical_headers),
                                    map_signed_headers(_headers_count, _canonical_headers),
                                    sha256_base16(_payload, strlen(_payload))
                                );
    if(_actual != NULL) return false;

    _actual = canonicalize_request(
                                    _http_request_method,
                                    NULL,
                                    _canonical_query,
                                    map_headers_string(_headers_count, _canonical_headers),
                                    map_signed_headers(_headers_count, _canonical_headers),
                                    sha256_base16(_payload, strlen(_payload))
                                );
    if(_actual != NULL) return false;

    _actual = canonicalize_request(
                                    _http_request_method,
                                    _canonical_uri,
                                    NULL,
                                    map_headers_string(_headers_count, _canonical_headers),
                                    map_signed_headers(_headers_count, _canonical_headers),
                                    sha256_base16(_payload, strlen(_payload))
                                );
    if(_actual != NULL) return false;

    _actual = canonicalize_request(
                                    _http_request_method,
                                    _canonical_uri,
                                    _canonical_query,
                                    NULL,
                                    map_signed_headers(_headers_count, _canonical_headers),
                                    sha256_base16(_payload, strlen(_payload))
                                );
    if(_actual != NULL) return false;

    _actual = canonicalize_request(
                                    _http_request_method,
                                    _canonical_uri,
                                    _canonical_query,
                                    map_headers_string(_headers_count, _canonical_headers),
                                    NULL,
                                    sha256_base16(_payload, strlen(_payload))
                                );
    if(_actual != NULL) return false;

    _actual = canonicalize_request(
                                    _http_request_method,
                                    _canonical_uri,
                                    _canonical_query,
                                    map_headers_string(_headers_count, _canonical_headers),
                                    map_signed_headers(_headers_count, _canonical_headers),
                                    NULL
                                );
    if(_actual != NULL) return false;

    return true;
}

bool credential_scope_verify()
{
    gchar* _actual = NULL;
    gchar* _expected = NULL;
    time_t _input;
    struct tm _t;

    const gchar* _region = "us-east-1";
    const gchar* _service= "s3" ;

    _t.tm_sec = 0;
    _t.tm_min = 0;
    _t.tm_hour = 0;
    _t.tm_mon = 4;
    _t.tm_year = 2013 - 1900;
    _t.tm_mday = 23;   

    _input = timegm(&_t);
    _expected = "20130523/us-east-1/s3/aws4_request";

    _actual = credential_scope(
                                    &_input,
                                    _region,
                                    _service
                                );

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }



    return true;
}

bool string_to_sign_verify()
{
    // data taken from amazon http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html

    gchar* _actual = NULL;
    gchar* _expected = NULL;

    const gchar* _http_request_method = "GET";
    const gchar* _url = "http://examplebucket.s3.amazonaws.com/test.txt";
    const gchar* _payload = "";

    gchar** _headers_string;
    gchar* _canonical_uri;
    gchar* _canonical_query;
    gchar* _canonical_request;
    gchar* _credential_scope;
    unsigned int _headers_count = 4;
    struct tm _t; 

    GURI* _uri;
    KeyValuePair** _canonical_headers;

    _headers_string = g_malloc((_headers_count+1)*sizeof(gchar*));
    _headers_string[0] = g_strdup("Host: examplebucket.s3.amazonaws.com");
    _headers_string[1] = g_strdup("x-amz-date:20130524T000000Z");
    _headers_string[2] = g_strdup("Range: bytes=0-9 ");
    _headers_string[3] = g_strdup("x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    _headers_string[_headers_count] = NULL;

    _uri = gnet_uri_new(_url);
    _canonical_uri = canonicalize_uri(_uri);
    _canonical_query = canonicalize_query(_uri);
    _canonical_headers = canonicalize_headers(_headers_count, _headers_string);

    _canonical_request = canonicalize_request(
                                    _http_request_method,
                                    _canonical_uri,
                                    _canonical_query,
                                    map_headers_string(_headers_count, _canonical_headers),
                                    map_signed_headers(_headers_count, _canonical_headers),
                                    sha256_base16(_payload, strlen(_payload))
                                );


    time_t _time;
     _t.tm_sec = 0;
    _t.tm_min = 0;
    _t.tm_hour = 0;
    _t.tm_mon = 4;
    _t.tm_year = 2013 - 1900;
    _t.tm_mday = 24;   
    
    _time = timegm(&_t);

    _credential_scope = credential_scope(
                                            &_time,
                                            "us-east-1",
                                            "s3"
                                        );


    _actual = string_to_sign(
                                "AWS4-HMAC-SHA256",
                                &_time,
                                _credential_scope,
                                sha256_base16(_canonical_request, strlen(_canonical_request))
                            );

    _expected = "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972";

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    return true;
}

bool calculate_signature_verify()
{
    // data taken from amazon http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

    gchar* _actual = NULL;
    gchar* _expected = NULL;

    const gchar* _url = "http://examplebucket.s3.amazonaws.com/test.txt";
    const gchar* _payload = "";

    gchar* _string_to_sign;
    struct tm _t; 


    time_t _time;
     _t.tm_sec = 0;
    _t.tm_min = 0;
    _t.tm_hour = 0;
    _t.tm_mon = 4;
    _t.tm_year = 2013 - 1900;
    _t.tm_mday = 24;   
    
    _time = timegm(&_t);


    _string_to_sign = "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca";

    _actual = calculate_signature
                                    (
                                        &_time, 
                                        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                        "us-east-1",
                                        "s3",
                                        _string_to_sign
                                    );

    _expected = "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543";

    if(strcmp(_actual, _expected) != 0)
    {
        return false;
    }


    return true;
}

int main(int argc, char *argv[]) 
{
    if(HexEncode_verify() == false)
    {
        printf("%s\n","HexEncode failed!");
    }
    else
    {
        printf("%s\n","HexEncode - success!");

    }

    if(strsplit_verify() == false)
    {
        printf("%s\n","strsplit failed!");
    }
    else
    {
        printf("%s\n","strsplit - success!");

    }

    if(sha256_verify() == false)
    {
        printf("%s\n","sha256 - failed!");
    }
    else
    {
        printf("%s\n","sha256 - success!");

    }

    if(sha256_base16_verify() == false)
    {
        printf("%s\n","sha256_base16 - failed!");
    }
    else
    {
        printf("%s\n","sha256_base16 - success!");

    }

    if(ISO8601_date_verify() == false)
    {
        printf("%s\n","ISO8601_date - failed!");
    }
    else
    {
        printf("%s\n","ISO8601_date - success!");

    }

    if(utc_yyyymmdd_verify() == false)
    {
        printf("%s\n","utc_yyyymmdd - failed!");
    }
    else
    {
        printf("%s\n","utc_yyyymmdd - success!");

    }

    if(canonicalize_uri_verify() == false)
    {
        printf("%s\n","canonicalize_uri - failed!");
    }
    else
    {
        printf("%s\n","canonicalize_uri - success!");

    }

    if(canonicalize_query_verify() == false)
    {
        printf("%s\n","canonicalize_query - failed!");
    }
    else
    {
        printf("%s\n","canonicalize_query - success!");

    }

    if(canonicalize_headers_verify() == false)
    {
        printf("%s\n","canonicalize_headers_verify - failed!");
    }
    else
    {
        printf("%s\n","canonicalize_headers_verify - success!");

    }

    if(map_headers_string_verify() == false)
    {
        printf("%s\n","map_headers_string_verify - failed!");
    }
    else
    {
        printf("%s\n","map_headers_string_verify - success!");

    }

    if(map_signed_headers_verify() == false)
    {
        printf("%s\n","map_signed_headers_verify - failed!");
    }
    else
    {
        printf("%s\n","map_signed_headers_verify - success!");

    }

    if(canonicalize_request_verify() == false)
    {
        printf("%s\n","canonicalize_request_verify - failed!");
    }
    else
    {
        printf("%s\n","canonicalize_request_verify - success!");

    }

    if(credential_scope_verify() == false)
    {
        printf("%s\n","credential_scope_verify - failed!");
    }
    else
    {
        printf("%s\n","credential_scope_verify - success!");
    }

    if(string_to_sign_verify() == false)
    {
        printf("%s\n","string_to_sign_verify - failed!");
    }
    else
    {
        printf("%s\n","string_to_sign_verify - success!");
    }

    if(calculate_signature_verify() == false)
    {
        printf("%s\n","calculate_signature_verify - failed!");
    }
    else
    {
        printf("%s\n","calculate_signature_verify - success!");
    }


    // 20110909T233600Z
    struct tm t;
    

    const gchar region[] = "us-east-1\0";
    const gchar service[] = "iam\0";

    const gchar* base_uri = "http://iam.amazonaws.com/\0";
    const gchar* query_args = "";
    const gchar payload[] = "Action=ListUsers&Version=2010-05-08\0";

    const gchar* headers[] = {
                            "host: iam.amazonaws.com\0",
                            "Content-type: application/x-www-form-urlencoded; charset=utf-8\0",
                            "x-amz-date: 20110909T233600Z\0"
                        };

    time_t request_date = timegm(&t);
    GURI* _uri;

    t.tm_sec = 0;
    t.tm_min = 36;
    t.tm_hour = 16;
    t.tm_mon = 8;
    t.tm_year = 2011 - 1900;
    t.tm_isdst = -1; 
    t.tm_mday = 9;   

    _uri = gnet_uri_new("http://iam.amazonaws.com/");

    gchar* canonical_uri = canonicalize_uri(_uri);    
    gchar* canonical_query = canonicalize_query(_uri);
    
    
    const KeyValuePair** canonical_headers_map = canonicalize_headers(3, headers);

    gchar* headers_string = map_headers_string(3,canonical_headers_map);
    gchar* signed_headers = map_signed_headers(3,canonical_headers_map);

    gchar* sha256_payload = sha256_base16(payload, strlen(payload)); 
    
    gchar* canonical_request = canonicalize_request(POST,
                                                               canonical_uri,
                                                               canonical_query,
                                                               headers_string,
                                                               signed_headers,
                                                               sha256_base16(payload, strlen(payload)));
    
    printf("%s\n",g_strconcat("--\n\0", canonical_request, "\n--\n\0", NULL));

    gchar* hashed_canonical_request = sha256_base16(canonical_request, strlen(canonical_request)); 
    printf("%s\n", hashed_canonical_request );

    gchar* cs = credential_scope(&request_date,region,service);

    gchar* sts = string_to_sign(STRING_TO_SIGN_ALGO,
                                                &request_date,
                                                cs,
                                                hashed_canonical_request);

    printf("%s\n",g_strconcat( "--\n\0", sts, "\n----\n\0", NULL));

    const gchar* secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\0";
    
    gchar* signature = calculate_signature(&request_date, 
                                                secret,
                                                region,
                                                service,
                                                sts);
    
    printf("%s\n",signature );
    
    return 0;
}
