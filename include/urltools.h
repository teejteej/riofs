#ifndef URLTOOLS_H
#define URLTOOLS_H

#include "global.h"

gchar *url_decode(gchar *str);
gchar *url_encode(gchar *str, bool encode_slash);

#endif
