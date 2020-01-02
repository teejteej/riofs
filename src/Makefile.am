AM_CPPFLAGS = -I$(top_srcdir)/include -DSYSCONFDIR=\""$(sysconfdir)/@PACKAGE@/"\"
bin_PROGRAMS = riofs
riofs_SOURCES = $(abs_srcdir)/log.c
riofs_SOURCES += $(abs_srcdir)/dir_tree.c
riofs_SOURCES += $(abs_srcdir)/awsv4.c
riofs_SOURCES += $(abs_srcdir)/urltools.c
riofs_SOURCES += $(abs_srcdir)/rfuse.c
riofs_SOURCES += $(abs_srcdir)/http_connection.c
riofs_SOURCES += $(abs_srcdir)/http_connection_dir_list.c
riofs_SOURCES += $(abs_srcdir)/bucket_client.c
riofs_SOURCES += $(abs_srcdir)/client_pool.c
riofs_SOURCES += $(abs_srcdir)/file_io_ops.c
riofs_SOURCES += $(abs_srcdir)/cache_mng.c
riofs_SOURCES += $(abs_srcdir)/stat_srv.c
riofs_SOURCES += $(abs_srcdir)/utils.c
riofs_SOURCES += $(abs_srcdir)/conf.c
riofs_SOURCES += $(abs_srcdir)/range.c
riofs_SOURCES += $(abs_srcdir)/main.c

riofs_CFLAGS = $(AM_CFLAGS) $(DEPS_CFLAGS) $(LEDEPS_CFLAGS) $(LIBEVENT_OPENSSL_CFLAGS) $(SSL_CFLAGS) $(MAGIC_CFLAGS)
riofs_LDADD = $(AM_LDADD) $(DEPS_LIBS) $(LEDEPS_LIBS) $(LIBEVENT_OPENSSL_LIBS) $(SSL_LIBS) $(MAGIC_LDFLAGS) $(MAGIC_LIBS)
