// Very simplified versions of the Nginx structs we are using, just to be able to compile while testing without having an entire built Nginx source tree.

#include <stdlib.h>
#include <stdint.h>

// src/core/ngx_string.h
typedef struct {
    size_t len;
    u_char *data;
} ngx_str_t;

// src/core/ngx_config.h
typedef uintptr_t ngx_uint_t;

// src/core/ngx_list.h
typedef struct ngx_list_part_s  ngx_list_part_t;
struct ngx_list_part_s {
    void *elts;
    ngx_uint_t nelts;
    ngx_list_part_t *next;
};

// src/core/ngx_list.h
typedef struct {
    ngx_list_part_t part;
} ngx_list_t;

// src/http/ngx_http_request.h
typedef struct {
    ngx_list_t headers;
} ngx_http_headers_in_t;

// src/core/ngx_core.h
typedef struct ngx_chain_s ngx_chain_t;

// src/core/ngx_buf.h
typedef struct ngx_buf_s  ngx_buf_t;
struct ngx_buf_s {
    u_char *pos;
    u_char *last;
};

// src/core/ngx_buf.h
struct ngx_chain_s {
    ngx_buf_t *buf;
    ngx_chain_t *next;
};

// src/core/ngx_core.h
typedef struct ngx_file_s ngx_file_t;

// src/core/ngx_file.h
struct ngx_file_s {
};

// src/core/ngx_file.h
typedef struct {
    ngx_file_t file;
} ngx_temp_file_t;

// src/http/ngx_http_request.h
typedef struct {
    ngx_temp_file_t *temp_file;
    ngx_chain_t *bufs;
} ngx_http_request_body_t;

// src/http/ngx_http.h
typedef struct ngx_http_request_s ngx_http_request_t;

// src/http/ngx_http_request.h
struct ngx_http_request_s {
    ngx_http_headers_in_t headers_in;
    ngx_http_request_body_t *request_body;
    ngx_str_t unparsed_uri;
    ngx_str_t method_name;
    ngx_str_t http_protocol;
};

// src/core/ngx_hash.h
typedef struct {
    ngx_str_t key;
    ngx_str_t value;
} ngx_table_elt_t;
