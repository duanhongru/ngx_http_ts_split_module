#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <inttypes.h>

typedef struct {
    ngx_uint_t media_begin;
    ngx_uint_t media_len;
} ngx_http_ts_split_media_index_t;


static char * ngx_http_ts_split(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_ts_split_rpartition(const ngx_str_t *src, ngx_str_t *first,
        ngx_str_t *second, u_char delim);
static ngx_str_t ngx_http_ts_split_get_media_name(const ngx_str_t *src);
static ngx_int_t ngx_http_ts_split_get_media_seq(const ngx_str_t *src);
static ngx_int_t ngx_http_ts_split_index_info(ngx_http_request_t *r,
        ngx_str_t *index_path, ngx_int_t media_seq, ngx_uint_t *media_begin,
        ngx_uint_t *media_len);
static ngx_int_t ngx_http_ts_split_handler(ngx_http_request_t *r);

static ngx_command_t  ngx_http_ts_split_commands[] = {

    { ngx_string("ts_split"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_ts_split,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

ngx_http_module_t  ngx_http_ts_split_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,     /* create location configuration */
    NULL       /* merge location configuration */
};


ngx_module_t  ngx_http_ts_split_module = {
    NGX_MODULE_V1,
    &ngx_http_ts_split_module_ctx,           /* module context */
    ngx_http_ts_split_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};




static char *
ngx_http_ts_split(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_ts_split_handler;

    return NGX_CONF_OK;
}

static void
ngx_http_ts_split_rpartition(const ngx_str_t *src, ngx_str_t *first,
        ngx_str_t *second, u_char delim)
{
    u_char  *p;

    for (p = src->data + src->len; p >= src->data; p--) {
        if (*p == delim) {
            first->data = src->data;
            first->len = p - first->data;
            second->data = p + 1;
            second->len = src->len - first->len - 1;
            break;

        }
    }

    return;
}

static ngx_str_t
ngx_http_ts_split_get_media_name(const ngx_str_t *src)
{
    u_char *p;
    ngx_uint_t count;
    ngx_str_t media;

    count = 0;
    for (p = src->data + src->len; p != src->data; p--) {
        if (*p == '.') {
            count++;
        }

        if (count == 3) {
            break;
        }
    }

    media.data = src->data;
    media.len = p - src->data;

    return media;
}

static ngx_int_t
ngx_http_ts_split_get_media_seq(const ngx_str_t *src)
{
    u_char *p, *begin, *end;
    ngx_uint_t count;
    ngx_str_t media_seq;

    count = 0;
    begin = NULL;
    end = NULL;
    for (p = src->data + src->len; p != src->data; p--) {
        if (*p == '.') {
            count++;
        }

        if (count == 2 && end == NULL) {
            end = p;
        }

        if (count == 3 && begin == NULL) {
            begin = p + 1;
        }

        if (begin != NULL && end != NULL) {
            break;
        }
    }


    if (begin != NULL && end != NULL) {
        media_seq.data = begin;
        media_seq.len = end - begin;

        return ngx_atoi(media_seq.data, media_seq.len);
    }

    return NGX_ERROR;

}


static ngx_int_t
ngx_http_ts_split_index_info(ngx_http_request_t *r, ngx_str_t *index_path,
        ngx_int_t media_seq, ngx_uint_t *media_begin, ngx_uint_t *media_len)
{
    ngx_http_ts_split_media_index_t *addr;
    ngx_open_file_info_t  of;
    ngx_log_t *log;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_uint_t level;
    ngx_int_t rc;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    log = r->connection->log;
    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, index_path, &of) != NGX_OK) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, index_path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, index_path->data);
        }

        return rc;
    }

    addr = (ngx_http_ts_split_media_index_t *)mmap(NULL, of.size, PROT_READ,
            MAP_SHARED, of.fd, 0);
    if (addr == MAP_FAILED) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "mmap(%uz) \"%V\" %s", of.size, index_path,
                      strerror(errno));
        return NGX_ERROR;
    }

    ngx_http_ts_split_media_index_t *media_index =
            (ngx_http_ts_split_media_index_t *)addr + media_seq/10;
    *media_begin = media_index->media_begin;
    *media_len = media_index->media_len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ts_split_handler(ngx_http_request_t *r)
{
    u_char                    *last;
    size_t                     root;
    ngx_str_t                  path, index_path, media_path;
    ngx_str_t                  first, second, media_name;
    ngx_int_t                  rc, media_seq;
    ngx_uint_t                 media_begin, media_len;
    ngx_uint_t                 level;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_log_t                 *log;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
          return NGX_HTTP_NOT_ALLOWED;
      }

    if (r->uri.data[r->uri.len - 1] == '/') {
      return NGX_DECLINED;
    }

    ngx_str_null(&media_name);
    ngx_str_null(&second);
    log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                 "http filename: \"%s\"", path.data);



    ngx_http_ts_split_rpartition(&path, &first, &second, '/');

    index_path.len = first.len + sizeof("index.m3u8") + 1;
    index_path.data = ngx_palloc(r->pool, index_path.len);

    ngx_snprintf(index_path.data, index_path.len, "%V/index.m3u8", &first);


    index_path.data[index_path.len-1] = '\0';

    media_name = ngx_http_ts_split_get_media_name(&second);

    media_path.len = first.len + 5 + media_name.len;
    media_path.data = ngx_palloc(r->pool, media_path.len);

    ngx_snprintf(media_path.data, media_path.len, "%V/%V.ts", &first,
                &media_name);


    media_path.data[media_path.len-1] = '\0';


    media_seq = ngx_http_ts_split_get_media_seq(&second);
    media_begin = 0;
    media_len = 0;
    if (ngx_http_ts_split_index_info(r, &index_path, media_seq, &media_begin,
            &media_len) != NGX_OK) {
        return NGX_ERROR;
    }
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &media_path, &of) != NGX_OK) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &media_path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, media_path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;




#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    if (r->method & NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = media_len;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    /* we need to allocate all before the header would be sent */

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = media_begin;
    b->file_last = media_begin + media_len;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = media_path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
