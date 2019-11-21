/*
 *
 * Nginx module to run Azwaf in-proc within an Nginx worker, as opposed to running as a standalone process connected via gRPC.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../bodyreading.h"

static ngx_int_t ngx_http_azwaf_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_azwaf_handler_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_azwaf_handler(ngx_http_request_t *r);
static void* ngx_http_azwaf_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_azwaf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

typedef struct {
    ngx_str_t secrule_conf;
} ngx_http_azwaf_loc_conf_t;

// Module directives
static ngx_command_t ngx_http_azwaf_commands[] = {
    {
        ngx_string("azwaf"),
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_azwaf_loc_conf_t, secrule_conf),
        NULL
    },
    ngx_null_command
};

// Module context
static ngx_http_module_t ngx_http_azwaf_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_azwaf_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_azwaf_create_loc_conf, /* create location configuration */
    ngx_http_azwaf_merge_loc_conf /* merge location configuration */
};


// Module definition
ngx_module_t ngx_http_azwaf_module = {
    NGX_MODULE_V1,
    &ngx_http_azwaf_module_ctx, /* module context */
    ngx_http_azwaf_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    ngx_http_azwaf_handler_init_worker, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};


static void* ngx_http_azwaf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_azwaf_loc_conf_t *conf;

    conf = (ngx_http_azwaf_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_azwaf_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char* ngx_http_azwaf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    (void)(cf); // Not used

    ngx_http_azwaf_loc_conf_t *prev = (ngx_http_azwaf_loc_conf_t*)parent;
    ngx_http_azwaf_loc_conf_t *conf = (ngx_http_azwaf_loc_conf_t*)child;

    ngx_conf_merge_str_value(conf->secrule_conf, prev->secrule_conf, "");

    return NGX_CONF_OK;
}

static ngx_uint_t request_id_index;

static ngx_str_t get_request_id(ngx_http_request_t *r) {
    ngx_str_t request_id_str;
    request_id_str.data = NULL;
    request_id_str.len = 0;

    ngx_http_variable_value_t* request_id = ngx_http_get_indexed_variable(r, request_id_index);
    if (request_id != NULL && !request_id->not_found) {
        request_id_str.data = request_id->data;
        request_id_str.len = request_id->len;
    }

    return request_id_str;
}

static ngx_int_t ngx_http_azwaf_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    cmcf = (ngx_http_core_main_conf_t*)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // Add this module's handler to the pipeline
    ngx_http_handler_pt *h;
    h = (ngx_http_handler_pt*)ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_azwaf_handler;

    ngx_str_t request_id_varname = ngx_string("request_id");
    request_id_index = (ngx_uint_t)ngx_http_get_variable_index(cf, &request_id_varname);

    return NGX_OK;
}

static ngx_int_t ngx_http_azwaf_handler_init_worker(ngx_cycle_t *cycle)
{
    (void)(cycle); // Not used

    return NGX_OK;
}

static void ngx_http_azwaf_body_handler(ngx_http_request_t *r)
{
    // similar to https://github.com/nbs-system/naxsi/blob/f2380e7d0cda3e451446914dcf71cb149d4b494e/naxsi_src/naxsi_runtime.c#L2348
    // similar to https://github.com/openresty/srcache-nginx-module/blob/53a98806b0a24cc736d11003662e8b769c3e7eb3/src/ngx_http_srcache_fetch.c#L443
    r->main->count--; // this looks strange, but requests hang on keepalive without this line
    ngx_http_core_run_phases(r);
}

typedef int (*AzwafEvalRequestFn)(ngx_str_t, ngx_str_t, ngx_http_request_t*, ngxReadFileFn cb);
static AzwafEvalRequestFn AzwafEvalRequest = NULL;
static void *azwaf_module = NULL;

static ngx_int_t load_azwaf_shared_object(ngx_log_t* log)
{
    char *sopath = "./azwafnginxinproc.so";
    struct stat statbuffer;
    if(stat(sopath, &statbuffer) != 0) {
        // Shared object file was not in current directory. Use system dynamic linker search instead.
        sopath = "azwafnginxinproc.so";
    }

    char *error;

    azwaf_module = dlopen(sopath, RTLD_NOW);
    if (!azwaf_module) {
        if ((error = dlerror()) != NULL)  {
            ngx_log_error(NGX_LOG_ERR, log, 0, "%s", error);
        }

        return NGX_ERROR;
    }

    AzwafEvalRequest = (AzwafEvalRequestFn) dlsym(azwaf_module, "AzwafEvalRequest");
    if ((error = dlerror()) != NULL)  {
        ngx_log_error(NGX_LOG_ERR, log, 0, "%s", error);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_azwaf_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;

    ngx_http_azwaf_loc_conf_t *cf = (ngx_http_azwaf_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_azwaf_module);

    // Is module not enabled for this config section?
    if (cf->secrule_conf.len == 0) {
        return NGX_DECLINED;
    }

    // Process only main request
    if (r->main != r || r->internal) {
        return NGX_DECLINED;
    }

    // Load shared object if not already loaded. Doing this here rather than ngx_http_azwaf_handler_init_worker to avoid crashing if azwaf isn't configured to be used anyway.
    // TODO Consider moving to ngx_http_azwaf_handler_init_worker for better first-request perf
    if (azwaf_module == NULL) {
        rc = load_azwaf_shared_object(r->connection->log);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    // Read body if not yet read
    if (!r->request_body) {
        rc = ngx_http_read_client_request_body(r, ngx_http_azwaf_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;
    }

    // TODO consider moving this to worker threads to avoid blocking the Nginx main loop
    if(!AzwafEvalRequest(get_request_id(r), cf->secrule_conf, r, ngx_read_file)) {
        return 403;
    }

    return NGX_DECLINED;
}
