/*
 * Copyright (c) 2013, FengGu <flygoast@126.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <math.h>


#define KETAMA_NVNODE    160


typedef struct {
    ngx_array_t  *values;
    ngx_array_t  *lengths;
} ngx_http_upstream_ketama_chash_conf_t;


typedef struct {
    uint32_t      point;
    ngx_uint_t    index;
    ngx_array_t  *peer_indexes;
} ngx_http_upstream_ketama_chash_vnode_t;


typedef struct {
    struct sockaddr  *sockaddr;
    socklen_t         socklen;
    ngx_str_t         name;

    ngx_int_t         weight;
    ngx_uint_t        fails;
    ngx_uint_t        max_fails;
    time_t            fail_timeout;
    time_t            accessed;
    time_t            checked;
    ngx_uint_t        down;
} ngx_http_upstream_ketama_chash_peer_t;


typedef struct ngx_http_upstream_ketama_chash_peers_s
    ngx_http_upstream_ketama_chash_peers_t;

struct ngx_http_upstream_ketama_chash_peers_s {
    ngx_uint_t                               number;
    ngx_uint_t                               vnode_number;
    ngx_uint_t                               total_weight;
    unsigned                                 single:1;
    ngx_str_t                               *name;
    ngx_http_upstream_ketama_chash_peers_t  *next;
    ngx_http_upstream_ketama_chash_vnode_t  *continuum;
    ngx_http_upstream_ketama_chash_peer_t    peer[0];
};


typedef struct {
    ngx_http_upstream_ketama_chash_peers_t  *peers;
    uint32_t                                 point;
    ngx_uint_t                               conti_index;
    ngx_uint_t                               index;
} ngx_http_upstream_ketama_chash_peer_data_t;


static int ngx_libc_cdecl ngx_http_cmp_ketama_chash_vnode(const void *one,
    const void *two);
static char *ngx_http_upstream_ketama_chash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_upstream_ketama_chash_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_init_ketama_chash(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_init_ketama_chash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_http_upstream_ketama_chash_peer_t *ngx_http_upstream_get_peer(
    ngx_http_upstream_ketama_chash_peer_data_t *ukchpd, ngx_log_t *log);
static ngx_int_t ngx_http_upstream_get_ketama_chash_peer(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_free_ketama_chash_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static ngx_uint_t ngx_http_upstream_get_ketama_chash_index(
    ngx_http_upstream_ketama_chash_peer_data_t *ukchpd);
static ngx_int_t ngx_http_upstream_ketama_chash_generate_continuum(
    ngx_conf_t *cf, ngx_http_upstream_ketama_chash_peers_t *peers);


static ngx_command_t ngx_http_upstream_ketama_chash_commands[] = {

    { ngx_string("ketama_chash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_ketama_chash,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_upstream_ketama_chash_module_ctx = {
    NULL,                               /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    ngx_http_upstream_ketama_chash_create_conf,
                                        /* create server configuration */
    NULL,                               /* merge server configuration */

    NULL,                               /* create location configuration */
    NULL                                /* merge location configuration */
};


ngx_module_t ngx_http_upstream_ketama_chash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ketama_chash_module_ctx,  /* module context */
    ngx_http_upstream_ketama_chash_commands,     /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_upstream_init_ketama_chash(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                               i, j, n, s, w;
    ngx_http_upstream_server_t              *server;
    ngx_http_upstream_ketama_chash_peers_t  *peers, *backup;

    s = 0;

    us->peer.init = ngx_http_upstream_init_ketama_chash_peer;

    if (!us->servers) {
        return NGX_ERROR;
    }

    server = us->servers->elts;

    n = 0;
    w = 0;
    for (i = 0; i < us->servers->nelts; i++) {
        if (server[i].backup) {
            continue;
        }

        n += server[i].naddrs;
        w += server[i].naddrs * server[i].weight;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no servers in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    peers = ngx_pcalloc(cf->pool, 
                        sizeof(ngx_http_upstream_ketama_chash_peers_t)
                        + sizeof(ngx_http_upstream_ketama_chash_peer_t) * n);
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->total_weight = w;
    peers->name = &us->host;

    n = 0;

    for (i = 0; i < us->servers->nelts; i++) {
        for (j = 0; j < server[i].naddrs; j++) {
            if (server[i].backup) {
                continue;
            }

            peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
            peers->peer[n].socklen = server[i].addrs[j].socklen;
            peers->peer[n].name = server[i].addrs[j].name;
            peers->peer[n].down = server[i].down;
            peers->peer[n].weight = server[i].weight;
            peers->peer[n].max_fails = server[i].max_fails;
            peers->peer[n].fail_timeout = server[i].fail_timeout;
            n++;
        }
    }

    us->peer.data = peers;

    if (peers->number > 1) {
        if (ngx_http_upstream_ketama_chash_generate_continuum(cf, peers)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /* backup servers */

    n = 0;
    w = 0;

    for (i = 0; i < us->servers->nelts; i++) {
        if (!server[i].backup) {
            continue;
        }

        n += server[i].naddrs;
        w += server[i].naddrs * server[i].weight;
    }

    if (n == 0) {
        return NGX_OK;
    }

    backup = ngx_pcalloc(cf->pool, 
                         sizeof(ngx_http_upstream_ketama_chash_peers_t)
                         + sizeof(ngx_http_upstream_ketama_chash_peer_t) * n);
    if (backup == NULL) {
        return NGX_ERROR;
    }

    peers->single = 0;
    backup->single = 0;
    backup->number = n;
    backup->total_weight = w;
    backup->name = &us->host;

    n = 0;

    for (i = 0; i < us->servers->nelts; i++) {
        for (j = 0; j < server[i].naddrs; j++) {
            if (!server[i].backup) {
                continue;
            }

            backup->peer[n].sockaddr = server[i].addrs[j].sockaddr;
            backup->peer[n].socklen = server[i].addrs[j].socklen;
            backup->peer[n].name = server[i].addrs[j].name;
            backup->peer[n].down = server[i].down;
            backup->peer[n].weight = server[i].weight;
            backup->peer[n].max_fails = server[i].max_fails;
            backup->peer[n].fail_timeout = server[i].fail_timeout;
            n++;
        }
    }

    peers->next = backup;

    if (backup->number > 1) {
        if (ngx_http_upstream_ketama_chash_generate_continuum(cf, backup)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_ketama_chash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                                   n;
    ngx_str_t                                    val;
    ngx_http_upstream_ketama_chash_conf_t       *ukchcf;
    ngx_http_upstream_ketama_chash_peer_data_t  *ukchpd;

    ukchcf = ngx_http_conf_upstream_srv_conf(us, 
                                         ngx_http_upstream_ketama_chash_module);

    if (ngx_http_script_run(r, &val, ukchcf->lengths, 0, ukchcf->values)
        == NULL)
    {
        return NGX_ERROR;
    }

    ukchpd = ngx_pcalloc(r->pool, 
                         sizeof(ngx_http_upstream_ketama_chash_peer_data_t));
    if (ukchpd == NULL) {
        return NGX_ERROR;
    }

    /*
     * set by ngx_pcalloc:
     *      ukchpd->index = 0;
     *
     */

    r->upstream->peer.data = ukchpd;

    ukchpd->peers = us->peer.data;

    n = ukchpd->peers->number;

    r->upstream->peer.free = ngx_http_upstream_free_ketama_chash_peer;
    r->upstream->peer.get = ngx_http_upstream_get_ketama_chash_peer;
    r->upstream->peer.tries = ukchpd->peers->number;

    if (ukchpd->peers->number != 1
        || (ukchpd->peers->next && ukchpd->peers->next->number != 1))
    {
        ukchpd->point = ngx_crc32_short(val.data, val.len);
    }

    if (ukchpd->peers->number != 1) {
        ukchpd->conti_index = (ukchpd->point == 0) ? 0 :
                              ngx_http_upstream_get_ketama_chash_index(ukchpd);
    }

    return NGX_OK;
}


static char *
ngx_http_upstream_ketama_chash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_upstream_srv_conf_t           *uscf;
    ngx_http_script_compile_t               sc;
    ngx_str_t                              *value;
    ngx_array_t                            *vars_lengths, *vars_values;
    ngx_http_upstream_ketama_chash_conf_t  *ukchcf;

    value = cf->args->elts;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    vars_lengths = NULL;
    vars_values = NULL;

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &vars_lengths;
    sc.values = &vars_values;
    sc.variables = ngx_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    uscf->peer.init_upstream = ngx_http_upstream_init_ketama_chash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN
                  |NGX_HTTP_UPSTREAM_BACKUP;

    ukchcf = ngx_http_conf_upstream_srv_conf(uscf, 
                                         ngx_http_upstream_ketama_chash_module);
    ukchcf->values = vars_values->elts;
    ukchcf->lengths = vars_lengths->elts;

    return NGX_CONF_OK;
}


static void*
ngx_http_upstream_ketama_chash_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_ketama_chash_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, 
                       sizeof(ngx_http_upstream_ketama_chash_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc();
     *     conf->lengths = NULL;
     *     conf->values = NULL;
     */
    
    return conf;
}


static int ngx_libc_cdecl
ngx_http_cmp_ketama_chash_vnode(const void *one, const void *two)
{
    ngx_http_upstream_ketama_chash_vnode_t  *an, *bn;

    an = (ngx_http_upstream_ketama_chash_vnode_t *)one;
    bn = (ngx_http_upstream_ketama_chash_vnode_t *)two;

    return (an->point < bn->point) ? -1 : ((an->point > bn->point) ? 1 : 0);
}


static ngx_uint_t 
ngx_http_upstream_get_ketama_chash_index(
    ngx_http_upstream_ketama_chash_peer_data_t *ukchpd)
{
    uint32_t                                 hash;
    ngx_uint_t                               highp, lowp, midp;
    ngx_uint_t                               midval, midval1;
    ngx_http_upstream_ketama_chash_vnode_t  *vnodes;

    lowp = 0;
    highp = ukchpd->peers->vnode_number;
    vnodes = ukchpd->peers->continuum;
    hash = ukchpd->point;

    /* divide and conquer array search to find server with next
     * biggest point after what this key hashes to */
    while (1) {
        midp = (ngx_int_t)((lowp + highp) / 2);
        if (midp == ukchpd->peers->vnode_number) {
            return 0; /* if at the end, roll back to zeroth */
        }

        midval = vnodes[midp].point;
        midval1 = (midp == 0 ? 0 : vnodes[midp - 1].point);
        if (hash <= midval && hash > midval1) {
            return midp;
        }
        
        if (midval < hash) {
            lowp = midp + 1;
        } else {
            highp = midp - 1;
        }

        if (lowp > highp) {
            return 0;
        }
    }

    /* never get here */
    return 0;
}


static ngx_http_upstream_ketama_chash_peer_t *
ngx_http_upstream_get_peer(ngx_http_upstream_ketama_chash_peer_data_t *ukchpd,
    ngx_log_t *log)
{
    ngx_uint_t                               i, p, *value;
    time_t                                   now;
    ngx_http_upstream_ketama_chash_peer_t   *peer;
    ngx_http_upstream_ketama_chash_vnode_t  *vnodes;
    ngx_http_upstream_ketama_chash_peers_t  *peers = ukchpd->peers;

    peer = NULL;
    now = ngx_time();

    vnodes = peers->continuum;

    value = peers->continuum[ukchpd->conti_index].peer_indexes->elts;

    for (i = ukchpd->index;
         i < peers->continuum[ukchpd->conti_index].peer_indexes->nelts;
         i++)
    {
        ukchpd->index++;

        p = value[i];

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "test ketama peer, index: %ud, peer: %ud",
                       ukchpd->conti_index, p);

        peer = &peers->peer[p];
    
        if (peer->down) {
            continue;
        }
    
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "get ketama peer, index: %ui, peer: %ui",
                       ukchpd->conti_index, p);
        break;
    }

    if (i == peers->continuum[ukchpd->conti_index].peer_indexes->nelts) {
        return NULL;
    }

    peer->checked = now;

    return peer;
}


static ngx_int_t
ngx_http_upstream_get_ketama_chash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_int_t                                    rc;
    ngx_uint_t                                   i;
    ngx_http_upstream_ketama_chash_peer_t       *peer;
    ngx_http_upstream_ketama_chash_peers_t      *peers;
    ngx_http_upstream_ketama_chash_peer_data_t  *ukchpd = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ketama peer, try: %ui", pc->tries);

    pc->cached = 0;
    pc->connection = NULL;

    if (ukchpd->peers->number == 1) {
        if (ukchpd->index > 0) { /* peer accessed */
            goto failed;
        }

        ukchpd->index++;

        peer = &ukchpd->peers->peer[0];

        if (peer->down) {
            goto failed;
        }

    } else {

        /* there are several peers */

        peer = ngx_http_upstream_get_peer(ukchpd, pc->log);

        if (peer == NULL) {
            goto failed;
        }
    }
        
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    if (pc->tries == 1 && ukchpd->peers->next) {
        pc->tries += ukchpd->peers->next->number;
    }

    return NGX_OK;

failed:

    peers = ukchpd->peers;

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "ketama chash backup servers");

        ukchpd->peers = peers->next;
        ukchpd->index = 0;
        pc->tries = ukchpd->peers->number;

        if (ukchpd->peers->number != 1) {
            ukchpd->conti_index = (ukchpd->point == 0) ? 0 :
                               ngx_http_upstream_get_ketama_chash_index(ukchpd);
        }

        rc = ngx_http_upstream_get_ketama_chash_peer(pc, ukchpd);

        if (rc != NGX_BUSY) {
            return rc;
        }
    }

    /* all peers failed, mark them as live for quick recovery */

    for (i = 0; i < peers->number; i++) {
        peers->peer[i].fails = 0;
    }

    pc->name = peers->name;

    return NGX_BUSY;
}


static void
ngx_http_upstream_free_ketama_chash_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
    ngx_http_upstream_ketama_chash_peer_data_t  *ukchpd = data;
    time_t                                       now;
    ngx_uint_t                                   p, *value;
    ngx_http_upstream_ketama_chash_peer_t       *peer;
    

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free ketama peer %ui %ui", pc->tries, state);

    if (state == 0 && pc->tries == 0) {
        return;
    }

    if (ukchpd->peers->single) {
        pc->tries = 0;
        return;
    }

    if (ukchpd->peers->number == 1) {
        p = 0;

    } else {
        value = ukchpd->peers->continuum[ukchpd->conti_index].peer_indexes->elts;
        p = value[ukchpd->index - 1];
    }

    peer = &ukchpd->peers->peer[p];

    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        peer->fails++;
        peer->accessed = now;
        peer->checked = now;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "free failed ketama peer: index: %ui, p: %ui",
                       ukchpd->index, p);

    } else {

        /* mark peer live if check parsed */

        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }
    }

    if (pc->tries) {
        pc->tries--;
    }
}


static ngx_int_t
ngx_http_upstream_ketama_chash_generate_continuum(ngx_conf_t *cf,
    ngx_http_upstream_ketama_chash_peers_t *peers)
{
    ngx_uint_t                               i, j, m, n, p, s, nvnode, last;
    ngx_uint_t                              *peer_index;
    ngx_uint_t                              *checked, check_data;
    u_char                                   tmp_vnode[32];
    u_char                                   result[16];
    ngx_md5_t                                md5;
    float                                    percent;
    ngx_array_t                             *peer_indexes, *last_indexes;
    ngx_http_upstream_ketama_chash_vnode_t  *vnode;

    n = KETAMA_NVNODE * peers->number;

    peers->continuum = ngx_pcalloc(cf->pool,
                            n * sizeof(ngx_http_upstream_ketama_chash_vnode_t));
    if (peers->continuum == NULL) {
        return NGX_ERROR;
    }

    peers->vnode_number = 0;

    /* generate the consistent hash continuum */
    for (i = 0; i < peers->number; i++) {
        percent = (float)peers->peer[i].weight / (float)peers->total_weight;
        nvnode = floorf(percent * (KETAMA_NVNODE / 4) * peers->number);

        for (j = 0; j < nvnode; j++) {

            ngx_snprintf(tmp_vnode, sizeof(tmp_vnode), "%V-%ui%Z",
                         &peers->peer[i].name, j);
            ngx_md5_init(&md5);
            ngx_md5_update(&md5, tmp_vnode, ngx_strlen(tmp_vnode));
            ngx_md5_final(result, &md5);

            for (n = 0; n < 4; n++) {
                vnode = &peers->continuum[peers->vnode_number++];

                vnode->point = (result[3 + n * 4] << 24)
                               |(result[2 + n * 4] << 16)
                               |(result[1 + n * 4] << 8)
                               |(result[n * 4]);
                vnode->index = i;
            }
        }
    }

    /* sort in ascending order of "point" */
    ngx_qsort(peers->continuum, 
              (size_t)peers->vnode_number,
              sizeof(ngx_http_upstream_ketama_chash_vnode_t), 
              ngx_http_cmp_ketama_chash_vnode);

    s = 0;

    if (peers->number <= 8 * sizeof(uintptr_t)) {
        checked = &check_data;

    } else {
        s = (peers->number + (8 * sizeof(uintptr_t) - 1))
            / (8 * sizeof(uintptr_t));

        checked = ngx_palloc(cf->temp_pool, s * sizeof(uintptr_t));
        if (checked == NULL) {
            return NGX_ERROR;
        }
    }

    /* process the first continuum slot */

    if (peers->number <= 8 * sizeof(uintptr_t)) {
        *checked = 0;

    } else {
        ngx_memzero(checked, s * sizeof(uintptr_t));
    }

    peer_indexes = ngx_array_create(cf->pool, peers->number,
                                    sizeof(ngx_uint_t));
    if (peer_indexes == NULL) {
        return NGX_ERROR;
    }

    p = peers->continuum[0].index;
    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    peer_index = ngx_array_push(peer_indexes);
    if (peer_index == NULL) {
        return NGX_ERROR;
    }

    *peer_index = p;
    checked[n] |= m;

    for (j = 1; j < peers->vnode_number; j++) {

        p = peers->continuum[j].index;
        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (checked[n] & m) {
            continue;
        }

        checked[n] |= m;

        peer_index = ngx_array_push(peer_indexes);
        if (peer_index == NULL) {
            return NGX_ERROR;
        }

        *peer_index = peers->continuum[j].index;
    }

    peers->continuum[0].peer_indexes = peer_indexes;

    if (peer_indexes->nelts != peers->number) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "invalid peer index number in continuum[0]");
        return NGX_ERROR;
    }

    last = peers->continuum[0].index;
    last_indexes = peers->continuum[0].peer_indexes;
    for (j = peers->vnode_number - 1; j > 0; j--) {

        p = peers->continuum[j].index;
        if (p == last) {
            peers->continuum[j].peer_indexes = last_indexes;
            continue;
        }

        if (peers->number <= 8 * sizeof(uintptr_t)) {
            *checked = 0;

        } else {
            ngx_memzero(checked, s * sizeof(uintptr_t));
        }

        peer_indexes = ngx_array_create(cf->pool, peers->number,
                                        sizeof(ngx_uint_t));
        if (peer_indexes == NULL) {
            return NGX_ERROR;
        }

        peer_index = ngx_array_push(peer_indexes);
        if (peer_index == NULL) {
            return NGX_ERROR;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        *peer_index = p;
        checked[n] |= m;

        for (i = (j + 1) % peers->vnode_number;
             i != j;
             i = (i + 1) % peers->vnode_number)
        {
            p = peers->continuum[i].index;
            n = p / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

            if (checked[n] & m) {
                continue;
            }

            checked[n] |= m;

            peer_index = ngx_array_push(peer_indexes);
            if (peer_index == NULL) {
                return NGX_ERROR;
            }

            *peer_index = peers->continuum[i].index;

            if (peer_indexes->nelts == peers->number) {
                break;
            }
        }

        peers->continuum[j].peer_indexes = peer_indexes;

        if (peer_indexes->nelts != peers->number) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "invalid peer index number in continuum[%ud]",
                          j);
            return NGX_ERROR;
        }

        last = peers->continuum[j].index;
        last_indexes = peer_indexes;
    }

#if 1
    {
    u_char       buf[1024];
    u_char      *p, *end;
    ngx_uint_t  *value;

    for (i = 0; i < peers->vnode_number; i++) {
        p = buf;
        end = buf + sizeof(buf);
        peer_indexes = peers->continuum[i].peer_indexes;
        value = peer_indexes->elts;

        for (n = 0; n < peer_indexes->nelts; n++) {
            p = ngx_slprintf(p, end, "%ud-", value[n]);
        }

        if (p > buf && *(p - 1) == '-') {
            *(p - 1) = '\0';
        }

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                      "vnode[%ud] point: %uD, index: %ud, p: %p, indexes: %s",
                      i,
                      peers->continuum[i].point,
                      peers->continuum[i].index,
                      peers->continuum[i].peer_indexes,
                      buf);
    }
    }
#endif

    return NGX_OK;
}
