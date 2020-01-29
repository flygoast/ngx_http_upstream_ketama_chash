# ngx_http_upstream_ketama_chash_module

## Introduction

The `usptream_ketama_chash` module is a load balancer which provides upstream load distribution by hashing a configurable variable using ketama consistent hashing algorithm. 

## Synopsis

    upstream backend {
        ...
        ketama_chash    $uri;
    }
    
## Installation (as a Dynamic module)

    cd nginx-*version*
    ./configure --with-compat --add-dynamic-module=/path/to/this/directory
    make modules
    cp objs/ngx_http_upstream_ketama_chash_module.so /etc/nginx/modules

In order to use this module, add these lines in /etc/nginx/nginx.conf (after `pid` line)

    load_module modules/ngx_http_upstream_ketama_chash_module.so;

After the module added, reload nginx for seeing the changes:

    nginx -s reload

## Author

FengGu <flygoast@126.com>
