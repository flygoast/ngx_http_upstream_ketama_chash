# ngx_http_upstream_ketama_chash_module

## Introduction

The `usptream_ketama_chash` module is a load balancer which provides upstream load distribution by hashing a configurable variable using ketama consistent hashing algorithm. 

## Synopsis

    upstream backend {
        ...
        ketama_chash    $request_uri;
    }
    
## Installation

    cd nginx-*version*
    ./configure --add-module=/path/to/this/directory
    make
    make install

## Author

FengGu <flygoast@126.com>
