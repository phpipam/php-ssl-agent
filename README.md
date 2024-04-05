php-ssl-agent is a http API that accepts 2 parameters, hostname and port and does and SSL scan and tries to fetch certificate and returns result bach to main php-ssl instance.

Example call from main instance to agent:
```
[root@php-ssl /usr/local/www] curl http://php-ssl-agent.mydomain.com/google.com/443/
{
   "code" : 200,
   "result" : {
      "certificate" : "-----BEGIN CERTIFICATE-----\n REDACTED \n-----END CERTIFICATE-----",
      "chain" : "-----BEGIN CERTIFICATE-----\n REDACTED \n-----END CERTIFICATE-----",
      "created" : "2024-04-05 07:24:28",
      "expires" : "2024-05-27 06:35:49",
      "ip" : "142.251.208.142",
      "port" : "443",
      "serial" : "0x9BD38B8CA681AB151096F2CF1FC71615",
      "success" : true
   },
   "success" : true,
   "time" : "0.046 s"
}


[root@php-ssl /usr/local/www] curl http://php-ssl-agent.mydomain.com/google1.com/443/
{
   "code" : 500,
   "result" : {
      "code" : 500,
      "error" : "php_network_getaddresses: getaddrinfo for google1.com failed: Address family for hostname not supported",
      "ip" : "google1.com",
      "success" : false
   },
   "success" : false,
   "time" : "0.083 s"
}
```

## required php modules
```
[root@php-ssl-agent /usr/local/etc/nginx] % php -m
[PHP Modules]
Core
ctype
curl
date
filter
hash
json
openssl
pcre
posix
random
Reflection
SPL
standard
```

## nginx configuration

Sample nginx config:
```
[root@php-ssl-agent /usr/local/etc/nginx] % more nginx.conf
http {
    include       mime.types;
    default_type  application/octet-stream;

    # logi
    access_log  /var/log/nginx/www.access.log;
    error_log  /var/log/nginx/www.error.log;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    gzip  on;

    # hide version
    server_tokens off;

    server {
        listen       80;
        server_name  _;

        root   /var/www;

        location / {
            # ACL - permit only master instance
            allow 172.17.128.111/32;
            deny all;

            try_files $uri $uri/ /index.php;
            index  index.php;
        }

        error_page 404 /index.php?app=error&page=404;

        # php-fpm
        location ~ \.php$ {
            fastcgi_pass   unix:/var/run/php-fpm.socket;
            fastcgi_index  index.php;
            try_files      $uri $uri/ index.php = 404;
            include        fastcgi_params;
        }
    }
}
```

fastcgi_params:
```
[root@php-ssl-agent /usr/local/etc/nginx] % more fastcgi_params

fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;

fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;

fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;

fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;

```

## php-fpm configuration (filtered, relevant part only)
```
[root@php-ssl-agent /usr/local/etc/php-fpm.d] % more www.conf
; Unix user/group of the child processes. 
user = www
group = www

; The address on which to accept FastCGI requests.
listen = /var/run/php-fpm.socket

; Set permissions for unix socket
listen.owner = www
listen.group = www

; The number of child processes to be created when pm is set to 'static' and the
; maximum number of child processes when pm is set to 'dynamic' or 'ondemand'.
pm.max_children = 64

; The number of child processes created on startup.
pm.start_servers = 32

; The desired minimum number of idle server processes.
pm.min_spare_servers = 32

; The desired maximum number of idle server processes.
pm.max_spare_servers = 32

; The access log file
access.log = /var/log/$pool.access.log

; Redirect worker stdout and stderr into main error log.
catch_workers_output = yes

; Additional php.ini defines, specific to this pool of workers.
php_flag[display_errors] = on
php_admin_value[error_log] = /var/log/fpm-php.www.log
php_admin_flag[log_errors] = on
```
