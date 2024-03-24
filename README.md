# A TLS Tunnel

A TLS Tunnel base on openSSL.

## develop locally:

#### create a self-signed certificate with openSSL

```shell
$ mkdir cert
$ openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout cert/localhost.key -out cert/localhost.crt -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
$ cat cert/localhost.crt cert/localhost.key > cert/localhost.pem

# on Ubuntu
$ sudo cp cert/localhost.crt /usr/local/share/ca-certificates
$ sudo update-ca-certificates
```

### compile the code

```shell
$ make croxy
```

### and run

```shell
$ ./croxy
$ curl -iv --proxy https://localhost:4433 https://www.bing.com
```

## dependencies

[llhttp](https://github.com/nodejs/llhttp)

[openSSL](https://www.openssl.org/)
