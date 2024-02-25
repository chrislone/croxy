

```shell
$ mkdir cert
$ openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout cert/localhost.key -out cert/localhost.crt -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
$ cat cert/localhost.crt cert/localhost.key > cert/localhost.pem

# on Ubuntu
$ sudo cp localhost.crt /usr/local/share/ca-certificates
$ sudo update-ca-certificates
```

```shell
$ make croxy
$ ./croxy
$ curl -iv --proxy https://localhost:4433 https://www.bing.com
```
