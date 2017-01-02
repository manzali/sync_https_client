# sync_https_client

Example of a simple sync client that performs a POST over https. The client is written in c++ using boost asio and openssl.

In order to compile run inside the build directory:

cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl ..
