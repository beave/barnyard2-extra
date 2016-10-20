#!/bin/bash -v

# This is for building on Debian Jessie

./autogen.sh

./configure --enable-dns --enable-healthcheck --prefix=/usr --with-mysql

make -j5

make install

/usr/bin/barnyard2 -V

