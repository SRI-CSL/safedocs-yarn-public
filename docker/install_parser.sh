#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
DIR=$1
MV_DIR=$2
LIBC=libc-2.31.so
UNAME=user
PARSER_DIR=/processor/parsers/$DIR
ZIP_PATH=$(ls $PARSER_DIR/*.zip)

if [ $? -eq 0 ]; then
    if [ "$MV_DIR" = "." ]; then
	OPT_DIR=/opt
	MV_DIR=""
    else
	OPT_DIR=$(realpath /opt/$DIR)
    fi
    if [ ! -e $OPT_DIR ]; then
	mkdir $OPT_DIR
    fi
    cd $OPT_DIR
    unzip -D -q $ZIP_PATH
    if [ -n "$MV_DIR" ]; then
	cd $OPT_DIR
	mv $MV_DIR/* .
	rm -rf $MV_DIR
	cd ..
    fi

    if [ "$(realpath $OPT_DIR)" = "/opt" ]; then
	OPT_DIR=$(ls -td $OPT_DIR/* | head -n 1)
    fi

    # add link to libc
    ln -s /opt/$LIBC $OPT_DIR/$LIBC
    ln -s $OPT_DIR/$LIBC $OPT_DIR/libc.so.6

    if [ -e $PARSER_DIR/install.sh ]; then
	$PARSER_DIR/install.sh $OPT_DIR
    fi

    if [ -e $PARSER_DIR/README ]; then
	cp $PARSER_DIR/README $OPT_DIR
    fi
    chown -R $UNAME .
fi
