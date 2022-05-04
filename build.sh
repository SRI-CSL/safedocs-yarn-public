#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
set -e

BUILD_RIO=1
DELETE=0
BUILD_OPTS=""
DIR=$(realpath $(dirname 0))
# NAME=mr_memtrace-analysis-dev
NAME=yarn
while getopts "hnd" opt ; do
    case ${opt} in
	  h )
	      echo "$0: accepts -d (remove image from docker first), --nocache (dont use docker cache)"
	      exit 0
	      ;;
	  d )
	      DELETE=1
	      ;;
	  n )
	      BUILD_OPTS+="--no-cache"
	      ;;
    esac
done
shift $(expr $OPTIND - 1 )

# make sure parser zips have been downloaded correctly
ZIP=$(ls parsers/*/*.zip | head -n 1)
zip -Tq $ZIP
if [ $? -ne 0 ]; then
    echo "Did not find a proper zip file at $ZIP.  Make sure git-lfs is installed and then reclone this repository from scratch" >&2
    exit 1
fi

# quick if any of the follow commands isn't successful
set +e
if [ $BUILD_RIO -eq 1 ]; then
    if [ $DELETE -eq 1 ]; then
	docker rmi $NAME
    fi
    docker build $@ $BUILD_OPTS -t $NAME -f docker/Dockerfile.memtrace .
fi
