#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
# This is a script that makes it easier to invoke memtrace analysis
# tools within the memtrace docker container without having to
# remember to manually switch between pyenv versions/python
# interpreters
DIR=$(realpath $(dirname $0)) # directory of this tool
TOOLDIR=$DIR/tracetools/tools
readonly COMMAND="$(basename $1)" # get first argument to shell script
shift # shift it off arugment array
# get list of py files in tracetools/tools
readonly SUPPORTED=($(find $DIR/tracetools/tools -maxdepth 1 -name "*.py" -exec basename {} \; | sort))

# list of tools that must be run w/ cpython
readonly CPYCOMMANDS=( gen_bin_metadata.py )

if [ -n "$COMMAND" ]; then # if first argument isn't empty string
    if [[ " ${SUPPORTED[*]} " =~ ${COMMAND} ]]; then # if is supported tool name
	which pyenv 2>&1 >/dev/null # check that pyenv is installed
	if [ $? -eq 0 ]; then
	    readonly GLOBAL=$(pyenv global) # get current value of pyenv global
	    if [[ " ${CPYCOMMANDS[*]} " =~ ${COMMAND} ]]; then
		# values for cpython comand
		WHICH="CPY"
		VERSION=$CPY
		PYTHON=python3
	    else
		# values for pypy command
		WHICH="PYPY"
		VERSION=$PYPY
		PYTHON=pypy3
	    fi
	    if [ -z "$VERSION" ]; then
		# if $PYPY or $CPY (pyenv environment name) env var is empty, cannot continue
		echo "$WHICH environmental variable not set"
		exit 1
	    else
		# change pyenv global to $VERSION
		pyenv global $VERSION
		echo "running $COMMAND"
		# execute command with correct python interpreter,
		# passing remaining arguments
		$PYTHON $TOOLDIR/$COMMAND $@
		# revert to previous pyenv version
		pyenv global $GLOBAL
		# success
		exit 0
	    fi
	else
	    echo "penv is not installed, bailing."
	    exit 1
	fi
    fi
fi
echo "unknown command: '$COMMAND'"
echo "Supported analyses are: ${SUPPORTED[*]}"
exit 1
