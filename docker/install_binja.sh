#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
BINJA_ZIP=BinaryNinja.zip
LICENCE=license.dat
HOME_BINJA=$HOME/.binaryninja

if [ -e $BINJA_ZIP ]; then
    set -e
    mkdir $HOME_BINJA
    sudo unzip $BINJA_ZIP -x 'binaryninja/docs/*' 'binaryninja/api-docs/*' \
	 'binaryninja/scc-docs/*'
    sudo rm $BINJA_ZIP
    if [ -e $LICENCE ]; then
	sudo mv $LICENCE $HOME_BINJA
    fi
    sudo chown -R user /binaryninja $HOME_BINJA
    cd binaryninja

    # binary ninja does not work with pypy, so make sure we are using
    # cPython before installing
    pyenv global $CPY
    bash scripts/linux-setup.sh -s
    # chmod +x $SETUP
    python3 ./scripts/install_api.py
fi
