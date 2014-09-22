#!/bin/bash

source $(which virtualenvwrapper.sh)
workon gazouilleur
pip install -r requirements.txt --upgrade || echo 'Please complete apt/yum dependencies first (see "### Requirements" in README.md'
deactivate

