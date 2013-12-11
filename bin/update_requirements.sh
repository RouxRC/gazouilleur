#!/bin/bash

source $(which virtualenvwrapper.sh)
workon gazouilleur
pip install -r requirements.txt
deactivate

