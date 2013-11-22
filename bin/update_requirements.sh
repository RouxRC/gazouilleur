#!/bin/bash

source /usr/local/bin/virtualenvwrapper.sh
workon gazouilleur
pip install -r requirements.txt
deactivate

