#!/bin/bash

source $(which virtualenvwrapper.sh)
workon gazouilleur
pip uninstall -y twitter
pip install -r requirements.txt
deactivate

