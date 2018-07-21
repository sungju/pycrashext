#!/bin/bash

usage() {
	echo 
	echo "To run this server as a standalone, you need to have"
	echo "the below commands installed."
	echo
	echo "python"
	echo "virtualenv"
	echo "pip"
	echo
}

cd web
virtualenv .  >/dev/null 2>&1 || { usage; exit -1; }
source bin/activate
pip install -r requirements.txt  >/dev/null 2>&1 || { usage; exit -2; }

python app.py || { usage; exit -3; }
