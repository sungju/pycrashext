#!/bin/bash

rm -rf bin/

python3 -m venv --upgrade-deps .
MYOS="$OSTYPE"
if ( test "$MYOS" = "msys" ); then
	source Scripts/activate.bat
else
	. bin/activate
fi

pip3 install wheel
python3 setup.py bdist_wheel 

pip3 install -r requirements.txt

python3 app.py
