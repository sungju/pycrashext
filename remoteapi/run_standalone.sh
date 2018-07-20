#!/bin/bash

cd web
virtualenv .
source bin/activate
pip install -r requirements.txt

python app.py
