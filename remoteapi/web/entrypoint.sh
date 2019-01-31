#!/bin/bash

rm -rf bin/

python3 -m venv .
. bin/activate

export PYTHONPATH="/usr/lib/python3/dist-packages:/usr/local/lib/python3.6/dist-packages:/usr/lib/python3.6/site-packages:$PWD/insights-core"

pip3 install wheel
python3 setup.py bdist_wheel 

pip3 install -e insights-core 

# Install additional rules
if [ ! -z "$INSIGHTS_RULES" ]; then
    IFS=':' read -r -a rules_list <<< "$INSIGHTS_RULES"
    for rule_path in "${rules_list[@]}"
    do
	rule_base_name=$(basename "$rule_path")
        ln -s "$rule_path" "$rule_base_name"
	pip3 install -e "$rule_base_name"
    done
fi

pip3 install -r requirements.txt

python3 app.py


# Delete additional rules
if [ ! -z "$INSIGHTS_RULES" ]; then
    IFS=':' read -r -a rules_list <<< "$INSIGHTS_RULES"
    for rule_path in "${rules_list[@]}"
    do
	rule_base_name=$(basename "$rule_path")
        rm "$rule_base_name"
    done
fi
