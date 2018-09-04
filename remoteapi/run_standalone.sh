#!/bin/bash

unamestr=`uname`
versionstr=`uname -r`


howto_install() {
	if [[ "$unamestr" == 'Linux' ]]; then
		if echo "$versionstr" | grep -q ".el"; then
			echo "$ yum install python-virtualenv python2-pip python34-pip python";
		else
			echo "Please check your distributor for the below commands";
			echo "python, virtualenv, pip";
		fi
	elif [[ "$unamestr" == 'Darwin' ]]; then
		echo "$ brew install python pyenv-virtualenv pyenv-virtualenvwrapper";
		echo "$ sudo easy_install pip";
	fi
}

usage() {
	echo 
	echo "To run this server as a standalone, you need to have"
	echo "the below commands installed."
	echo
	echo "python, virtualenv, pip"
	echo
	howto_install
}

if [ -z $RHEL_SOURCE_DIR ] || [ $RHEL_SOURCE_DIR == "" ]; then
	echo "RHEL_SOURCE_DIR bash variable should be configured"
	echo "and should point to the source directory."
	echo
	echo "  example)  export RHEL_SOURCE_DIR='/home/dkwon/source/'"
	echo
	echo "The source tree should be something like below."
	echo
	echo "<your_source_dir> -+-- rhel5"
	echo "                   +-- rhel6"
        echo "                   ..."
        echo "                   +-- fedora"
	echo
	echo "The directory doesn't need to have all source repositories."
	echo "It only needs to have the directories you are going to use."
	echo
	exit -1
fi

cd web
sh ./entrypoint.sh
