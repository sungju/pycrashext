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

set_bg() {
        if [[ "$unamestr" == 'Linux' ]]; then
		echo "" -n
	elif [[ "$unamestr" == 'Darwin' ]]; then
	  osascript -e "tell application \"Terminal\" to set background color of window 1 to $1"
	fi
}

if [[ "$unamestr" == 'Darwin' ]]; then
on_exit() {
  set_bg "{65535, 65535, 65535}"
}
trap on_exit EXIT
fi


set_background_color() {
        if [[ "$unamestr" == 'Linux' ]]; then
		echo "" -n
	elif [[ "$unamestr" == 'Darwin' ]]; then
		set_bg "{65535, 45232, 35980}" 
		#set_bg "{65535, 62451, 63479}"
		#set_bg "{61937, 60395, 47288}"
		#set_bg "{58853, 65278, 65535}"
		#set_bg "{65535, 61166, 54998}"
	fi
}

set_background_color
cd web
sh ./entrypoint.sh
