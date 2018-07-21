#!/bin/bash

echo "Installing crash extensions running on PyKdump"
echo ""
echo "Please make sure 'PyKdump' is already configured to be loaded"
echo "during crash utlity starting."
echo "You can check it by looking 'extend' command in ~/.crashrc"
echo ""
echo "If you don't have PyKdump' extension, you can download it from"
echo "the below link"
echo ""
echo "      Python/CRASH API"
echo "      https://sourceforge.net/projects/pykdump/"
echo ""
grep "mpykdump.*.so" ~/.crashrc >/dev/null 2>&1
if (( $? != 0 ))
then
  echo "mpykdump64.so needs to be loaded before the script in ~/.crashrc"
  exit 0
fi

echo
echo "To use 'edis' properly, it's recommended to configure source server"
echo "in another system which has all source repositories and running"
echo "the server by run './start_server.sh' under 'remoteapi' directory"
echo
echo "If it's configured, please provide the server address in the below"
echo "format."
echo
echo " example) http://<server address>:5000"
echo -n "Please provide address> "
read server_addr

if [ ! -z $server_addr ] && [ $server_addr != "" ]; then
	echo "export CRASHEXT_SERVER=$server_addr" >> ~/.bash_profile
fi

# Set the extention code path in .bash_profile
echo -n "Setting the extention code path in .bash_profile ..."
echo '' >> ~/.bash_profile
echo "export PYKDUMPPATH=$PWD:\$PYKDUMPPATH" >> ~/.bash_profile
echo " [DONE]"

# Make it load the registeration code during crash start
echo -n "Making it load the registeration code during crash start ..."
echo '' >> ~/.crashrc
echo "epython $PWD/regext.py" >> ~/.crashrc
echo " [DONE]"


echo ""
echo "All Done"
echo
echo "Please re-login to apply the changes"
