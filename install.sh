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
grep "mpykdump*.so" ~/.crashrc 
if (( $? != 0 ))
then
  echo "mpykdump64.so needs to be loaded before the script in ~/.crashrc"
  exit 0
fi

# Set the extention code path in .bash_profile
echo -n "Setting the extention code path in .bash_profile ..."
echo '' >> ~/.bash_profile
echo "export PYKDUMPPATH=$PWD" >> ~/.bash_profile
echo " [DONE]"

# Make it load the registeration code during crash start
echo -n "Making it load the registeration code during crash start ..."
echo '' >> ~/.crashrc
echo "epython $PWD/regext.py" >> ~/.crashrc
echo " [DONE]"


echo ""
echo "All Done"
