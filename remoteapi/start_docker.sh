#!/bin/bash
#
# remoteapi docker starting script
#
# Written by Daniel Sungju Kwon
# dkwon@redhat.com
#

unamestr=`uname`


usage() {
        echo "RHEL_SOURCE_DIR needs to be configured properly"
        echo "    This should point to the directory that contains"
        echo "    all the source code and the path should be in the"
        echo "    rhelX such as rhel5, rhel6, rhel7, etc"
        echo ""
        echo "You may want to put it int ~/.bash_profile with something like below"
        echo "export RHEL_SOURCE_DIR=/home/dkwon/source/"
  	echo
}

remove_docker_image() {
  old_img=$(docker image ls | grep crashext | awk '{ print $3 }')
  docker image rm $old_img
}

while (( "$#" )); do
  case "$1" in
    -h|--help) # help
      usage
      exit 0
      ;;
    -r|--sslab) # Delete the old image before start
      remove_docker_image
      ;;
    *) # unknown option
      usage
      exit 1
      ;;
  esac
  shift
done


error_docker_start_commands() {
  echo 
  echo "  systemctl start docker.service"
  echo "  systemctl enable docker.service"
  echo
}


error_docker_commands() {
  echo
  echo "WARNING: docker and docker-compose are required"
  echo "  to run this tool."
  echo
  echo "RHEL provided packages installation:"
  echo
  echo "  yum-config-manager --enable rhel-7-server-extras-rpms"
  echo "  yum install docker docker-client docker-common -y"
  echo "  curl -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose"
  echo "  chmod +x /usr/local/bin/docker-compose"

  error_docker_start_commands

  echo "Upstream docker packages:"
  echo "docker installation:"
  echo "  https://docs.docker.com/install/linux/docker-ce/centos/"
  echo
  echo "docker-compose installation:"
  echo "  https://docs.docker.com/compose/install/"
  echo
}

docker_loc=$(which docker)
docker_compose_loc=$(which docker-compose)
if [ -z "$docker_loc" ] || [ -z "$docker_compose_loc" ]; then
  error_docker_commands
  exit 2
fi

no_ftype() {
  echo
  echo "WARNING: In RHEL, the docker should run as root privilege"
  echo "  and /var/lib/docker should be a xfs filesystem with ftype=1"
  echo "  Please consider to mount /var/lib/docker with a xfs filesystem"
  echo "  which is created with latest mkfs.xfs command and"
  echo "  it requires at least 1GB of free space"
  echo 
  echo "  You can check ftype by run the below command:"
  echo
  echo "     $ xfs_info /var/lib/docker"
  echo
}

#
# Check if it's XFS filesystem and d_ftype=1 is set
#
if [[ "$unamestr" == 'Linux' ]]; then
	mountdir=$(df /var/lib/docker | tail -n 1 | awk '{ print $NF }')
	fstype=$(mount | grep " $mountdir " | awk '{ print $5 }')
  xfs_exist=$(which xfs_info)
  if [ -n "$xfs_exist" ]; then
	  d_ftype=$(xfs_info $mountdir | grep 'ftype=1')
  fi
elif [[ "$unamestr" == 'Darwin' ]]; then
  mountdir=$(df /Users/$USER/Library/Containers/com.docker.docker/Data/vms/0/Docker.qcow2 | tail -n 1 | awk '{ print $NF }')
	fstype=$(mount | grep " $mountdir " | awk '{ print $4 }')
fi

if [ $fstype == "xfs" ] && [ -z "$d_ftype" ]; then
  no_ftype
  exit 4
fi

# Check if the environment variable is configured properly
if [[ -z "$RHEL_SOURCE_DIR" ]]; then
	usage
	exit 5
fi

#docker-compose run --service-ports crashext
docker-compose up crashext
sleep 1
docker-compose down crashext

#container_id=$(docker container ls -a | grep crashext | awk '{ print $1 }')
#docker container rm $container_id
