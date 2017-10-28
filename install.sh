#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "You need root privileges to run this script."
  exit 1
fi

echo "Installing files..."
cp arpwatcher.service /etc/systemd/system/
cp arpwatcher.py /usr/local/bin
echo "Starting arpwatcher service..."
systemctl enable arpwatcher
systemctl start arpwatcher
echo "Done !"
