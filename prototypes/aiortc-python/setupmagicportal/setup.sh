 #!/bin/bash

# chose installation type:
PS3='Installation type: '
types=("listener" "initiator" "exit")
select type in "${types[@]}"; do
	case $type in
		"listener")
			echo "install portal as listener"
			#read -p "Public key of initiator: " pubkey
			#echo "Use initator public key: $pubkey"
			break
			;;
		"initiator")
			echo "install portal as initiator"
			read -p "Public key of listener: " pubkey
			echo "Use listener public key: $pubkey"
			break
			;;
		"exit")
			echo "bye"
			exit
			break
			;;
		*)
			echo "invalid choice $REPLY"
			;;
	esac
done

# read UID of tinkerforge linear poti
read -p "UID of tinkerforge linear poti: " PotiUID
echo "Use UID of linear poti: $PotiUID"

echo "install mosquitto"
sudo apt-get install mosquitto

echo "install flatpak"
sudo apt-get install flatpak
flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

echo "setup flatpak dependencies"
flatpak remote-add --user --if-not-exists flatpak-salvm4 https://salvm4.github.io/flatpak-salvm4.flatpakrepo
echo "install magic message portal applications"
flatpak --user install flatpak-salvm4 ch.bfh.ti.applic-tunnel
flatpak --user install flatpak-salvm4 ch.bfh.ti.secure-bridge

echo "install nodeRED"
bash <(curl -sL https://raw.githubusercontent.com/node-red/linux-installers/master/deb/update-nodejs-and-nodered)

echo "install tinkerforge utilities"
wget https://download.tinkerforge.com/apt/$(. /etc/os-release; echo $ID)/tinkerforge.gpg -q -O - | sudo tee /etc/apt/trusted.gpg.d/tinkerforge.gpg > /dev/null
echo "deb https://download.tinkerforge.com/apt/$(. /etc/os-release; echo $ID $VERSION_CODENAME) main" | sudo tee /etc/apt/sources.list.d/tinkerforge.list
sudo apt-get update
sudo apt-get install brickd
sudo apt-get install brickv
sudo apt-get install tinkerforge-mqtt


echo "configure mosguitto"
if [ "$type" = "initiator" ]
then
	sudo cp ./mosquitto_initiator.conf /etc/mosquitto/mosquitto.conf 
else
	sudo cp ./mosquitto_listener.conf /etc/mosquitto/mosquitto.conf
fi
sudo systemctl enable mosquitto.service
sudo systemctl restart mosquitto.service

echo "create new systemd services"
# run flatpak to initialize folder
flatpak run ch.bfh.ti.secure-bridge -h
flatpak run ch.bfh.ti.applic-tunnel -h

systemdpath="/lib/systemd/system"

if [ "$type" == "initiator" ]
then
	sudo cp ./mqtt-tunnel-initiator.service $systemdpath/
	sudo mv $systemdpath/mqtt-tunnel-initiator.service $systemdpath/mqtt-tunnel.service
	# replace public key of listener
  sudo sed -i "s/<publickey>/$pubkey/g" $systemdpath/mqtt-tunnel.service
	sudo cp ./secure-bridge-decrypt-initiator.service $systemdpath/
	sudo mv $systemdpath/secure-bridge-decrypt-initiator.service $systemdpath/secure-bridge-decrypt.service
	sudo cp ./secure-bridge-encrypt-initiator.service $systemdpath/
	sudo mv $systemdpath/secure-bridge-encrypt-initiator.service $systemdpath/secure-bridge-encrypt.service
else
	sudo cp ./mqtt-tunnel-listener.service $systemdpath/
	sudo mv $systemdpath/mqtt-tunnel-listener.service $systemdpath/mqtt-tunnel.service
	sudo cp ./secure-bridge-decrypt-listener.service $systemdpath/
	sudo mv $systemdpath/secure-bridge-decrypt-listener.service $systemdpath/secure-bridge-decrypt.service
	sudo cp ./secure-bridge-encrypt-listener.service $systemdpath/
	sudo mv $systemdpath/secure-bridge-encrypt-listener.service $systemdpath/secure-bridge-encrypt.service
	# create a keypair
	flatpak run ch.bfh.ti.applic-tunnel keygen -p /home/$USER/.var/app/ch.bfh.ti.applic-tunnel/data/
fi

sudo cp ./tinkerforge-mqtt.service $systemdpath/
mkdir /home/$USER/.tinkerforge
cp ./motorized_poti_mqtt.cfg /home/$USER/.tinkerforge/
# replace poti UID
sudo sed -i "s/<uid>/$PotiUID/g" /home/$USER/.tinkerforge/motorized_poti_mqtt.cfg

# replace user name placeholder with current user name
sudo sed -i "s/<user>/$USER/g" $systemdpath/mqtt-tunnel.service
sudo sed -i "s/<user>/$USER/g" $systemdpath/secure-bridge-decrypt.service
sudo sed -i "s/<user>/$USER/g" $systemdpath/secure-bridge-encrypt.service
sudo sed -i "s/<user>/$USER/g" $systemdpath/tinkerforge-mqtt.service

sudo systemctl daemon-reload
sudo systemctl enable mqtt-tunnel.service
sudo systemctl restart mqtt-tunnel.service
sudo systemctl enable secure-bridge-decrypt.service
sudo systemctl restart secure-bridge-decrypt.service
sudo systemctl enable secure-bridge-encrypt.service
sudo systemctl restart secure-bridge-encrypt.service


sudo systemctl enable tinkerforge-mqtt.service
sudo systemctl restart tinkerforge-mqtt.service


echo "setup secure bridge"
cp ./shared.key /home/$USER/.var/app/ch.bfh.ti.secure-bridge/data/


echo "configure nodeRED"
sudo systemctl enable nodered.service


if [ "$type" == "listener" ]
then
  echo "Listener public key is:"
  cat /home/$USER/.var/app/ch.bfh.ti.applic-tunnel/data/key.public
  echo -e "\nUse this key to setup the initator side"
fi
read -p "Setup finished, press any key to exit"