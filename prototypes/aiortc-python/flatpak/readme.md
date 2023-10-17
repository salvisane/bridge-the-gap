# Manual to use flatpak application
## Prepare Windows Subsystem for Linux (WSL)
Install WSL. Ubuntu is the default installed linux system.
```console
wsl --install
```
Start Ubuntu via Start menu.
dbus is not started on WSL on startup. Start dbus therefore after each restart of the linux system.
```console
sudo service dbus start
```

## Install the flatpak application on Linux systems or on Windows Subsystem for Linux (WSL)

Install latest flatpak according to https://flatpak.org/setup/.

Add the flathub repo to provide the necessary dependencies during installation. Reboot the system afterwards.
```console
flatpak --user remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```

Add the flatpak repo of salvm4 (hosted on a github page, gpg key: 61CD575CF141018B9F6F42A05CC47942CAC08368)
```console
flatpak --user remote-add flatpak-salvm4 https://salvm4.github.io/flatpak-salvm4.flatpakrepo
```
Install the application.
```console
flatpak --user install flatpak-salvm4 ch.bfh.ti.applic-tunnel
```

## Use the application
Create key pair in application directory (the application is only allowed to access its own directory by configuration)
```console
cd $HOME/.var/app/ch.bfh.ti.applic-tunnel/data 
flatpak run ch.bfh.ti.applic-tunnel keygen
```
Get the public key of the listener as Base32 string and add it to the program call.

Run the application as initiator:
```console
flatpak run ch.bfh.ti.applic-tunnel initiator broker.hivemq.com 1883 127.0.01 1883 <PUBLIC_KEY_LISTENER> --notls
```

Run the application as listener:
```console
flatpak run ch.bfh.ti.applic-tunnel listener broker.hivemq.com 1883 127.0.01 1883 $HOME/.var/app/ch.bfh.ti.applic-tunnel/data/key.private --notls
```

Update application:
```console
flatpak update ch.bfh.ti.applic-tunnel
```

# Manual to build

## Useful commands to maintain flatpak files/environment

### Create flatpak application

Install rust compiler and cargo on the linux system.

Add freedesktop runtime and rust extension:
```console
flatpak install org.freedesktop.Sdk//21.08
flatpak install org.freedesktop.Platform//21.08
flatpak install org.freedesktop.Sdk.Extension.rust-stable//21.08
```

Analyze current dependencies in venv (called from application specific flatpak folder). This should be used as 
a base to maintain requirements.txt. 
```console
pipreqs ../src --savepath requirements_env.txt
```

Generate importable flatpak module import json (called from application specific flatpak folder):
```console
python3 ../../flatpak/flatpak-pip-generator.py --requirements-file=requirements.txt
```

Create application:
```console
flatpak-builder --force-clean build ch.bfh.ti.applic-tunnel.yml
```

Debug/run application:
```console
flatpak-builder --run build ch.bfh.ti.applic-tunnel.yml runner.sh
```

Add application to local repo:
```console
flatpak-builder --repo=applic-tunnel --force-clean build ch.bfh.ti.applic-tunnel.yml
```

Install application from local build:
```console
flatpak --user remote-add --no-gpg-verify thesis-repo repo
flatpak --user install thesis-repo ch.bfh.ti.applic-tunnel
```

### Maintain flatpak repo on github page

Add application build for x84_64 processor to github repo (has to be committed afterwards):
```console
flatpak-builder --gpg-sign=<gpg key ID> --arch=x86_64 --repo=../../../../../salvm4.github.io/applic-tunnel --force-clean build ch.bfh.ti.applic-tunnel.yml
```


### ARM build (use raspberry pi as build machine, knowledge of cross compiling not yet acquired)
Cross compiling is tested with Ubuntu. Use the following commands to prepare Ubuntu for cross compiling.
In addition, make sure the system has at least 24GB memory available (RAM + SWAP). 
```console
sudo apt-get install qemu-system-arm qemu-user-static binfmt-support
sudo systemctl restart systemd-binfmt.service
```

Install flatpak resources for cross compiling.
```console
flatpak install org.freedesktop.Sdk/aarch64/21.08
flatpak install org.freedesktop.Platform/aarch64/21.08
flatpak install org.freedesktop.Sdk.Extension.rust-stable/aarch64/21.08
```

```console
flatpak-builder --gpg-sign=<gpg key ID> --arch=aarch64 --repo=../../../../../salvm4.github.io/applic-tunnel --force-clean build ch.bfh.ti.applic-tunnel.yml
```

## Useful links

https://docs.flatpak.org/en/latest/first-build.html

https://docs.flatpak.org/en/latest/python.html

https://www.loganasherjones.com/2018/05/using-flatpak-with-python/

https://opensource.com/article/19/10/how-build-flatpak-packaging

https://blogs.gnome.org/alexl/2017/02/10/maintaining-a-flatpak-repository/

https://www.lprp.fr/2020/05/static-files-publication-on-gitlab-pages/

https://flatpak.org/setup/

https://developer.puri.sm/Librem5/Apps/Packaging_Apps/Building_Flatpaks/Cross-Building.html

https://wiki.debian.org/RaspberryPi/qemu-user-static

https://github.com/flatpak/flatpak/issues/5

https://docs.flatpak.org/en/latest/hosting-a-repository.html#flatpakrepo-files