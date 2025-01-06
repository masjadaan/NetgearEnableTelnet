# Enable Telnet on Netgear Routers RAX30
***

### Steps
- The Blowfish implementation from Rupan has been used.
- Ensure that Blowfish code is in the same directory as NetgearEnableTelnet project
```shell
git clone https://github.com/Rupan/blowfish.git
cd blowfish
gcc -shared -o libblowfish.so -fPIC blowfish.c

cd ..
git clone https://github.com/masjadaan/NetgearEnableTelnet.git
cd NetgearEnableTelnet
./enable_telnet.py -ip <router IP> \
  -port 23 \
  -u admin \
  -w password \
  -m "XX:XX:XX:XX:XX:XX"
```