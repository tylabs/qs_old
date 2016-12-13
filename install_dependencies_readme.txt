brew install automake libtool wget
cd ~/Desktop
wget https://github.com/VirusTotal/yara/archive/v3.5.0.tar.gz
gunzip v3.5.0.tar.gz
tar -xvf v3.5.0.tar
cd yara-3.5.0
chmod 777 ./build.sh
LD_LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH
LDFLAGS=-L/usr/local/opt/openssl/lib
export LDFLAGS
CPPFLAGS=-I/usr/local/opt/openssl/include
export CPPFLAGS
./build.sh
sudo make install

cd ..
wget https://nih.at/libzip/libzip-1.1.3.tar.gz
gunzip libzip-1.1.3.tar.gz
tar -xvf libzip-1.1.3.tar
cd libzip-1.1.3
./configure
make
sudo make install
sudo ln -vs  /usr/local/lib/libzip/include/zipconf.h /usr/local/include


cd ..
wget http://zlib.net/zlib-1.2.8.tar.gz
gunzip zlib-1.2.8.tar.gz
tar -xvf zlib-1.2.8.tar
cd zlib-1.2.8
./configure
make
sudo make install


