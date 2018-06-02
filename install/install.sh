set -e
sudo apt-get update

echo "installing basic"
sudo apt-get -y install unzip python2.7
sudo apt-get -y install python-pip
mkdir ctinst
cd ctinst
wget https://github.com/google/certificate-transparency/archive/master.zip
unzip master
sudo easy_install certificate-transparency-master/python/
cd ..
sudo rm -rf ctinst

echo "installing python libs"
sudo apt-get -y install libffi-dev python2.7-dev libxext-dev libssl-dev
sudo apt-get -y install python-qt4 qt4-dev-tools build-essential g++
sudo pip install impacket rsa twisted pyasn1 qt4reactor service_identity  pycrypto bitstring primesieve
sudo pip install virtualenv

echo "installing openssl"
OPENSSL_VERSION='1.1.0'
CWD=$(pwd)
sudo virtualenv env
. env/bin/activate
pip install -U setuptools
pip install -U wheel pip
curl -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
tar xvf openssl-${OPENSSL_VERSION}.tar.gz
rm -f openssl-${OPENSSL_VERSION}.tar.gz
cd openssl-${OPENSSL_VERSION}
echo "Patching.."
patch -p1 < ../openssl_diff_file.diff
echo "Configuring"
#./config no-ssl2 no-ssl3 -fPIC --prefix=${CWD}/openssllib
./config -d no-shared no-ssl2 no-ssl3 -fPIC -ggdb --prefix=${CWD}/openssl
echo "Making"
make && make install
cd ..
CFLAGS="-I${CWD}/openssl/include" LDFLAGS="-L${CWD}/openssl/lib" ./env/bin/pip wheel --no-use-wheel cryptography
deactivate

echo "installing new crypto"

FN2=$(find . -iname cryptography*.whl)

# There was a problem with filename. Python doesn't know that the executable compatible with this machine.
#It checks that by the filename. So now we will let it ignore it.
#If it doesn't work , (in ubuntu 14 mainly ) , please uncomment these lines ..
#FN1=$(find . -iname cffi*.whl)
#FN2=$(echo ${FN1} | sed "s/cp27mu/none/g" )
#mv ${FN1} ${FN2} #replace file name
#FN1=$(find . -iname cryptography*.whl)
#FN2=$(echo ${FN1} | sed "s/cp27mu/none/g" )
#mv ${FN1} ${FN2} #replace file name

sudo CFLAGS="-I${CWD}/openssl/include" LDFLAGS="-L${CWD}/openssl/lib"  pip install  --find-links=. --no-index  ${FN2}
rm -rf *.whl
sudo rm -rf ./env

echo "installing pyopenssl"
sudo pip install --upgrade pyopenssl
