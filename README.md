# MITMNBDF v1.0
MITMNBDF (_MITM 'n' BDF_) is a kind of `BDFProxy` (https://github.com/secretsquirrel/BDFProxy) rewrite, from which it takes great inspiration.

## What's new (v1.0)
- archive types are handled by the config file: you can add support for new archive types just by editing the config file (default is `mitmnbdf.cfg`) following the format outlined in the next paragraph. This means that you can add new file types support without stopping `mitmnbdf`, giving maximum flexibility.
- mostly of the static variables are now handled by the config file (default is `mitmnbdf.cfg`)
- the whole config file is parsed on every traffic request, that means: it can be edited anytime and the script will adapt in real-time. Most notably, now you can edit the `[targets]` section, so you can change IP addresses, ports, payloads and others without closing `mitmnbdf` 
- multiprocess supports thanks to python `multiprocessing` module. Every stream will run on a dedicate process
- adding support for domain name in log file and output, so you can specify domain names in the `[targets]`
- adding support for multiple metasploit resource files based on `[targets]`: each target now has its own resource file, to reflect the changes that can be made in real time to the config file (the resource file per target follows the format `example_domain_org_msf.rc`).
- log file is grep-friendly: the format helps tools to grep for information. The log format is `date|loglevel|message`, where _loglevel_ is always 4 chars (`ERRO`, `WARN`, `INFO`, `DEBG` and `CRIT` @ EnhancedOutput class)
- more robust error checking and error handling

### File type format
Just as example, the following lines define a new archive file type called 'antani' (a fantasy one) in the `mitmnbdf.cfg`:

```
# don't forget to add your archive type in 'supportedArchiveTypes
# archive type name must be upper letters
supportedArchiveTypes = ZIP, TAR, AR, DEB, LZMA, ANTANI

[...]

[ANTANI]
# patchCount is the max number of files to patch in a zip file
# After the max is reached it will bypass the rest of the files 
# and send on it's way

patchCount = 5

# In Bytes
maxSize = 40000000

blacklist = .dll,  # don't do dlls in the archive file

# here we have a list of all the mime types that belongs to the archive type.
# you can use the command 'file --mime-types archive_file.ext' to fill the variable
mimes = "application/x-antani-compressed", "application/antani"

	# then we specified for each mime types what kind of format and filter we need to
	# apply to create the archive. You can find it out by looking at the libarchive-c source code
	[["application/x-antani-compressed"]]
	format = antani
	filter = xz

	[["application/antani"]]
	format = antani
	filter = None
```

## Why forking
I felt the BDFProxy source code needed a proper redesign to be able to add more features and flexibility, giving the great job Josh did with Backdoor Factory and BDFProxy.
I tried to work with Josh to redesign the code, but he has his ideas and way to manage code that is incompatible with my coding style. Variety is the spice of life.

## How to install
You need to install the python packages listed in `requirements.txt` (hint: `sudo pip install -r requirements.txt`). Before doing that, you need to install `libarchive-dev` from your packet manager. (`sudo apt-get install libarchive-dev` on Debian/Ubuntu).

You need to initialise the `bdf` submodule, so:
```
~/mitmnbdf$ git submodule init
~/mitmnbdf$ git submodule update
```

## How to use
Simply type `sudo python mitmnbdf.py`. Be sure to edit the config file and add your IP addresses and ports in the `[targets]` section.

Of course, you have already mitm'd your victim(s) (use your favourite tool)
To run a quick test, you can setup two VMs as follow:

#### VM A (mitmnbdf)
```
~$ ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 00:0c:29:32:0e:37  
          inet addr:192.168.8.129  Bcast:192.168.8.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fe32:e37/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:466 errors:0 dropped:0 overruns:0 frame:0
          TX packets:430 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:282593 (282.5 KB)  TX bytes:356018 (356.0 KB)
~$ route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.8.2     0.0.0.0         UG    0      0        0 eth0
192.168.8.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0

~/mitmnbdf$ cat mitmnbdf.cfg | grep proxyPort
proxyPort = 8080
~/mitmnbdf$ cat mitmnbdf.cfg | grep proxyMode
proxyMode = transparent  # <-- this is important!!!

~$ sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
~$ sudo echo 1 > /proc/sys/net/ipv4/ip_forward

~/mitmnbdf$ sudo python mitmnbdf.py
```

#### VM B (victim)

```
~$ ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 00:0c:29:e1:a1:ed  
          inet addr:192.168.8.135  Bcast:192.168.8.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fee1:a1ed/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:263 errors:0 dropped:0 overruns:0 frame:0
          TX packets:403 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:209801 (204.8 KiB)  TX bytes:31364 (30.6 KiB)

~$ sudo route add default gw 192.168.8.129
~$ sudo route del default gw 192.168.8.2
~$ curl -O http://example.com/mysw.exe
```

## mitmproxy script
If you want to use the `mitmproxy`'s scripting capability with mitmnbdf, now you can! 

I've release `mitmnbdf_inline.py` that it's basically a copy of the main `mitmnbdf.py` but adapted to be used as inline script.

To use it, you must first install the `bdf` library. If you didn't do that, you can use `bdf_install.sh`, that will install `bdf` directory into your python library path.

Then you may want to run the inline script as following:

```
~/mitmnbdf$ mitmproxy -T --host -s "mitmnbdf_inline.py mitmnbdf.cfg"
```

Some basic information are logged into `mitmproxy` and can be viewed by pressind the `e` key.

## WARNING
This project uses `python-libarchive-c` (https://github.com/Changaco/python-libarchive-c) that is a wrapper for `libarchive` (https://github.com/libarchive/libarchive) which suffers from various bugs that could lead to a remote exploit. Use with care.