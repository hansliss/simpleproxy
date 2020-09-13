Simpleproxy
===========

Simplified/modified version by Hans@Liss.pp.se
 * No HTTP proxy support
 * No POP3 support
 * Better trace support

Original authors:
-----------------
  * Vadim Zaliva <lord@crocodile.org>
  * Vlad Karpinsky <vlad@noir.crocodile.org>
  * Vadim Tymchenko <verylong@noir.crocodile.org>

Contributors:
-------------
  * Renzo Davoli <renzo@cs.unibo.it> (HTML probe & HTTP authentication)
  * Patch submitters via sourceforge and github project pages

Description
-----------
Simpleproxy is a simple TCP proxy. It accepts connections on a local
TCP port and forward them to anoter port on a remote host via TCP.

It can be used as standalone foreground or background daemon.

With the -T flag, simpleproxy will generate a new log file for each new
{day,session,client(ip, port)}, using the given log file name as a prefix.

Installation
------------

To install run `./configure`. Then, do 'make install'.

License
-------

GPLv2. See LICENSE.txt for details.

Home page
---------
To report bugs and get most recent version please go to:

https://github.com/vzaliva/simpleproxy






