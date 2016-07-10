---
layout: post
title: Valet and XDebug with PHPStorm
subtitle: debugging your web apps with lightning fast Valet
---

This is how I setup xdebug with [Valet](https://laravel.com/docs/master/valet) on MacOSX 10.11.5:

First use phpinfo() to verify your php version (Mine is: 7.0.6).

Then install the correct xdebug for your php version. Using homebrew you can search for the correct xdebug using the command:

~~~
$ brew search xdebug
~~~
This returns the most suitable:'homebrew/php/php70-xdebug

Install xdebug using homebrew:

~~~
$ brew install php70-xdebug
~~~
Then find your PHP path using the following:

~~~
$ php --ini
Configuration File (php.ini) Path: /usr/local/etc/php/7.0
Loaded Configuration File: /usr/local/etc/php/7.0/php.ini
Scan for additional .ini files in: /usr/local/etc/php/7.0/conf.d
Additional .ini files parsed: /usr/local/etc/php/7.0/conf.d/ext-xdebug.ini
~~~
Select this php version in your IDE (Under [PHPStorm](https://www.jetbrains.com/phpstorm/) in interpreter section) by simply adding your PHP path into 'PHP executable':

~~~
/usr/local/Cellar/php70/7.0.6/bin/php
~~~
Also "php --ini" should tell you which php.ini file you're using. (mine is /usr/local/etc/php/7.0/php.ini see above).

To enable xdebug open this php.ini file and add the following lines:

~~~
zend_extension=/usr/local/Cellar/php70-xdebug/2.4.0/xdebug.so
xdebug.remote_enable=1
xdebug.remote_host=localhost
xdebug.remote_port=9001
xdebug.remote_autostart=1
xdebug.idekey=PHPSTORM
~~~

Update the zend_extension parameter to wherever your xdebug.so is located. (Note an additional .ini file may also be loading xdebug, mine was /usr/local/etc/php/7.0/conf.d/ext-xdebug.ini)

Finally, note that the port is 9001 (not the default 9000), this is because valet and/or vagrant may be using port 9000. You will need to inform your IDE you have changed the port, you can do this in PHPStorm under 'Preferences -> PHP -> Debug' then change Xdebug Port number to 9001. Also don't forget to restart valet:

~~~
$ valet restart
~~~

