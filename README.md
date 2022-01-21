# Matomo Server Log Analytics

Import your server logs in Matomo with this powerful and easy to use tool.

## Requirements

* Python 3.5, 3.6, 3.7, 3.8, 3.9, 3.10.
* Matomo On-Premise >= 4.0.0 or Matomo Cloud. Doesn't work when [Matomo for WordPress](https://wordpress.org/plugins/matomo/) is used.

Build status (main branch) ![PHPUnit](https://github.com/matomo-org/matomo-log-analytics/workflows/Tests/badge.svg?branch=4.x-dev)

## Supported log formats


The script will import all standard web server log files, and some files with non-standard formats. The following log formats are supported:
 * all default log formats for: Nginx, Apache, IIS, Tomcat, Haproxy
 * all log formats commonly used such as: NCSA Common log format, Extended log format, W3C Extended log files, Nginx JSON, OVH, Gandi virtualhost servers
 * log files of some popular Cloud services: Amazon AWS CloudFront logs, AWS S3 logs, AWS ELB logs.
 * streaming media server log files such as: Icecast
 * log files with and without the virtual host will be imported

In general, many fields are left optional to make the log importer very flexible.

## Get involved

We're looking for contributors! Feel free to submit Pull requests on Github.

### Submit a new log format

The Log Analytics importer is designed to detect and import into Matomo as many log files as possible. Help us add your log formats!

 * Implement your new log format in the import_logs.py file (look for `FORMATS = {` variable where the log formats are defined),
 * Add a new test in [tests/test_main.py](https://github.com/matomo-org/matomo-log-analytics/blob/4.x-dev/tests/test_main.py),
 * Test that the logs are imported successfully as you expected (`tests/run_tests.sh`),
 * Open a Pull Request,
 * Check the test you have added works (the build should be green),
 * One Matomo team member will review and merge the Pull Request as soon as possible.

We look forward to your contributions!

### Improve this guide

This readme page could be improved and maybe you would like to help? Feel free to "edit" this page and create a pull request.

### Implement new features or fixes

If you're a Python developer and would like to contribute to open source log importer, check out the [list of issues for import_logs.py](https://github.com/matomo-org/matomo-log-analytics/issues) which lists all issues and suggestions.

## How to use this script?

The most simple way to import your logs is to run:

    ./import_logs.py --url=matomo.example.com /path/to/access.log

You must specify your Matomo URL with the `--url` argument.
The script will automatically read your config.inc.php file to get the authentication
token and communicate with your Matomo install to import the lines. If your Matomo install is on a different server, use the `--token-auth=<SECRET>` parameter to specify your API token.

The default mode will try to mimic the Javascript tracker as much as possible,
and will not track bots, static files, or error requests.

If you wish to track all requests the following command would be used:

    python /path/to/matomo/misc/log-analytics/import_logs.py --url=http://mysite/matomo/ --idsite=1234 --recorders=4 --enable-http-errors --enable-http-redirects --enable-static --enable-bots access.log


### Format Specific Details

* If you are importing Netscaler log files, make sure to specify the `--iis-time-taken-secs` option. Netscaler stores
  the time-taken field in seconds while most other formats use milliseconds. Using this option will ensure that the
  log importer interprets the field correctly.

* Some log formats can't be detected automatically as they would conflict with other formats. In order to import those logfiles make sure to specify the `--log-format-name` option.
  Those log formats are: OVH (ovh), Incapsula W3C (incapsula_w3c)

## How to import your logs automatically every day?

You must first make sure your logs are automatically rotated every day. The most
popular ways to implement this are using either:

* logrotate: http://www.linuxcommand.org/man_pages/logrotate8.html
  It will work with any HTTP daemon.
* rotatelogs: http://httpd.apache.org/docs/2.0/programs/rotatelogs.html
  Only works with Apache.
* let us know what else is useful and we will add it to the list

Your logs should be automatically rotated and stored on your webserver, for instance in daily logs
`/var/log/apache/access-%Y-%m-%d.log` (where %Y, %m and %d represent the year,
month and day).
You can then import your logs automatically each day (at 0:01). Setup a cron job with the command:

    1 0 * * * /path/to/matomo/misc/log-analytics/import-logs.py -u matomo.example.com `date --date=yesterday +/var/log/apache/access-\%Y-\%m-\%d.log`

## Using Basic access authentication

If you protect your site with Basic access authentication then you can pass the credentials via your
cron job.

Apache configuration:
```
<Location /matomo>
    AuthType basic
    AuthName "Site requires authentication"
    # Where all the external login/passwords are
    AuthUserFile /etc/apache2/somefile
    Require valid-user
</Location>
```

cron job:
```
5 0 * * * /var/www/html/matomo/misc/log-analytics/import_logs.py --url https://www.mysite.com/matomo --auth-user=someuser --auth-password=somepassword --exclude-path=*/matomo/index.php --enable-http-errors --enable-reverse-dns --idsite=1 `date --date=yesterday +/var/log/apache2/access-ssl-\%Y-\%m-\%d.log` > /opt/scripts/import-logs.log
```

Security tips:
* Currently the credentials are not encrypted in the cron job. This should be a future enhancement.
* Always use HTTPS with Basic access authentication to ensure you are not passing credentials in clear text.

## Performance

With an Intel Core i5-2400 @ 3.10GHz (2 cores, 4 virtual cores with Hyper-threading),
running Matomo and its MySQL database, between 250 and 300 records were imported per second.

The import_logs.py script needs CPU to read and parse the log files, but it is actually
Matomo server itself (i.e. PHP/MySQL) which will use more CPU during data import.

To improve performance,

1. by default, the script uses one thread to parse and import log lines.
   You can use the `--recorders` option to specify the number of parallel threads which will
   import hits into Matomo. We recommend to set `--recorders=N` to the number N of CPU cores
   that the server hosting Matomo has. The parsing will still be single-threaded,
   but several hits will be tracked in Matomo at the same time.
2. the script will issue hundreds of requests to matomo.php - to improve the Matomo webserver performance
   you can disable server access logging for these requests.
   Each Matomo webserver (Apache, Nginx, IIS) can also be tweaked a bit to handle more req/sec.

## Advanced uses

### Example Nginx Virtual Host Log Format

nginx's default access log is parsed with the `--log-format-name=ncsa_extended` option.

To log multiple virtual hosts in nginx's access log, use the following configuration:

```
log_format vhosts '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /PATH/TO/access.log vhosts;
```

When executing `import_logs.py`, use `--log-format-name=common_complete`.

### How do I import Page Speed Metric from logs?

In Matomo> Actions> Page URLs and Page Title reports, Matomo reports the Avg. generation time, as an indicator of your website speed.
This metric works by default when using the Javascript tracker, but you can use it with log file as well.

Apache can log the generation time in microseconds using `%D` in the LogFormat.
This metric can be imported using a custom log format in this script.
In the command line, add the `--log-format-regex` parameter that contains the group `generation_time_micro`.

Here's an example:
```
Apache LogFormat "%h %l %u %t \"%r\" %>s %b %D"
--log-format-regex="(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?) (?P<timezone>.*?)\] \"\S+ (?P<path>.*?) \S+\" (?P<status>\S+) (?P<length>\S+) (?P<generation_time_micro>\S+)"
```

Note: the group `<generation_time_milli>` is also available if your server logs generation time in milliseconds rather than microseconds.

### How do I setup Nginx to directly import to Matomo via syslog?

Since nginx 1.7.1 you can [log to syslog](http://nginx.org/en/docs/syslog.html) and import them live to Matomo.

Path: nginx -> syslog -> (syslog central server) -> import_logs.py -> matomo

As a syslog central server you could use rsyslog or syslog-ng, use relevant parts of documentation below. Rsyslog part is tested with Ubuntu 16.10 and is working out-of-the-box.

You can use any log format that this script can handle, like Apache Combined, and Json format which needs less processing.

##### Setup Nginx logs

```
http {
...
log_format  matomo                   '{"ip": "$remote_addr",'
                                    '"host": "$host",'
                                    '"path": "$request_uri",'
                                    '"status": "$status",'
                                    '"referrer": "$http_referer",'
                                    '"user_agent": "$http_user_agent",'
                                    '"length": $bytes_sent,'
                                    '"generation_time_milli": $request_time,'
                                    '"date": "$time_iso8601"}';
...
	server {
	...
	# for syslog-ng
	access_log syslog:server=127.0.0.1,severity=info matomo;
	# for rsyslog
	access_log syslog:server=unix:/var/cache/nginx/access.socket,facility=local0 matomo;
	...
	}
}
```

##### Setup syslog-ng

This is the config for the central server if any. If not, you can also use this config on the same server as Nginx.

```
options {
    stats_freq(600); stats_level(1);
    log_fifo_size(1280000);
    log_msg_size(8192);
};
source s_nginx { udp(); };
destination d_matomo {
    program("/usr/local/matomo/matomo.sh" template("$MSG\n"));
};
log { source(s_nginx); filter(f_info); destination(d_matomo); };
```

###### matomo.sh, syslog-ng version

Just needed to configure the best params for import_logs.py, file `/usr/local/matomo/matomo.sh`:
```
#!/bin/sh

/path/to/misc/log-analytics/import_logs.py \
 --url=http://localhost/matomo/ \
 --idsite=1 --recorders=4 --enable-http-errors --enable-http-redirects --enable-static --enable-bots \
 --log-format-name=nginx_json -
```

##### Example of regex for syslog format (centralized logs)

###### log format example

```
Aug 31 23:59:59 tt-srv-name www.tt.com: 1.1.1.1 - - [31/Aug/2014:23:59:59 +0200] "GET /index.php HTTP/1.0" 200 3838 "http://www.tt.com/index.php" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0" 365020 www.tt.com
```

###### Corresponding regex

```
--log-format-regex='.* ((?P<ip>\S+) \S+ \S+ \[(?P<date>.*?) (?P<timezone>.*?)\] "\S+ (?P<path>.*?) \S+" (?P<status>\S+) (?P<length>\S+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)").*'
```

##### Setup rsyslog

Create new file `/etc/rsyslog.d/10-matomo.conf` with following content and restart rsyslog service afterwards:
```
# socket to which you should send nginx data
$AddUnixListenSocket /var/cache/nginx/access.socket

# message starts with tag, "nginx: <...>", which we remove
$template matomo,"%msg:9:$%\n"

# uncomment following line to debug what is sent to matomo and in which format
# to check script part you could issue following command
# and expected result is "1 requests imported successfully":
# 'tail -1 /var/tmp/nginx.tmp | /usr/local/matomo/matomo.sh'

#local0.* /var/tmp/nginx.tmp;matomo
if $syslogfacility-text == 'local0' then ^/usr/local/matomo/matomo.sh;matomo
```

###### matomo.sh, rsyslog version

`/usr/local/matomo/matomo.sh`, won't work without `--token-auth` parameter:
```
#!/bin/sh

echo "${@}" | /path/to/misc/log-analytics/import_logs.py \
 --url=https://localhost/matomo/ --token-auth=<SECRET> \
 --enable-http-errors --enable-http-redirects --enable-static --enable-bots \
 --idsite=1 --recorders=4 --log-format-name=nginx_json -
```


### Setup Apache CustomLog that directly imports in Matomo

Since apache CustomLog directives can send log data to a script, it is possible to import hits into matomo server-side in real-time rather than processing a logfile each day.

This approach has many advantages, including real-time data being available on your matomo site, using real logs files instead of relying on client-side Javacsript, and not having a surge of CPU/RAM usage during log processing.
The disadvantage is that if Matomo is unavailable, logging data will be lost. Therefore we recommend to also log into a standard log file. Bear in mind also that apache processes will wait until a request is logged before processing a new request, so if matomo runs slow so does your site: it's therefore important to tune `--recorders` to the right level.

##### Basic setup example

You might have in your main config section:

```
# Set up your log format as a normal extended format, with hostname at the start
LogFormat "%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" myLogFormat
# Log to a file as usual
CustomLog /path/to/logfile myLogFormat
# Log to matomo as well
CustomLog "|/path/to/import_logs.py --option1 --option2 ... -" myLogFormat
```

Note: on Debian/Ubuntu, the default configuration defines the `vhost_combined` format. You can use it instead of defining `myLogFormat`.

Here is another example on Apache defining the custom log:
```
LogFormat "%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" matomoLogFormat

CustomLog "||/var/www/virtual/test.tld/matomo/htdocs/misc/log-analytics/import_logs.py \
--debug --enable-http-errors --enable-http-redirects --enable-bots \
--url=http://matomo.test.tld --output=/var/log/matomo.log --recorders=1 \
--recorder-max-payload-size=1 --log-format-name=common_complete \
-" matomoLogFormat
```

Useful options here are:

* `--add-sites-new-hosts` (creates new websites in matomo based on %v in the LogFormat)
* `--output=/path/to/matomo.log` (puts any output into a log file for reference/debugging later)
* `--recorders=4` (use whatever value seems sensible for you - higher traffic sites will need more recorders to keep up)
* `-` so it reads straight from /dev/stdin

You can have as many CustomLog statements as you like. However, if you define any CustomLog directives within a <VirtualHost> block, all CustomLogs in the main config will be overridden. Therefore if you require custom logging for particular VirtualHosts, it is recommended to use mod_macro to make configuration more maintainable.


##### Advanced setup: Apache vhost, custom logs, automatic website creation

As a rather extreme example of what you can do, here is an apache config with:

* standard logging in the main config area for the majority of VirtualHosts
* customised logging in a particular virtualhost to change the hostname (for instance, if a particular virtualhost should be logged as if it were a different site)
* customised logging in another virtualhost which creates new websites in matomo for subsites (e.g. to have domain.com/subsite1 as a whole website in its own right). This requires setting up a custom `--log-format-regex` to allow "/" in the hostname section (NB the escaping necessary for apache to pass through the regex to matomo properly), and also to have multiple CustomLog directives so the subsite gets logged to both domain.com and domain.com/subsite1 websites in matomo
* we also use mod_rewrite to set environment variables so that if you have multiple subsites with the same format , e.g. /subsite1, /subsite2, etc, you can automatically create a new matomo website for each one without having to configure them manually

NB use of mod_macro to ensure consistency and maintainability

Apache configuration source code:

```
# Set up macro with the options
# * $vhost (this will be used as the matomo website name),
# * $logname (the name of the LogFormat we're using),
# * $output (which logfile to save import_logs.py output to),
# * $env (CustomLog can be set only to fire if an environment variable is set - this contains that environment variable, so subsites only log when it's set)
# NB the --log-format-regex line is exactly the same regex as import_logs.py's own 'common_vhost' format, but with "\/" added in the "host" section's allowed characters
<Macro matomolog $vhost $logname $output $env>
LogFormat "$vhost %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" $logname
CustomLog       "|/path/to/matomo/misc/log-analytics/import_logs.py \
--add-sites-new-hosts \
--config=/path/to/matomo/config/config.ini.php \
--url='http://your.matomo.install/' \
--recorders=4 \
--log-format-regex='(?P<host>[\\\\w\\\\-\\\\.\\\\/]*)(?::\\\\d+)? (?P<ip>\\\\S+) \\\\S+ \\\\S+ \\\\[(?P<date>.*?) (?P<timezone>.*?)\\\\] \\\"\\\\S+ (?P<path>.*?) \\\\S+\\\" (?P<status>\\\\S+) (?P<length>\\\\S+) \\\"(?P<referrer>.*?)\\\" \\\"(?P<user_agent>.*?)\\\"' \
--output=/var/log/matomo/$output.log \
-" \
$logname \
$env
</Macro>
# Set up main apache logging, with:

# * normal %v as hostname,
# * vhost_common as logformat name,
# * /var/log/matomo/main.log as the logfile,
# * no env variable needed since we always want to trigger
Use matomolog %v vhost_common main " "
<VirtualHost>
	ServerName example.com
	# Set this host to log to matomo with a different hostname (and using a different output file, /var/log/matomo/example_com.log)
	Use matomolog "another-host.com" vhost_common example_com " "
</VirtualHost>

<VirtualHost>
	ServerName domain.com
	# We want to log this normally, so repeat the CustomLog from the main section
	# (if this is omitted, our other CustomLogs below will override the one in the main section, so the main site won't be logged)
	Use matomolog %v vhost_common main " "

	# Now set up mod_rewrite to detect our subsites and set up new matomo websites to track just hits to these (this is a bit like profiles in Google Analytics).
	# We want to match domain.com/anothersubsite and domain.com/subsite[0-9]+

	# First to be on the safe side, unset the env we'll use to test if we're in a subsite:
	UnsetEnv vhostLogName

	# Subsite definitions. NB check for both URI and REFERER (some files used in a page, or downloads linked from a page, may not reside within our subsite directory):
	# Do the one-off subsite first:
	RewriteCond %{REQUEST_URI} ^/anothersubsite(/|$) [OR]
	RewriteCond %{HTTP_REFERER} domain\.com/anothersubsite(/|$)
	RewriteRule ^/.*        -       [E=vhostLogName:anothersubsite]
	# Subsite of the form /subsite[0-9]+. NB the capture brackets in the RewriteCond rules which get mapped to %1 in the RewriteRule
	RewriteCond %{REQUEST_URI} ^/(subsite[0-9]+)(/|$)) [OR]
	RewriteCond %{HTTP_REFERER} domain\.com/(subsite[0-9]+)(/|$)
	RewriteRule ^/.*        -       [E=vhostLogName:subsite%1]

	# Now set the logging to matomo setting:
	# * the hostname to domain.com/<subsitename>
	# * the logformat to vhost_domain_com_subsites (can be anything so long as it's unique)
	# * the output to go to /var/log/matomo/domain_com_subsites.log (again, can be anything)
	# * triggering only when the env variable is set, so requests to other URIs on this domain don't call this logging rule
	Use matomolog domain.com/%{vhostLogName}e vhost_domain_com_subsites domain_com_subsites env=vhostLogName
</VirtualHost>
```

### License

As [matomo](`https://github.com/matomo-org/matomo`) (which includes this code as a git reference), matomo-log-analytics is released under the GPLv3 or later.  Please refer to  [LEGALNOTICE](LEGALNOTICE) for copyright and trademark statements and [LICENSE.txt](LICENSE.txt) for the full text of the GPLv3.

### And that's all !


***This documentation is a community effort, we welcome your pull requests to [improve this documentation](https://github.com/matomo-org/matomo-log-analytics/edit/master/README.md).***
