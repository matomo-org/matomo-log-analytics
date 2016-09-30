# Piwik Server Log Analytics

Import your server logs in Piwik with this powerful and easy to use tool.

## Requirements

* Python 2.6 or 2.7. Python 3.x is not supported.
* Piwik >= 2.14.0

Build status (master branch) [![Build Status](https://travis-ci.org/piwik/piwik-log-analytics.svg?branch=master)](https://travis-ci.org/piwik/piwik-log-analytics)

## Supported log formats


The script will import all standard web server log files, and some files with non-standard formats. The following log formats are supported:
 * all default log formats for: Nginx, Apache, IIS, Tomcat
 * all log formats commonly used such as: NCSA Common log format, Extended log format, W3C Extended log files, Nginx JSON
 * log files of some popular Cloud Saas services: Amazon CloudFront logs, Amazon S3 logs
 * streaming media server log files such as: Icecast
 * log files with and without the virtual host will be imported

In general, many fields are left optional to make the log importer very flexible.
 
## Get involved

We're looking for contributors! Feel free to submit Pull requests on Github.

### Submit a new log format

The Log Analytics importer is designed to detect and import into Piwik as many log files as possible. Help us add your log formats!

 * Implement your new log format in the import_logs.py file (look for `FORMATS = {` variable where the log formats are defined),
 * Add a new test in [tests/tests.py](https://github.com/piwik/piwik-log-analytics/blob/master/tests/tests.py),
 * Test that the logs are imported successfully as you expected,
 * Open a Pull Request,
 * Check the test you have added works (the build should be green),
 * One Piwik team member will review and merge the Pull Request as soon as possible.

We look forward to your contributions!

### Improve this guide

This readme page could be improved and maybe you would like to help? feel free to create a "edit" this page and create a pull request. 

### Implement new features or fixes

if you're a Python developer and would like to contribute to open source log importer, check out the [list of issues for import_logs.py](https://github.com/piwik/piwik-log-analytics/issues) which lists all issues and suggestions.

## How to use this script?

The most simple way to import your logs is to run:

    ./import_logs.py --url=piwik.example.com /path/to/access.log

You must specify your Piwik URL with the `--url` argument.
The script will automatically read your config.inc.php file to get the authentication
token and communicate with your Piwik install to import the lines.
The default mode will try to mimic the Javascript tracker as much as possible,
and will not track bots, static files, or error requests.

If you wish to track all requests the following command would be used:

    python /path/to/piwik/misc/log-analytics/import_logs.py --url=http://mysite/piwik/ --idsite=1234 --recorders=4 --enable-http-errors --enable-http-redirects --enable-static --enable-bots access.log 


### Format Specific Details

* If you are importing Netscaler log files, make sure to specify the `--iis-time-taken-secs` option. Netscaler stores
  the time-taken field in seconds while most other formats use milliseconds. Using this option will ensure that the
  log importer interprets the field correctly.

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

    0 1 * * * /path/to/piwik/misc/log-analytics/import-logs.py -u piwik.example.com `date --date=yesterday +/var/log/apache/access-\%Y-\%m-\%d.log`

## Using Basic access authentication

If you protect your site with Basic access authentication then you can pass the credentials via your
cron job.

Apache configuration:
```
<Location /piwik>
    AuthType basic
    AuthName "Site requires authentication"
    # Where all the external login/passwords are
    AuthUserFile /etc/apache2/somefile
    Require valid-user
</Location>
```

cron job:
```
5 0 * * * /var/www/html/piwik/misc/log-analytics/import_logs.py --url https://www.mysite.com/piwik --auth-user=someuser --auth-password=somepassword --exclude-path=/piwik/index.php --enable-http-errors --enable-reverse-dns --idsite=1 date --date=yesterday +/var/log/apache2/access-ssl-\%Y-\%m-\%d.log > /opt/scripts/import-logs.log
```

Security tips:
* Currently the credentials are not encrypted in the cron job. This should be a future enhancement.
* Always use HTTPS with Basic access authentication to ensure you are not passing credentials clear text.

## Performance

With an Intel Core i5-2400 @ 3.10GHz (2 cores, 4 virtual cores with Hyper-threading),
running Piwik and its MySQL database, between 250 and 300 records were imported per second.

The import_logs.py script needs CPU to read and parse the log files, but it is actually
Piwik server itself (i.e. PHP/MySQL) which will use more CPU during data import.

To improve performance,

1. by default, the script one thread to parse and import log lines.
   you can use the `--recorders` option to specify the number of parallel threads which will
   import hits into Piwik. We recommend to set `--recorders=N` to the number N of CPU cores
   that the server hosting Piwik has. The parsing will still be single-threaded,
   but several hits will be tracked in Piwik at the same time.
2. the script will issue hundreds of requests to piwik.php - to improve the Piwik webserver performance
   you can disable server access logging for these requests.
   Each Piwik webserver (Apache, Nginx, IIS) can also be tweaked a bit to handle more req/sec.

## Advanced uses

### Example Nginx Virtual Host Log Format

nginx's default access log is parsed with the `--log-format-name=ncsa_extended` option.

To log multiple virtual hosts in nginx's access log, use the following configuration:

```
log_format vhosts '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /PATH/TO/access.log vhosts;
```

When executing `import_logs.py`, use `--log-format-name=ncsa_extended`.

### How do I import Page Speed Metric from logs?

In Piwik> Actions> Page URLs and Page Title reports, Piwik reports the Avg. generation time, as an indicator of your website speed.
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

### How do I setup Nginx to directly imports in Piwik via syslog?

Since nginx 1.7.1 you can [log to syslog](http://nginx.org/en/docs/syslog.html) and import them live to Piwik.

Path: Nginx -> syslog -> (syslog central server) -> this script -> piwik

You can use any log format that this script can handle, like Apache Combined, and Json format which needs less processing.

##### Setup Nginx logs

```
http {
...
log_format  piwik                   '{"ip": "$remote_addr",'
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
	access_log syslog:info piwik;
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
destination d_piwik {
    program("/usr/local/piwik/piwik.sh" template("$MSG\n"));
};
log { source(s_nginx); filter(f_info); destination(d_piwik); };
```

##### piwik.sh

Just needed to configure the best params for import_logs.py :
```
#!/bin/sh

exec python /path/to/misc/log-analytics/import_logs.py \
 --url=http://localhost/ \
 --idsite=1 --recorders=4 --enable-http-errors --enable-http-redirects --enable-static --enable-bots \
 --log-format-name=nginx_json -
```

##### Example of regex for syslog format (centralized logs)

###### log format exemple

```
Aug 31 23:59:59 tt-srv-name www.tt.com: 1.1.1.1 - - [31/Aug/2014:23:59:59 +0200] "GET /index.php HTTP/1.0" 200 3838 "http://www.tt.com/index.php" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0" 365020 www.tt.com
```

###### Corresponding regex

```
--log-format-regex='.* ((?P<ip>\S+) \S+ \S+ \[(?P<date>.*?) (?P<timezone>.*?)\] "\S+ (?P<path>.*?) \S+" (?P<status>\S+) (?P<length>\S+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)").*'
```


### Setup Apache CustomLog that directly imports in Piwik

Since apache CustomLog directives can send log data to a script, it is possible to import hits into piwik server-side in real-time rather than processing a logfile each day.

This approach has many advantages, including real-time data being available on your piwik site, using real logs files instead of relying on client-side Javacsript, and not having a surge of CPU/RAM usage during log processing.
The disadvantage is that if Piwik is unavailable, logging data will be lost. Therefore we recommend to also log into a standard log file. Bear in mind also that apache processes will wait until a request is logged before processing a new request, so if piwik runs slow so does your site: it's therefore important to tune `--recorders` to the right level.

##### Basic setup example 

You might have in your main config section:

```
# Set up your log format as a normal extended format, with hostname at the start
LogFormat "%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" myLogFormat
# Log to a file as usual
CustomLog /path/to/logfile myLogFormat
# Log to piwik as well
CustomLog "|/path/to/import_logs.py --option1 --option2 ... -" myLogFormat
```

Note: on Debian/Ubuntu, the default configuration defines the `vhost_combined` format. You can use it instead of defining `myLogFormat`. 

Here is another example on Apache defining the custom log:
```
LogFormat "%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" piwikLogFormat

CustomLog "||/var/www/virtual/test.tld/piwik/htdocs/misc/log-analytics/import_logs.py \
--debug --enable-http-errors --enable-http-redirects --enable-bots \
--url=http://piwik.test.tld --output=/var/log/piwik.log --recorders=1 \
--recorder-max-payload-size=1 --log-format-name=common_complete \
-" piwikLogFormat
```

Useful options here are:

* `--add-sites-new-hosts` (creates new websites in piwik based on %v in the LogFormat)
* `--output=/path/to/piwik.log` (puts any output into a log file for reference/debugging later)
* `--recorders=4` (use whatever value seems sensible for you - higher traffic sites will need more recorders to keep up)
* `-` so it reads straight from /dev/stdin

You can have as many CustomLog statements as you like. However, if you define any CustomLog directives within a <VirtualHost> block, all CustomLogs in the main config will be overridden. Therefore if you require custom logging for particular VirtualHosts, it is recommended to use mod_macro to make configuration more maintainable.


##### Advanced setup: Apache vhost, custom logs, automatic website creation

As a rather extreme example of what you can do, here is an apache config with:

* standard logging in the main config area for the majority of VirtualHosts
* customised logging in a particular virtualhost to change the hostname (for instance, if a particular virtualhost should be logged as if it were a different site)
* customised logging in another virtualhost which creates new websites in piwik for subsites (e.g. to have domain.com/subsite1 as a whole website in its own right). This requires setting up a custom `--log-format-regex` to allow "/" in the hostname section (NB the escaping necessary for apache to pass through the regex to piwik properly), and also to have multiple CustomLog directives so the subsite gets logged to both domain.com and domain.com/subsite1 websites in piwik
* we also use mod_rewrite to set environment variables so that if you have multiple subsites with the same format , e.g. /subsite1, /subsite2, etc, you can automatically create a new piwik website for each one without having to configure them manually

NB use of mod_macro to ensure consistency and maintainability

Apache configuration source code:

```
# Set up macro with the options
# * $vhost (this will be used as the piwik website name),
# * $logname (the name of the LogFormat we're using),
# * $output (which logfile to save import_logs.py output to),
# * $env (CustomLog can be set only to fire if an environment variable is set - this contains that environment variable, so subsites only log when it's set)
# NB the --log-format-regex line is exactly the same regex as import_logs.py's own 'common_vhost' format, but with "\/" added in the "host" section's allowed characters
<Macro piwiklog $vhost $logname $output $env>
LogFormat "$vhost %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" $logname
CustomLog       "|/path/to/piwik/misc/log-analytics/import_logs.py \
--add-sites-new-hosts \
--config=/path/to/piwik/config/config.ini.php \
--url='http://your.piwik.install/' \
--recorders=4 \
--log-format-regex='(?P<host>[\\\\w\\\\-\\\\.\\\\/]*)(?::\\\\d+)? (?P<ip>\\\\S+) \\\\S+ \\\\S+ \\\\[(?P<date>.*?) (?P<timezone>.*?)\\\\] \\\"\\\\S+ (?P<path>.*?) \\\\S+\\\" (?P<status>\\\\S+) (?P<length>\\\\S+) \\\"(?P<referrer>.*?)\\\" \\\"(?P<user_agent>.*?)\\\"' \
--output=/var/log/piwik/$output.log \
-" \
$logname \
$env
</Macro>
# Set up main apache logging, with:

# * normal %v as hostname,
# * vhost_common as logformat name,
# * /var/log/piwik/main.log as the logfile,
# * no env variable needed since we always want to trigger
Use piwiklog %v vhost_common main " "
<VirtualHost>
	ServerName example.com
	# Set this host to log to piwik with a different hostname (and using a different output file, /var/log/piwik/example_com.log)
	Use piwiklog "another-host.com" vhost_common example_com " "
</VirtualHost>

<VirtualHost>
	ServerName domain.com
	# We want to log this normally, so repeat the CustomLog from the main section
	# (if this is omitted, our other CustomLogs below will override the one in the main section, so the main site won't be logged)
	Use piwiklog %v vhost_common main " "

	# Now set up mod_rewrite to detect our subsites and set up new piwik websites to track just hits to these (this is a bit like profiles in Google Analytics).
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

	# Now set the logging to piwik setting:
	# * the hostname to domain.com/<subsitename>
	# * the logformat to vhost_domain_com_subsites (can be anything so long as it's unique)
	# * the output to go to /var/log/piwik/domain_com_subsites.log (again, can be anything)
	# * triggering only when the env variable is set, so requests to other URIs on this domain don't call this logging rule
	Use piwiklog domain.com/%{vhostLogName}e vhost_domain_com_subsites domain_com_subsites env=vhostLogName
</VirtualHost>
```

### And that's all !


***This documentation is a community effort, we welcome your pull requests to [improve this documentation](https://github.com/piwik/piwik-log-analytics/edit/master/README.md).***

