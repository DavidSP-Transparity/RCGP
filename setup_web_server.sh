#!/bin/bash

function configure_nfs_client_and_mount_setup {
    local NFS_HOST_EXPORT_PATH=${1}   # E.g., controller-vm-ab12cd:/moodle
    local MOUNTPOINT=${2}             # E.g., /moodle

    apt install -y nfs-common
    mkdir -p ${MOUNTPOINT}

    grep -q -s "^${NFS_HOST_EXPORT_PATH}" /etc/fstab && _RET=$? || _RET=$?
    if [ $_RET = "0" ]; then
        echo "${NFS_HOST_EXPORT_PATH} already in /etc/fstab... skipping to add"
    else
        echo -e "\n${NFS_HOST_EXPORT_PATH}    ${MOUNTPOINT}    nfs    auto    0    0" >> /etc/fstab
    fi
    mount ${MOUNTPOINT}
}

function configure_nfs_client_and_mount {
    local NFS_SERVER=${1}     # E.g., controller-vm-ab12cd
    local NFS_DIR=${2}        # E.g., /moodle or /drbd/data
    local MOUNTPOINT=${3}     # E.g., /moodle

    configure_nfs_client_and_mount_setup "${NFS_SERVER}:${NFS_DIR}" ${MOUNTPOINT}
}

function get_php_version {
# Returns current PHP version, in the form of x.x, eg 7.0 or 7.2
    if [ -z "$_PHPVER" ]; then
        _PHPVER=`/usr/bin/php -r "echo PHP_VERSION;" | /usr/bin/cut -c 1,2,3`
    fi
    echo $_PHPVER
}

function setup_moodle_mount_dependency_for_systemd_service
{
  local serviceName=$1 # E.g., nginx, apache2
  if [ -z "$serviceName" ]; then
    return 1
  fi

  local systemdSvcOverrideFileDir="/etc/systemd/system/${serviceName}.service.d"
  local systemdSvcOverrideFilePath="${systemdSvcOverrideFileDir}/moodle_on_azure_override.conf"

  grep -q -s "After=moodle.mount" $systemdSvcOverrideFilePath && _RET=$? || _RET=$?
  if [ $_RET != "0" ]; then
    mkdir -p $systemdSvcOverrideFileDir
    cat <<EOF > $systemdSvcOverrideFilePath
[Unit]
After=moodle.mount
[Service]
LimitNOFILE=100000
EOF
    systemctl daemon-reload
  fi
}

function setup_html_local_copy_cron_job {
  if [ "$(whoami)" != "root" ]; then
    echo "${0}: Must be run as root!"
    return 1
  fi

  local SYNC_SCRIPT_FULLPATH="/usr/local/bin/sync_moodle_html_local_copy_if_modified.sh"
  mkdir -p $(dirname ${SYNC_SCRIPT_FULLPATH})

  local SYNC_LOG_FULLPATH="/var/log/moodle-html-sync.log"

  cat <<EOF > ${SYNC_SCRIPT_FULLPATH}
#!/bin/bash
sleep \$((\$RANDOM%30))
if [ -f "$SERVER_TIMESTAMP_FULLPATH" ]; then
  SERVER_TIMESTAMP=\$(cat $SERVER_TIMESTAMP_FULLPATH)
  if [ -f "$LOCAL_TIMESTAMP_FULLPATH" ]; then
    LOCAL_TIMESTAMP=\$(cat $LOCAL_TIMESTAMP_FULLPATH)
  else
    logger -p local2.notice -t moodle "Local timestamp file ($LOCAL_TIMESTAMP_FULLPATH) does not exist. Probably first time syncing? Continuing to sync."
    mkdir -p /var/www/html
  fi
  if [ "\$SERVER_TIMESTAMP" != "\$LOCAL_TIMESTAMP" ]; then
    logger -p local2.notice -t moodle "Server time stamp (\$SERVER_TIMESTAMP) is different from local time stamp (\$LOCAL_TIMESTAMP). Start syncing..."
    if [[ \$(find $SYNC_LOG_FULLPATH -type f -size +20M 2> /dev/null) ]]; then
      truncate -s 0 $SYNC_LOG_FULLPATH
    fi
    echo \$(date +%Y%m%d%H%M%S) >> $SYNC_LOG_FULLPATH
    rsync -av --delete /moodle/html/moodle /var/www/html >> $SYNC_LOG_FULLPATH
  fi
else
  logger -p local2.notice -t moodle "Remote timestamp file ($SERVER_TIMESTAMP_FULLPATH) does not exist. Is /moodle mounted? Exiting with error."
  exit 1
fi
EOF
  chmod 500 ${SYNC_SCRIPT_FULLPATH}

  local CRON_DESC_FULLPATH="/etc/cron.d/sync-moodle-html-local-copy"
  cat <<EOF > ${CRON_DESC_FULLPATH}
* * * * * root ${SYNC_SCRIPT_FULLPATH}
EOF
  chmod 644 ${CRON_DESC_FULLPATH}

  # Addition of a hook for custom script run on VMSS from shared mount to allow customised configuration of the VMSS as required
  local CRON_DESC_FULLPATH2="/etc/cron.d/update-vmss-config"
  cat <<EOF > ${CRON_DESC_FULLPATH2}
* * * * * root [ -f /moodle/bin/update-vmss-config ] && /bin/bash /moodle/bin/update-vmss-config
EOF
  chmod 644 ${CRON_DESC_FULLPATH2}
}

# set variables
phpVersion="7.2"
siteFQDN="devole.rcgp.org.uk"
nfsVmName="controller-vm-u6c66z.internal.cloudapp.net"
syslogServer="controller-vm-u6c66z.internal.cloudapp.net"
htmlRootDir="/moodle/html/moodle"

set -ex
echo "### Function Start `date`###"

# add azure-cli repository
curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
AZ_REPO=$(lsb_release -cs)
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" |  tee /etc/apt/sources.list.d/azure-cli.list

# add PHP-FPM repository 
add-apt-repository ppa:ondrej/php -y > /dev/null 2>&1

# install pre-requisites including VARNISH and PHP-FPM
export DEBIAN_FRONTEND=noninteractive
apt-get --yes \
--no-install-recommends \
-qq -o=Dpkg::Use-Pty=0 \
-o Dpkg::Options::="--force-confdef" \
-o Dpkg::Options::="--force-confold" \
install \
azure-cli \
ca-certificates \
curl \
apt-transport-https \
lsb-release gnupg \
software-properties-common \
unzip \
rsyslog \
postgresql-client \
mysql-client \
git \
unattended-upgrades \
tuned \
varnish \
php$phpVersion \
php$phpVersion-cli \
php$phpVersion-curl \
php$phpVersion-zip \
php-pear \
php$phpVersion-mbstring \
mcrypt \
php$phpVersion-dev \
graphviz \
aspell \
php$phpVersion-soap \
php$phpVersion-json \
php$phpVersion-redis \
php$phpVersion-bcmath \
php$phpVersion-gd \
php$phpVersion-pgsql \
php$phpVersion-mysql \
php$phpVersion-xmlrpc \
php$phpVersion-intl \
php$phpVersion-xml \
php$phpVersion-bz2 \
php$phpVersion-sqlite3

# install azcopy
wget -q -O azcopy_v10.tar.gz https://aka.ms/downloadazcopy-v10-linux && tar -xf azcopy_v10.tar.gz --strip-components=1 && mv ./azcopy /usr/bin/

# kernel settings
cat <<EOF > /etc/sysctl.d/99-network-performance.conf
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 5000
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_wmem = 4096 12582912 16777216
net.ipv4.tcp_rmem = 4096 12582912 16777216
net.ipv4.route.flush = 1
net.ipv4.tcp_max_syn_backlog = 8096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535
EOF
# apply the new kernel settings
sysctl -p /etc/sysctl.d/99-network-performance.conf

# scheduling IRQ interrupts on the last two cores of the cpu
# masking 0011 or 00000011 the result will always be 3 echo "obase=16;ibase=2;0011" | bc | tr '[:upper:]' '[:lower:]'
if [ -f /etc/default/irqbalance ]; then
sed -i "s/\#IRQBALANCE_BANNED_CPUS\=/IRQBALANCE_BANNED_CPUS\=3/g" /etc/default/irqbalance
systemctl restart irqbalance.service 
fi

# configuring tuned for throughput-performance
systemctl enable tuned
tuned-adm profile throughput-performance

# install apache packages
apt-get --yes -qq -o=Dpkg::Use-Pty=0 install libapache2-mod-php$phpVersion

# enable SSL on Apache
a2enmod ssl

# PHP Version
PhpVer=$(get_php_version)

# mount NFS export (set up on controller VM)
echo -e '\n\rMounting NFS export from '$nfsVmName':/moodle on /moodle and adding it to /etc/fstab\n\r'
configure_nfs_client_and_mount $nfsVmName /moodle /moodle
wait
echo -e '\n\rAdded '$nfsVmName':/moodle on /moodle successfully\n\r'

# Configure syslog to forward
cat <<EOF >> /etc/rsyslog.conf
\$ModLoad imudp
\$UDPServerRun 514
EOF
cat <<EOF >> /etc/rsyslog.d/40-remote.conf
local1.*   @${syslogServer}:514
local2.*   @${syslogServer}:514
EOF
service syslog restart

# Set up html dir local copy
mkdir -p /var/www/html/moodle
rsync -a $htmlRootDir /var/www/html
wait
setup_html_local_copy_cron_job
wait

# Configure Apache/php
nl=$'\n'
sed -i 's/\Listen 80/'"Listen 443""\\${nl}"'Listen 80/' /etc/apache2/ports.conf
a2enmod rewrite && a2enmod remoteip && a2enmod headers

# php config 
PhpIni=/etc/php/${PhpVer}/apache2/php.ini
sed -i "s/memory_limit.*/memory_limit = 512M/" $PhpIni
sed -i "s/max_execution_time.*/max_execution_time = 18000/" $PhpIni
sed -i "s/max_input_vars.*/max_input_vars = 100000/" $PhpIni
sed -i "s/max_input_time.*/max_input_time = 600/" $PhpIni
sed -i "s/upload_max_filesize.*/upload_max_filesize = 1024M/" $PhpIni
sed -i "s/post_max_size.*/post_max_size = 1056M/" $PhpIni
sed -i "s/;opcache.use_cwd.*/opcache.use_cwd = 1/" $PhpIni
sed -i "s/;opcache.validate_timestamps.*/opcache.validate_timestamps = 1/" $PhpIni
sed -i "s/;opcache.save_comments.*/opcache.save_comments = 1/" $PhpIni
sed -i "s/;opcache.enable_file_override.*/opcache.enable_file_override = 0/" $PhpIni
sed -i "s/;opcache.enable.*/opcache.enable = 1/" $PhpIni
sed -i "s/;opcache.memory_consumption.*/opcache.memory_consumption = 512/" $PhpIni
sed -i "s/;opcache.max_accelerated_files.*/opcache.max_accelerated_files = 20000/" $PhpIni

# Remove the default site. Moodle is the only site we want
rm -f /etc/apache2/sites-enabled/000-default.conf

# Configure varnish startup for 18.04
VARNISHSTART="ExecStart=\/usr\/sbin\/varnishd -j unix,user=vcache -F -a :80 -T localhost:6082 -f \/etc\/varnish\/moodle.vcl -S \/etc\/varnish\/secret -s malloc,4096m -p thread_pool_min=1000 -p thread_pool_max=4000 -p thread_pool_add_delay=0.1 -p timeout_linger=10 -p timeout_idle=30 -p send_timeout=1800 -p thread_pools=2 -p http_max_hdr=512 -p workspace_backend=512k"
sed -i "s/^ExecStart.*/${VARNISHSTART}/" /lib/systemd/system/varnish.service

# Configure varnish VCL for moodle
cat <<EOF >> /etc/varnish/moodle.vcl
vcl 4.0;
import std;
import directors;
backend default {
.host = "localhost";
.port = "81";
.first_byte_timeout = 3600s;
.connect_timeout = 600s;
.between_bytes_timeout = 600s;
}
sub vcl_recv {
# Varnish does not support SPDY or HTTP/2.0 untill we upgrade to Varnish 5.0
if (req.method == "PRI") {
    return (synth(405));
}
if (req.restarts == 0) {
    if (req.http.X-Forwarded-For) {
    set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
    } else {
    set req.http.X-Forwarded-For = client.ip;
    }
}
# Non-RFC2616 or CONNECT HTTP requests methods filtered. Pipe requests directly to backend
if (req.method != "GET" &&
    req.method != "HEAD" &&
    req.method != "PUT" &&
    req.method != "POST" &&
    req.method != "TRACE" &&
    req.method != "OPTIONS" &&
    req.method != "DELETE") {
    return (pipe);
}
# Varnish don't mess with healthchecks
if (req.url ~ "^/admin/tool/heartbeat" || req.url ~ "^/healthcheck.php")
{
    return (pass);
}
# Pipe requests to backup.php straight to backend - prevents problem with progress bar long polling 503 problem
# This is here because backup.php is POSTing to itself - Filter before !GET&&!HEAD
if (req.url ~ "^/backup/backup.php")
{
    return (pipe);
}
# Varnish only deals with GET and HEAD by default. If request method is not GET or HEAD, pass request to backend
if (req.method != "GET" && req.method != "HEAD") {
    return (pass);
}
### Rules for Moodle and Totara sites ###
# Moodle doesn't require Cookie to serve following assets. Remove Cookie header from request, so it will be looked up.
if ( req.url ~ "^/altlogin/.+/.+\.(png|jpg|jpeg|gif|css|js|webp)$" ||
        req.url ~ "^/pix/.+\.(png|jpg|jpeg|gif)$" ||
        req.url ~ "^/theme/font.php" ||
        req.url ~ "^/theme/image.php" ||
        req.url ~ "^/theme/javascript.php" ||
        req.url ~ "^/theme/jquery.php" ||
        req.url ~ "^/theme/styles.php" ||
        req.url ~ "^/theme/yui" ||
        req.url ~ "^/lib/javascript.php/-1/" ||
        req.url ~ "^/lib/requirejs.php/-1/"
    )
{
    set req.http.X-Long-TTL = "86400";
    unset req.http.Cookie;
    return(hash);
}
# Perform lookup for selected assets that we know are static but Moodle still needs a Cookie
if(  req.url ~ "^/theme/.+\.(png|jpg|jpeg|gif|css|js|webp)" ||
        req.url ~ "^/lib/.+\.(png|jpg|jpeg|gif|css|js|webp)" ||
        req.url ~ "^/pluginfile.php/[0-9]+/course/overviewfiles/.+\.(?i)(png|jpg)$"
    )
{
        # Set internal temporary header, based on which we will do things in vcl_backend_response
        set req.http.X-Long-TTL = "86400";
        return (hash);
}
# Serve requests to SCORM checknet.txt from varnish. Have to remove get parameters. Response body always contains "1"
if ( req.url ~ "^/lib/yui/build/moodle-core-checknet/assets/checknet.txt" )
{
    set req.url = regsub(req.url, "(.*)\?.*", "\1");
    unset req.http.Cookie; # Will go to hash anyway at the end of vcl_recv
    set req.http.X-Long-TTL = "86400";
    return(hash);
}
# Requests containing "Cookie" or "Authorization" headers will not be cached
if (req.http.Authorization || req.http.Cookie) {
    return (pass);
}
# Almost everything in Moodle correctly serves Cache-Control headers, if
# needed, which varnish will honor, but there are some which don't. Rather
# than explicitly finding them all and listing them here we just fail safe
# and don't cache unknown urls that get this far.
return (pass);
}
sub vcl_backend_response {
# Happens after we have read the response headers from the backend.
# 
# Here you clean the response headers, removing silly Set-Cookie headers
# and other mistakes your backend does.
# We know these assest are static, let's set TTL >0 and allow client caching
if ( beresp.http.Cache-Control && bereq.http.X-Long-TTL && beresp.ttl < std.duration(bereq.http.X-Long-TTL + "s", 1s) && !beresp.http.WWW-Authenticate )
{ # If max-age < defined in X-Long-TTL header
    set beresp.http.X-Orig-Pragma = beresp.http.Pragma; unset beresp.http.Pragma;
    set beresp.http.X-Orig-Cache-Control = beresp.http.Cache-Control;
    set beresp.http.Cache-Control = "public, max-age="+bereq.http.X-Long-TTL+", no-transform";
    set beresp.ttl = std.duration(bereq.http.X-Long-TTL + "s", 1s);
    unset bereq.http.X-Long-TTL;
}
else if( !beresp.http.Cache-Control && bereq.http.X-Long-TTL && !beresp.http.WWW-Authenticate ) {
    set beresp.http.X-Orig-Pragma = beresp.http.Pragma; unset beresp.http.Pragma;
    set beresp.http.Cache-Control = "public, max-age="+bereq.http.X-Long-TTL+", no-transform";
    set beresp.ttl = std.duration(bereq.http.X-Long-TTL + "s", 1s);
    unset bereq.http.X-Long-TTL;
}
else { # Don't touch headers if max-age > defined in X-Long-TTL header
    unset bereq.http.X-Long-TTL;
}
# Here we set X-Trace header, prepending it to X-Trace header received from backend. Useful for troubleshooting
if(beresp.http.x-trace && !beresp.was_304) {
    set beresp.http.X-Trace = regsub(server.identity, "^([^.]+),?.*$", "\1")+"->"+regsub(beresp.backend.name, "^(.+)\((?:[0-9]{1,3}\.){3}([0-9]{1,3})\)","\1(\2)")+"->"+beresp.http.X-Trace;
}
else {
    set beresp.http.X-Trace = regsub(server.identity, "^([^.]+),?.*$", "\1")+"->"+regsub(beresp.backend.name, "^(.+)\((?:[0-9]{1,3}\.){3}([0-9]{1,3})\)","\1(\2)");
}
# Gzip JS, CSS is done at the ngnix level doing it here dosen't respect the no buffer requsets
# if (beresp.http.content-type ~ "application/javascript.*" || beresp.http.content-type ~ "text") {
#    set beresp.do_gzip = true;
#}
}
sub vcl_deliver {
# Revert back to original Cache-Control header before delivery to client
if (resp.http.X-Orig-Cache-Control)
{
    set resp.http.Cache-Control = resp.http.X-Orig-Cache-Control;
    unset resp.http.X-Orig-Cache-Control;
}
# Revert back to original Pragma header before delivery to client
if (resp.http.X-Orig-Pragma)
{
    set resp.http.Pragma = resp.http.X-Orig-Pragma;
    unset resp.http.X-Orig-Pragma;
}
# (Optional) X-Cache HTTP header will be added to responce, indicating whether object was retrieved from backend, or served from cache
if (obj.hits > 0) {
    set resp.http.X-Cache = "HIT";
} else {
    set resp.http.X-Cache = "MISS";
}
# Set X-AuthOK header when totara/varnsih authentication succeeded
if (req.http.X-AuthOK) {
    set resp.http.X-AuthOK = req.http.X-AuthOK;
}
# If desired "Via: 1.1 Varnish-v4" response header can be removed from response
unset resp.http.Via;
unset resp.http.Server;
return(deliver);
}
sub vcl_backend_error {
# More comprehensive varnish error page. Display time, instance hostname, host header, url for easier troubleshooting.
set beresp.http.Content-Type = "text/html; charset=utf-8";
set beresp.http.Retry-After = "5";
synthetic( {"
<!DOCTYPE html>
<html>
<head>
    <title>"} + beresp.status + " " + beresp.reason + {"</title>
</head>
<body>
    <h1>Error "} + beresp.status + " " + beresp.reason + {"</h1>
    <p>"} + beresp.reason + {"</p>
    <h3>Guru Meditation:</h3>
    <p>Time: "} + now + {"</p>
    <p>Node: "} + server.hostname + {"</p>
    <p>Host: "} + bereq.http.host + {"</p>
    <p>URL: "} + bereq.url + {"</p>
    <p>XID: "} + bereq.xid + {"</p>
    <hr>
    <p>Varnish cache server
</body>
</html>
"} );
return (deliver);
}
sub vcl_synth {
#Redirect using '301 - Permanent Redirect', permanent redirect
if (resp.status == 851) { 
    set resp.http.Location = req.http.x-redir;
    set resp.http.X-Varnish-Redirect = true;
    set resp.status = 301;
    return (deliver);
}
#Redirect using '302 - Found', temporary redirect
if (resp.status == 852) { 
    set resp.http.Location = req.http.x-redir;
    set resp.http.X-Varnish-Redirect = true;
    set resp.status = 302;
    return (deliver);
}
#Redirect using '307 - Temporary Redirect', !GET&&!HEAD requests, dont change method on redirected requests
if (resp.status == 857) { 
    set resp.http.Location = req.http.x-redir;
    set resp.http.X-Varnish-Redirect = true;
    set resp.status = 307;
    return (deliver);
}
#Respond with 403 - Forbidden
if (resp.status == 863) {
    set resp.http.X-Varnish-Error = true;
    set resp.status = 403;
    return (deliver);
}
}
EOF

# restart Varnish
systemctl daemon-reload
systemctl restart varnish

# make Apache startup automatically
systemctl enable apache2

# configure SSL
secretname=$(find /var/lib/waagent -name "kv-shared-secrets-prod*.PEM")
chmod 644 "$secretname"
mkdir /etc/apache2/ssl
cp "$secretname" /etc/apache2/ssl/wildcard_rcgp_org_uk.pem

# setup Moodle mount dependency
setup_moodle_mount_dependency_for_systemd_service apache2 || exit 1

# restart Apache2
service apache2 restart

echo "### Script End `date`###"
