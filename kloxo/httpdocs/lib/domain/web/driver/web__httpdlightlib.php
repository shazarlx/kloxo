<?php 

class web__apache extends lxDriverClass {

static function uninstallMe()
{
	lxshell_return("service", "httpd", "stop");
	lxshell_return("rpm", "-e", "--nodeps", "httpd");
	if (file_exists("/etc/init.d/httpd")) {
		lunlink("/etc/init.d/httpd");
	}
}

static function installMe()
{
	//Remove any previous httpd
	system("rm -rf /etc/httpd");
	system("rm -rf /home/httpd/conf");
	system("rm -rf /home/apache/conf");
	system("rm -f /etc/init.d/httpd");
	system("rm -f /etc/sysconfig/httpd");

	//Install the httpd
	if (lxshell_return("yum", "-y", "install", "httpd")) {
		throw new lxexception('install_httpd_failed', 'parent');
	}
	
	system("rm -f /etc/httpd/conf.d/proxy_ajp.conf");
	
	lxfile_cp('/usr/local/lxlabs/kloxo/file/httpd-light/etc_httpd_conf_httpd.conf', '/etc/httpd/conf/httpd.conf');
	lxfile_cp('/usr/local/lxlabs/kloxo/file/httpd-light/etc_httpd_conf.d_worker.conf', '/etc/httpd/conf.d/worker.conf');
	lxfile_cp('/usr/local/lxlabs/kloxo/file/httpd-light/etc_httpd_conf.d_000-light.conf', '/etc/httpd/conf.d/000-light.conf');
	lxfile_cp('/usr/local/lxlabs/kloxo/file/httpd-light/etc_httpd_conf.d_itk.conf', '/etc/httpd/conf.d/itk.conf');
	lxfile_cp('/usr/local/lxlabs/kloxo/file/httpd-light/etc_httpd_conf.d_includes.conf', '/etc/httpd/conf.d/includes.conf');
	lxfile_cp('/usr/local/lxlabs/kloxo/file/httpd-light/etc_init.d_httpd', '/etc/init.d/httpd');
	
	if (lxshell_return('yum', '-y', 'install', 'httpd-devel', '--skip-broken'))
		throw new lxexception('install_httpd-devel_failed', 'parent');
	if (lxshell_return('tar', '-C', '/tmp/', '-xzf', '/usr/local/lxlabs/kloxo/file/httpd-light/mod_rpaf-0.6.tar.gz'))
		throw new lxexception('extract_mod_rpaf_failed', 'parent');
	if (lxshell_return('apxs', '-icn', 'mod_rpaf-2.0.so', '/tmp/mod_rpaf-0.6/mod_rpaf-2.0.c'))
		throw new lxexception('install_mod_rpaf_failed', 'parent');
	if (lxshell_return('yum', '-y', 'install', 'pcre-devel'))
		throw new lxexception('install_pcre-devel_failed', 'parent');
	system("echo '' | pecl install apc");
	//lfile_put_contents('/etc/php.d/apc.ini', 'extension=apc.so');
		
	//Create directory structure for virtual hosts
	lxfile_mkdir('/home/apache/conf');
	lxfile_mkdir("/home/apache/conf/defaults");
	lxfile_mkdir("/home/apache/conf/domains");

	system('chkconfig httpd on');
	system('service httpd start');
}

function updateMainConfFile()
{
	global $sgbl;
	
	$namevhoststring = '';
	
	foreach(os_get_allips() as $key => $ip){
		if ($ip) {
			$namevhoststring .= "NameVirtualHost {$ip}:80\n";
			$namevhoststring .= "NameVirtualHost {$ip}:443\n";
		}
	}
	
	$initconftemplate = lxfile_getfile('/usr/local/lxlabs/kloxo/file/httpd-light/home_apache_conf_defaults_init.conf');
	$initconffilename = '/home/apache/conf/defaults/init.conf';
	lfile_put_contents($initconffilename, str_replace('--TOKEN1--', $namevhoststring, $initconftemplate));
	
	$alliplist = os_get_allips();
	$vhostipstring .= $alliplist[0] . ":80 " . $alliplist[0] . ":443";
	$initconffile = lxfile_getfile($initconffilename);
	lfile_put_contents($initconffilename, str_replace('--VHOSTIPTOKEN1--', $vhostipstring, $initconffile));
	
	$sslconftemplate = lxfile_getfile('/usr/local/lxlabs/kloxo/file/httpd-light/home_apache_conf_defaults___ssl.conf');
	$sslconffilename = '/home/apache/conf/defaults/__ssl.conf';
	$ssl_cert = sslcert::getSslCertnameFromIP($this->main->__var_ipssllist[0]['nname']);
	$ssl_root = $sgbl->__path_ssl_root;
	sslcert::checkAndThrow(lfile_get_contents("{$ssl_root}/{$ssl_cert}.crt"), lfile_get_contents("{$ssl_root}/{$ssl_cert}.key"), $ssl_cert);
	lfile_put_contents($sslconffilename, str_replace('--VHOSTIPTOKEN1--', $alliplist[0], $sslconftemplate));
	$sslconffile = lxfile_getfile($sslconffilename);
	lfile_put_contents($sslconffilename, str_replace('--SSLCERTTOKEN1--', "{$ssl_root}/{$ssl_cert}", $sslconffile));
}

function getServerIp()
{
	global $gbl, $sgbl, $login, $ghtml;

	foreach($this->main->__var_domainipaddress as $ip => $dom) {
		if ($dom === $this->main->nname) {
			return true;
		}
	}

	return false;
}

function getSslIpList()
{
	global $gbl, $sgbl, $login, $ghtml;

	if ($this->getServerIp()) {
		foreach($this->main->__var_domainipaddress as $ip => $dom) {
			if ($this->main->nname !== $dom) { continue; }

			$list[] = $ip;
		}

		return $list;
	}

	$iplist = os_get_allips();

	foreach($iplist as $ip) {
		$list[] = $ip;
	}

	return $list;
}

function createVirtualHostiplist($port)
{
	global $gbl, $sgbl, $login, $ghtml;

	$string = "";

	if ($this->getServerIp()) {
		foreach($this->main->__var_domainipaddress as $ip => $dom) {
			if ($this->main->nname !== $dom) { continue; }

			$string .= "\t{$ip}:{$port}\\\n";
		}

		return $string;
	}

	$iplist = os_get_allips();

	foreach($iplist as $ip) {
		$string .= "\t{$ip}:{$port}\\\n";
	}

	return $string;
}

function addSendmail()
{
	global $gbl, $sgbl, $login, $ghtml;

	// enabled (rev 461)

	$sendmailstring  = "\t\tphp_admin_value sendmail_path \"/usr/sbin/sendmail -t -i\"\n";
	$sendmailstring .= "\t\tphp_admin_value sendmail_from \"{$this->main->nname}\"\n";

	$string .= "\t<IfModule mod_php5.c>\n";
	$string .= $sendmailstring;
	$string .= "\t</IfModule>\n\n";

	return $string;
}

function AddOpenBaseDir()
{
	global $gbl, $sgbl, $login, $ghtml;

	if (isset($this->main->webmisc_b) && $this->main->webmisc_b->isOn('disable_openbasedir')) {
		return null;
	}

	// MR -- fixed for 'disable' client
	if(!$this->main->isOn('status')) {
		return null;
	}

	$adminbasedir = trim($this->main->__var_extrabasedir);

	if ($adminbasedir) {
		$adminbasedir .= ":";
	}

	$uroot = $sgbl->__path_customer_root;

	$corepath = "{$uroot}/{$this->main->customer_name}";

	$httpdpath = "{$uroot}/{$this->main->nname}";

	$path  = "{$adminbasedir}";
	$path .= "{$corepath}:";
	$path .= "{$corepath}/kloxoscript:";
	$path .= "{$httpdpath}:";
	$path .= "{$httpdpath}/httpdocs:";
	$path .= "/tmp:";
	$path .= "/usr/share/pear:";
	$path .= "/var/lib/php/session/:";
	$path .= "/home/kloxo/httpd/script";

	$openbasdstring  = "php_admin_value open_basedir \"{$path}\"\n";

	$string = "\t<Location />\n";
	$string .= "\t\t<IfModule mod_php5.c>\n";
	$string .= "\t\t\t".$openbasdstring;
	$string .= "\t\t</IfModule>\n";
	$string .= "\t</Location>\n\n";

	return $string;
}

function getBlockIP()
{
	global $gbl, $sgbl, $login, $ghtml;

	$t = trimSpaces($this->main->text_blockip);
	$t = trim($t);

	if (!$t) { return; }

	$t = str_replace(".*", "", $t);

	$string = null;
	$string .= "\t<Location />\n";
	$string .= "\t\tOrder allow,deny\n";
	$string .= "\t\tdeny from $t\n";
	$string .= "\t\tallow from all\n";
	$string .= "\t</Location>\n\n";

	return $string;
}

function enablePhp()
{
	global $gbl, $sgbl, $login, $ghtml;

	$domname = $this->main->nname;
	$uname = $this->main->username;

	if (!$this->main->priv->isOn('php_flag'))  {
		return  "AddType application/x-httpd-php-source .php\n";
	}

	$string = null;

	lxfile_unix_chown("/home/httpd/{$domname}", "{$uname}:apache");
	lxfile_unix_chmod("/home/httpd/{$domname}", "0775");

	if (!lxfile_exists("/home/httpd/{$domname}/php.ini")) {
		// MR -- issue #650 - lxuser_cp doesn't work and change to lxfile_cp; lighttpd use lxfile_cp
		lxfile_cp("/etc/php.ini", "/home/httpd/{$domname}/php.ini");	
	}

	return $string;
}

function delDomain()
{
	global $gbl, $sgbl, $login, $ghtml;

	if (!$this->main->nname) {
		return;
	}

	$path = "/home/apache/conf/domains";

	foreach($plist as $k => $v) {
		lxfile_rm("{$path}/{$this->main->nname}.conf");
	}

	$this->main->deleteDir();
}

function clearDomainIpAddress()
{
	global $gbl, $sgbl, $login, $ghtml;

	$iplist = os_get_allips();

	foreach($this->main->__var_domainipaddress as $ip => $dom) {
		if (!array_search_bool($ip, $iplist)) {
			unset($this->main->__var_domainipaddress[$ip]);
		}
	}
}

function createConffile()
{
	global $gbl, $sgbl, $login, $ghtml;
	
	//Issue #976 Can't find what calls this creatConffile incorrectly, but this keeps bad configs from being created.
	if (!$this->main->username) {
		return;
	}
	
	$web_home = $sgbl->__path_httpd_root;

	$domainname = $this->main->nname;
	$log_path = "{$web_home}/{$this->main->nname}/stats";
	$cust_log = "{$log_path}/{$this->main->nname}-custom_log";
	$err_log = "{$log_path}/{$this->main->nname}-error_log";

	$wcline = "\tServerAlias \\\n\t\t*.{$domainname}\n\n";

	$string = '';
	$dirp = $this->main->__var_dirprotect;
	$this->clearDomainIpAddress();

	$string .= "<VirtualHost ";
	
	if($this->main->priv->isOn('ssl_flag') && $this->getServerIp()) {
		$iplist = $this->getSslIpList();
		foreach($iplist as $ip) {
			$ssl_cert = $this->sslsysnc($ip);
			if (!$ssl_cert) { continue; }
			$string .= "{$ip}:80";
		}
	}
	else {
		$alliplist = os_get_allips();
		$string .= $alliplist[0] . ":80 " . $alliplist[0] . ":443";
	}

	$string .= " 127.0.0.1:8080>\n\n";

	$syncto = $this->syncToPort("80", $cust_log, $err_log);
	$line = $this->createServerAliasLine();

	$token = "###serveralias###";
	$string .= str_replace($token, $line, $syncto);
	$string .= $this->middlepart($web_home, $domainname, $dirp); 
	$string .= $this->AddOpenBaseDir();
	
	//Grab specific values from the domain's php.ini file to set with php_admin_value
	$string .= "\t<IfModule mod_php5.c>\n";
	$phpinifile = lfile_get_contents("{$web_home}/{$this->main->nname}/php.ini");
	$phpiniarray = array_unique(explode("\n", $phpinifile));
	$phpvaluestosearchfor = array('disable_functions','zlib.output_compression','max_execution_time','max_input_time','memory_limit','post_max_size','upload_max_filesize','session.save_path');
	$phpadminvalues = array();
	foreach($phpvaluestosearchfor as $searchfor)
	{
		$phpadminvalues = array_merge($phpadminvalues, preg_grep("/^$searchfor/", $phpiniarray));
	}
	$phpadminvalues[0] = "\n" . $phpadminvalues[0];
	$phpadminvaluestr = str_replace ("\n", "\n\t\tphp_admin_value ", implode("\n",$phpadminvalues));
	$phpadminvaluestr = str_replace ('=', '', $phpadminvaluestr);
	$string .= $phpadminvaluestr . "\n";
	$string .= "\t</IfModule>\n";

	$string .= "\t<IfDefine light>\n";
	$string .= "\t\tCacheRoot {$web_home}/{$this->main->nname}/disk_cache/\n";
	$string .= "\t\tCacheEnable disk /\n";
	$string .= "\t\tCacheDirLevels 5\n";
	$string .= "\t\tCacheDirLength 3\n";
	$string .= "\t\tCacheIgnoreHeaders Pragma\n";
	$string .= "\t\tProxyPassReverse / http://127.0.0.1:8080/\n";
	$string .= "\t\tProxyPassMatch ^/(.*\\.php.*)$ http://127.0.0.1:8080/$1\n";
	$string .= "\t</IfDefine>\n";
	$string .= $this->endtag();
	lxfile_mkdir($this->main->getFullDocRoot());
	lxfile_mkdir("{$web_home}/{$this->main->nname}/disk_cache/");
	lxfile_unix_chown("{$web_home}/{$this->main->nname}/disk_cache/", "apache:apache");

	if($this->main->priv->isOn('ssl_flag') && $this->getServerIp()) {

		$iplist = $this->getSslIpList();
		foreach($iplist as $ip) {
			$string .= "\n#### ssl virtualhost per ip {$ip} start\n";
			$ssl_cert = $this->sslsysnc($ip);
			if (!$ssl_cert) { continue; }
			$string .= "<VirtualHost {$ip}:443>\n\n";

			$syncto = $this->syncToPort("443", $cust_log, $err_log);

			$line = $this->createServerAliasLine();

			$token = "###serveralias###";
			$string .= str_replace($token, $line, $syncto);

			$string .= $this->sslsysnc($ip);
			$string .= $this->middlepart($web_home, $domainname, $dirp); 
			$string .= $this->AddOpenBaseDir();
					
			$string .= "\t<IfDefine light>\n";
			$string .= "\t\tProxyPassReverse / http://127.0.0.1:8080/\n";
			$string .= "\t\tProxyPassMatch ^/(.*\\.php.*)$ http://127.0.0.1:8080/$1\n";
			$string .= "\t</IfDefine>\n";
			$string .= $this->endtag();
			$string .= "#### ssl virtualhost per ip {$ip} end\n";
		}
	}

	$v_file = "/home/apache/conf/domains/{$domainname}.conf";
				
	$string .= $this->setAddon();
	lfile_put_contents($v_file, $string);
		
	//reload webservers
	system('service httpd reload');
}

function setAddon()
{
	global $gbl, $sgbl, $login, $ghtml;

	$string = '';

	foreach($this->main->__var_addonlist as $m) {
		if ($m->ttype == 'redirect') {
			$string .= "<VirtualHost \\\n{$this->createVirtualHostiplist("80")}";
			$string .= "{$this->createVirtualHostiplist("443")}";
			$string .= "\t\t>\n\n";
			$string .= "\tServerName {$m->nname}\n";
			$string .= "\tServerAlias \\\n\t\twww.{$m->nname}\n\n";
			$dst = "{$this->main->nname}/{$m->destinationdir}/";
			$dst = remove_extra_slash($dst);
			$string .= "\tRedirect / \"http://{$dst}\"\n\n";
			$string .= "</VirtualHost>\n";
		}
	}

	if ($this->main->isOn('force_www_redirect')) {
		$string .= "<VirtualHost \\\n{$this->createVirtualHostiplist("80")}";
		$string .= "\t\t>\n\n";
		$string .= "\tServerName {$this->main->nname}\n\n";
		$string .= "\tRedirect / \"http://www.{$this->main->nname}/\"\n\n";
		$string .= "</VirtualHost>\n\n";
	}
	
	return $string;
}

function getDav()
{
	global $gbl, $sgbl, $login, $ghtml;

	$string = null;

	$bdir = "/home/httpd/{$this->main->nname}/__webdav";

	lxfile_mkdir($bdir);

	foreach($this->main->__var_davuser as $k => $v) {
		$file = get_file_from_path($k);
		$file = "{$bdir}/{$file}";

		$string .= "\t<Location {$k}>\n";
		$string .= "\t\tDAV On\n";
		$string .= "\t\tAuthType Basic\n";
		$string .= "\t\tAuthName \"WebDAV Restricted\"\n";
		$string .= "\t\tAuthUserFile {$file}\n";
		$string .= "\t\t<Limit HEAD GET POST OPTIONS PROPFIND>\n";
		$string .= "\t\t\tAllow from all\n";
		$string .= "\t\t</Limit>\n";
		$string .= "\t\t<Limit MKCOL PUT DELETE LOCK UNLOCK COPY MOVE PROPPATCH>\n";
		$string .= "\t\t\tallow from all\n";
		$string .= "\t\t</Limit>\n";
		$string .= "\t\tRequire valid-user\n";
		$string .= "\t</Location>\n\n";
	}

	return $string;
}

function sslsysnc($ipad)
{
	global $gbl, $sgbl, $login, $ghtml; 

	$ssl_root = $sgbl->__path_ssl_root;

	$ssl_cert = null;

	foreach((array) $this->main->__var_ipssllist as $ip) {
		// Get the first certificate;
		if (!$ipad) {
			$ssl_cert = sslcert::getSslCertnameFromIP($ip['nname']);
			break;
		}
		if ($ip['ipaddr'] === $ipad) {
			$ssl_cert = sslcert::getSslCertnameFromIP($ip['nname']);
			break;
		}
	}

	if (!$ssl_cert) {
		return;
	}

	$string = null;

	$certificatef = "{$ssl_root}/{$ssl_cert}.crt";
	$keyfile = "{$ssl_root}/{$ssl_cert}.key";
	$cafile = "{$ssl_root}/{$ssl_cert}.ca";

	sslcert::checkAndThrow(lfile_get_contents($certificatef), lfile_get_contents($keyfile), $ssl_cert);

	$string .= "\tSSLEngine On \n";
	$string .= "\tSSLCertificateFile {$certificatef}\n";
	$string .= "\tSSLCertificateKeyFile {$keyfile}\n";
	$string .= "\tSSLCACertificatefile {$cafile}\n\n";

	return $string;
}

function createShowAlist(&$alist, $subaction = null)
{
	global $gbl, $sgbl, $login, $ghtml; 

	$gen = $login->getObject('general')->generalmisc_b;

	$alist[] = "a=list&c=component";

	return $alist;
}

function middlepart($web_home, $domain, $dirp) 
{
	global $gbl, $sgbl, $login, $ghtml; 

	$string = null;

	foreach($this->main->customerror_b as $k => $v) {
		if (csb($k, "url_") && $v) {
			$num = strfrom($k, "url_");

			if (csb($v, "http:/")) {
				$nv = $v;
			} else {
				$nv = remove_extra_slash("/{$v}");
			}

			$string .= "\tErrorDocument {$num} {$nv}\n";
		}
	}

	$string .= $this->enablePhp();

	$string .= $this->getDirprotect('');

	return $string;
}

function getDirprotect()
{
	global $gbl, $sgbl, $login, $ghtml;

	$string = null;

	foreach((array) $this->main->__var_dirprotect as $prot) {
		if (!$prot->isOn('status') || $prot->isDeleted()) {
			continue;
		}

		$string .= $this->getDirprotectCore($prot->authname, $prot->path, $prot->getFileName());

	}

	return $string;
}

function getDirprotectCore($authname, $path, $file)
{
	global $gbl, $sgbl, $login, $ghtml; 

	$string  = null;

	// issue #74
	$path = remove_extra_slash("\"/{$path}\"");

	$string .= "\t<Location {$path}>\n";
	$string .= "\t\tAuthType Basic\n";
	$string .= "\t\tAuthName \"{$authname}\"\n";

	// issue #74
	$string .= "\t\tAuthUserFile \"{$sgbl->__path_httpd_root}/{$this->main->nname}/__dirprotect/{$file}\"\n";

	$string .= "\t\trequire  valid-user\n";
	$string .= "\t</Location>\n";

	return $string;
}

function getAwstatsString()
{
	global $gbl, $sgbl, $login, $ghtml; 

	$string  = null;

	$string .= "ScriptAlias /awstats/ \"{$sgbl->__path_kloxo_httpd_root}/awstats/wwwroot/cgi-bin/\"\n";

	if ($this->main->stats_password) {
		$string .= "\t".$this->getDirprotectCore("Awstats", "/awstats", "__stats");
	}

	web::createstatsConf($this->main->nname, $this->main->stats_username, $this->main->stats_password);

	return $string;
}

function getDocumentRoot($subweb)
{
	global $gbl, $sgbl, $login, $ghtml; 

	$path = "{$this->main->getFullDocRoot()}/";

	// Issue #656 - When adding a subdomain, the Document Root field is not being validated
	// Adding quotations so that we can work with directories with spaces
	// MR -- also for other lines

	$string = null;

	if($this->main->isOn('status')) {
		$string .= "DocumentRoot \"{$path}\"\n\n";
	} else {
		if ($this->main->__var_disable_url) {
			$url = add_http_if_not_exist($this->main->__var_disable_url);
			$string .= "\tRedirect / \"{$url}\"\n\n";
		} else {
			$disableurl = "/home/kloxo/httpd/disable/";
			$string .= "\tDocumentRoot \"{$disableurl}\"\n\n";
		}
	}

	return $string;
}

function getIndexFileOrder()
{
	global $gbl, $sgbl, $login, $ghtml;

	if ($this->main->indexfile_list) {
		$list = $this->main->indexfile_list;
	} else {
		$list = $this->main->__var_index_list;
	}
	if (!$list) { return; }

	$string = implode(" ", $list);
	$string = "DirectoryIndex $string\n";

	return $string;
}

function createHotlinkHtaccess()
{
	global $gbl, $sgbl, $login, $ghtml;

	$string = $this->hotlink_protection();
	$stlist[] = "### Kloxo Hotlink Protection";
	$endlist[] = "### End Kloxo Hotlink Protection";
	$startstring = $stlist[0];
	$endstring = $endlist[0];
	$htfile = "{$this->main->getFullDocRoot()}/.htaccess";
	file_put_between_comments($this->main->username, $stlist, $endlist, $startstring, $endstring, $htfile, $string);
	$this->norestart = 'on';
}

function syncToPort($port, $cust_log, $err_log)
{
	global $gbl, $sgbl, $login, $ghtml; 

	$base_root = "$sgbl->__path_httpd_root";

	$user_home = "{$this->main->getFullDocRoot()}/";
	$domname = $this->main->nname;

	$string  = null;

	if ($this->main->isOn('force_www_redirect')) {
		$string .= "\tServerName www.{$domname}\n" ;
	} else {
		$string .= "\tServerName {$domname}\n" ;
	}

	$string .= "###serveralias###";
	
	$string .= "\t".$this->getBlockIP();

	$string .= $this->getDocumentRoot('www');
	$string .= "\t".$this->getIndexFileOrder();

	$string .= "\t".$this->getAwstatsString();

	$assignuserid = ($this->main->isOn('status')) ? $this->main->username : 'lxlabs';
	$string .= "\n\t<IfModule itk.c>\n";
	$string .= "\t\tAssignUserId {$assignuserid} {$assignuserid}\n";
	$string .= "\t</IfModule>\n\n";
	
	foreach((array) $this->main->redirect_a as $red) {
		$rednname = remove_extra_slash("/{$red->nname}");

		if ($red->ttype === 'local') {
			$string .= "\tAlias \"{$rednname}\" \"{$user_home}\"/{$red->redirect}\"\n";
		} else {
			if (!redirect_a::checkForPort($port, $red->httporssl)) { continue; }

			$string .= "\tRedirect \"{$rednname}\" \"{$red->redirect}\"\n";
		}
	}

	if ($this->main->__var_statsprog === 'awstats') {
		$string .= "\tRedirect /stats \"http://{$domname}/awstats/awstats.pl?config={$domname}\"\n";
		$string .= "\tRedirect /stats/ \"http://{$domname}/awstats/awstats.pl?config={$domname}\"\n\n";
	} else {
		$string .= "\tAlias /stats {$base_root}/{$domname}/webstats/\n\n";
	}

	$string .= "\tAlias /__kloxo \"/home/{$this->main->customer_name}/kloxoscript/\"\n\n";

	$string .= "\tRedirect /kloxo \"https://cp.{$domname}:{$this->main->__var_sslport}\"\n";
	$string .= "\tRedirect /kloxononssl \"http://cp.{$domname}:{$this->main->__var_nonsslport}\"\n\n";

	foreach($this->main->__var_mmaillist as $m) {
		if ($m['nname'] === $domname) {
			$webmailprog = (isset($m['webmailprog'])) ? $m['webmailprog'] : '';
			$remotelocalflag = (isset($m['remotelocalflag'])) ? $m['remotelocalflag'] : 'local';
			$webmail_url = (isset($m['webmail_url'])) ? $m['webmail_url'] : '';
			break;
		}
	}

	if($this->main->isOn('status')) {
		$prog = ($webmailprog == '' || $webmailprog == '--system-default--' || $webmailprog == '--chooser--') ? '' : "{$webmailprog}/";
	
		if ($remotelocalflag == 'remote') {
			$webmail_url = add_http_if_not_exist($webmail_url);
			$string .= "\tRedirect /webmail \"{$webmail_url}\"\n";
		}
		else {
			$string .= "\tAlias /webmail \"/home/kloxo/httpd/webmail/{$prog}\"\n";
		}
	}	
		
	$string .= "\t<Directory \"/home/httpd/{$domname}/kloxoscript/\">\n";
	$string .= "\t\tAllowOverride All\n";
	$string .= "\t</Directory>\n\n";

	$string .= $this->addSendmail();

	if ($this->main->priv->isOn('cgi_flag')) {
		$string .= "\tScriptAlias /cgi-bin/ \"{$user_home}/cgi-bin/\"\n\n";
	}
	if ($port === '80') {
		$string .= "\tCustomLog \"{$cust_log}\" combined  \n";
		$string .= "\tErrorLog \"{$err_log}\"\n\n";
	}

	$string .= "\t<Directory \"{$user_home}/\">\n";
	$string .= "\t\tAllowOverride All\n";
	$string .= "\t</Directory>\n\n";
	$string .= "\t<Location />\n";
	$extrastring = null;

	if (isset($this->main->webmisc_b)) {
		if ($this->main->webmisc_b->isOn('execcgi')) {
			$extrastring .= "+ExecCgi";
		}
		if ($this->main->webmisc_b->isOn('dirindex')) {
			$extrastring .= " +Indexes";
		}
	}

	$string .= "\t\tOptions +Includes +FollowSymlinks {$extrastring}\n";

	if (isset($this->main->webmisc_b) && $this->main->webmisc_b->isOn('execcgi')) {
		$string .= "\t\tAddHandler cgi-script .cgi\n";
	}

	$string .= "\t</Location>\n\n";
	$string .= "\t<Directory \"{$base_root}/{$domname}/webstats/\">\n";
	$string .= "\t\tAllowOverride All\n";
	$string .= "\t</Directory>\n\n";

	if (isset($this->main->webindexdir_a)) foreach((array) $this->main->webindexdir_a as $webi) {
		$string .= "\t<Directory {$user_home}/{$webi->nname}>\n";
		$string .= "\t\tAllowOverride All\n";
		$string .= "\t\tOptions +Indexes\n";
		$string .= "\t</Directory>\n\n";
	}
		
	if($this->main->text_extra_tag) {
		$string .= "\n\n#Extra Tags\n{$this->main->text_extra_tag}\n#End Extra Tags\n\n";
	}

	if ($this->main->stats_password) {
		$string .= $this->getDirprotectCore("stats", "/stats", "__stats");
	}

	$string .= $this->getDirIndexCore("/stats");

	return $string;
}

function getRailsConf($app)
{
	global $gbl, $sgbl, $login, $ghtml;

	$string .= "\tProxyPass /{$app} http://localhost:{$apport}/\n";
	$string .= "\tProxyPassReverse /{$app} http://localhost:{$apport}\n";
	$string .= "\tProxyPreserveHost on\n\n";
}

function getDirIndexCore($dir)
{
	global $gbl, $sgbl, $login, $ghtml;

	$string = null;

	$dir = remove_extra_slash("/{$dir}");

	$string .= "\t<Location {$dir}>\n";
	$string .= "\t\tOptions +Indexes\n";
	$string .= "\t</Location>\n\n";

	return $string;
}

function EndTag()
{
	global $gbl, $sgbl, $login, $ghtml;

	$string  = null;

	$string .= "</VirtualHost>\n";  

	return $string;
}

function DeleteSubWeb()
{
	global $gbl, $sgbl, $login, $ghtml; 

	$docroot = $this->main->getFullDocRoot();

	foreach ($this->main->__t_delete_subweb_a_list as $t) {
		$file = "{$docroot}/{$t->nname}";
	}
}

function createServerAliasLine()
{
	global $gbl, $sgbl, $login, $ghtml;

	// MR -- alias too long if one line (http://forum.lxcenter.org/index.php?t=msg&th=16556)

	$string  = null;
	if ($this->main->isOn('force_www_redirect')) {
		$string .= "\tServerAlias ";
	} else {
		$string .= "\tServerAlias \\\n\t\twww.{$this->main->nname}";
	}
	foreach($this->main->server_alias_a as $val) {
		// MR -- issue 674 - wildcard and subdomain problem
		if ($val->nname === '*') { continue; }

		$string .= "\\\n\t\t{$val->nname}.{$this->main->nname}";
	}

	foreach((array) $this->main->__var_addonlist as $d) {
		if ($d->ttype === 'redirect') {
			continue;
		}

		$string .= "\\\n\t\t{$d->nname}\\\n\t\twww.{$d->nname}";
	}

	$string .= "\n\n";

	return $string;
}

function denyByIp()
{
	global $gbl, $sgbl, $login, $ghtml;

	$string  = null;
	$string .= "\t<Ifmodule mod_access.c>\n";
	$string .= "\t\t<Location />\n";
	$string .= "\t\t\tOrder Allow,Deny\n";
	$string .= "\t\t\tDeny from 6.28.130.\n";
	$string .= "\t\t\tAllow from all\n";
	$string .= "\t\t</Location>\n";
	$string .= "\t</Ifmodule>\n\n";

	return $string;
}

function addDomain()
{
	global $gbl, $sgbl, $login, $ghtml;

	$this->main->createDir();
	$this->createConffile();

	$this->main->createPhpInfo();
}

function hotlink_protection()
{
	global $gbl, $sgbl, $login, $ghtml;

	if (!$this->main->isOn('hotlink_flag')) {
		return null;
	}

	$allowed_domain_string = $this->main->text_hotlink_allowed;
	$allowed_domain_string = trim($allowed_domain_string);
	$allowed_domain_string = str_replace("\r", "", $allowed_domain_string);
	$allowed_domain_list = explode("\n", $allowed_domain_string);

	$string  = null;
	$string .= "\tRewriteEngine on\n";
	$string .= "\tRewriteCond %{HTTP_REFERER} !^$\n";

	$ht = trim($this->main->hotlink_redirect, "/");
	$ht = "/{$ht}";

	foreach($allowed_domain_list as $l) {
		$l = trim($l);

		if (!$l) { continue; }

		$string .= "\tRewriteCond %{HTTP_REFERER} !^http://.*{$l}.*$ [NC]\n";
		$string .= "\tRewriteCond %{HTTP_REFERER} !^https://.*{$l}.*$ [NC]\n";
	}

	$l = $this->main->nname;

	$string .= "\tRewriteCond %{HTTP_REFERER} !^http://.*{$l}.*$ [NC]\n";
	$string .= "\tRewriteCond %{HTTP_REFERER} !^https://.*{$l}.*$ [NC]\n";
	$string .= "\tRewriteRule .*[JrRjP][PpdDAa][GfFgrR]$|.*[Gg][Ii][Ff]$ {$ht} [L]\n";

	return $string;
}

function dbactionAdd()
{
	global $gbl, $sgbl, $login, $ghtml;

	$this->addDomain();
	$this->main->doStatsPageProtection();
}

function dbactionDelete()
{
	global $gbl, $sgbl, $login, $ghtml;

	$this->delDomain();
}

function dosyncToSystemPost()
{
	global $gbl, $sgbl, $login, $ghtml; 

	if (!$this->isOn('norestart')) {
		createRestartFile("apache");
	}
}

function addAllSubweb()
{
	global $gbl, $sgbl, $login, $ghtml;

	$this->AddSubWeb($this->subweb_a);
}

function AddSubWeb($list)
{
	global $gbl, $sgbl, $login, $ghtml; 
	
	$web_home = $sgbl->__path_httpd_root;
	$base_root = $sgbl->__path_httpd_root;

	$user_home = "{$this->main->getFullDocRoot()}/";

	foreach((array) $list as $subweb) {
		lxfile_mkdir("{$user_home}/subdomains/{$subweb->nname}");
	}
}

function fullUpdate()
{
	global $gbl, $sgbl, $login, $ghtml;

	$domname = $this->main->nname;
	$uname = $this->main->username;

	$hroot = $sgbl->__path_httpd_root;
	$droot = $this->main->getFullDocRoot();

	lxfile_mkdir("{$hroot}/{$domname}/webstats");

	$this->main->createPhpInfo();
	web::createstatsConf($domname, $this->main->stats_username, $this->main->stats_password);

	$this->createConffile();
	lxfile_unix_chown_rec("{$droot}/", "{$uname}:{$uname}");
	lxfile_unix_chmod("{$droot}/", "0755");
	lxfile_unix_chmod("{$droot}", "0755");
	lxfile_unix_chown("{$hroot}/{$domname}", "{$uname}:apache");
}

function dbactionUpdate($subaction)
{
	global $gbl, $sgbl, $login, $ghtml; 

	if (!$this->main->customer_name) {
		log_log("critical", "Lack customername for web: {$this->main->nname}");
		return;
	}

	switch($subaction) {

		case "full_update":
			if ($this->main->username) {
				$this->fullUpdate();
				$this->main->doStatsPageProtection();
			}

			break;

		case "add_subweb_a":
			$this->AddSubWeb($this->main->__t_new_subweb_a_list);
			$this->createConffile();
			break;

		case "delete_subweb_a":
			$this->DeleteSubWeb();
			$this->createConffile();
			break;

		case "changeowner":
			$this->main->webChangeOwner();
			$this->createConffile();
			break;

		case "create_config":
		case "addondomain":
			//$this->createConffile();
			break;

		case "add_delete_dirprotect":
		case "extra_tag" : 
		case "add_dirprotect" : 
		case "custom_error":
		case "dirindex":
		case "docroot":
		case "ipaddress": 
		case "blockip";
		case "add_redirect_a":
		case "delete_redirect_a":
		case "delete_redirect_a":
		case "add_webindexdir_a":
		case "delete_webindexdir_a":
		case "add_server_alias_a" : 
		case "delete_server_alias_a" : 
		case "configure_misc":
			$this->createConffile();
			break;

		case "redirect_domain" :
			$this->createConffile();
			break;

		case "add_forward_alias_a" : 
		case "delete_forward_alias_a" : 

		case "fixipdomain":
			$this->createConffile();
			$this->updateMainConfFile();
			break;

		case "enable_php_manage_flag":
			$this->createConffile();
			$this->updateMainConfFile();
			break;

		case "toggle_status" : 
			$this->createConffile();
			break;

		case "hotlink_protection":
			$this->createHotlinkHtaccess();
			break;

		case "enable_php_flag":
		case "enable_cgi_flag":
		case "enable_inc_flag":
		case "enable_ssl_flag" : 
			$this->createConffile();
			break;

		case "stats_protect":
			$this->main->doStatsPageProtection();
			$this->createConffile();
			break;

		case "default_domain":
			$this->main->setupDefaultDomain();
			break;

		case "graph_webtraffic":
			return rrd_graph_single("webtraffic (bytes)", $this->main->nname, $this->main->rrdtime);
			break;

		case "run_stats":
			$this->main->runStats();
			break;

		case "static_config_update":
			$this->updateMainConfFile();
			break;
	}
}

function do_backup()
{
	return $this->main->do_backup();
}

function do_restore($docd)
{
	global $gbl, $sgbl, $login, $ghtml; 

	$name = $this->main->nname;
	$fullpath = "{$sgbl->__path_customer_root}/{$this->main->customer_name}/";

	$this->main->do_restore($docd);

	lxfile_unix_chown_rec($fullpath, $this->main->username);
}

}