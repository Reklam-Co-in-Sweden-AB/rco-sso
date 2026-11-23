<?php
// Hela inloggningsflödet mot en lokal WordPress med rco-sso v0.4.
// En egen testnyckel ersätter Microsofts: den läggs i transienten rco_sso_jwks.
// Körs mot en lokal WordPress, se README (avsnittet Test).

$site = $argv[1];
$base = 'http://127.0.0.1:8099';
$_SERVER['HTTP_HOST'] = '127.0.0.1:8099';
require $site . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

const TENANT = '11111111-2222-3333-4444-555555555555';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

$fail = 0;
$n    = 0;
function ok( $cond, $name, $extra = '' ) {
	global $fail, $n;
	$n++;
	echo ( $cond ? 'ok   ' : 'FEL  ' ) . $name . ( $cond || '' === $extra ? '' : "  [$extra]" ) . "\n";
	if ( ! $cond ) {
		$fail++;
	}
}

// --- Testnyckel i stället för Microsofts ---
$key = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
$d   = openssl_pkey_get_details( $key );
$jwk = array( 'kty' => 'RSA', 'kid' => 'test1', 'n' => RCO_SSO_Token::b64url_encode( $d['rsa']['n'] ), 'e' => RCO_SSO_Token::b64url_encode( $d['rsa']['e'] ) );
set_transient( 'rco_sso_jwks', array( $jwk ), DAY_IN_SECONDS );
set_transient( 'rco_sso_jwks_refetch', 1, HOUR_IN_SECONDS ); // ingen hämtning mot Microsoft

function token( $claims ) {
	global $key;
	$now = time();
	$p   = array_merge( array( 'iss' => 'https://login.microsoftonline.com/' . TENANT . '/v2.0', 'aud' => CLIENT, 'tid' => TENANT, 'iat' => $now, 'nbf' => $now, 'exp' => $now + 3600, 'name' => 'Test Person' ), $claims );
	$h   = RCO_SSO_Token::b64url_encode( json_encode( array( 'alg' => 'RS256', 'kid' => 'test1' ) ) );
	$b   = RCO_SSO_Token::b64url_encode( json_encode( $p ) );
	openssl_sign( "$h.$b", $sig, $key, OPENSSL_ALGO_SHA256 );
	return "$h.$b." . RCO_SSO_Token::b64url_encode( $sig );
}

// --- HTTP ---
function http( $method, $path, $fields = null, $cookies = array(), $headers = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = $headers;
	if ( $cookies ) {
		$h[] = 'Cookie: ' . implode( '; ', array_map( function ( $k, $v ) { return "$k=$v"; }, array_keys( $cookies ), $cookies ) );
	}
	curl_setopt_array( $ch, array( CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_HTTPHEADER => $h ) );
	if ( null !== $fields ) {
		curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $fields ) );
	}
	$raw  = curl_exec( $ch );
	$size = curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	$res  = array( 'status' => curl_getinfo( $ch, CURLINFO_RESPONSE_CODE ), 'headers' => substr( $raw, 0, $size ), 'body' => substr( $raw, $size ), 'location' => '', 'cookies' => array(), 'setcookie' => array() );
	foreach ( explode( "\r\n", $res['headers'] ) as $line ) {
		if ( 0 === stripos( $line, 'Location:' ) ) {
			$res['location'] = trim( substr( $line, 9 ) );
		}
		if ( 0 === stripos( $line, 'Set-Cookie:' ) ) {
			$c                     = trim( substr( $line, 11 ) );
			list( $kv )            = explode( ';', $c, 2 );
			list( $k, $v )         = explode( '=', $kv, 2 );
			$res['cookies'][ $k ]  = $v;
			$res['setcookie'][ $k ] = $c;
		}
	}
	return $res;
}

/** Starta inloggningen och returnera nonce, state och cookies. */
function start( $redirect = '/wp-admin/profile.php' ) {
	global $base;
	$r = http( 'GET', '/wp-login.php?action=rco_sso&redirect_to=' . rawurlencode( $base . $redirect ) );
	parse_str( (string) parse_url( $r['location'], PHP_URL_QUERY ), $q );
	return array( 'r' => $r, 'q' => $q, 'cookies' => array_intersect_key( $r['cookies'], array( '__Host-rco_sso_c' => 1, '__Host-rco_sso_to' => 1 ) ) );
}

function callback( $s, $claims, $state = null, $cookies = null ) {
	$claims = array_merge( array( 'nonce' => $s['q']['nonce'] ), $claims );
	$tok    = token( $claims );
	return array( http( 'POST', '/wp-login.php?action=rco_sso_callback', array( 'id_token' => $tok, 'state' => $state ?? $s['q']['state'] ), $cookies ?? $s['cookies'] ), $tok );
}

function error_code( $r ) {
	parse_str( (string) parse_url( $r['location'], PHP_URL_QUERY ), $q );
	return $q['rco_sso_error'] ?? '';
}

function fresh_user( $login_or_email ) {
	$u = get_user_by( is_email( $login_or_email ) ? 'email' : 'login', $login_or_email );
	if ( $u ) {
		clean_user_cache( $u );
		wp_cache_flush();
		$u = get_userdata( $u->ID );
	}
	return $u;
}

// === 1. Knappen ===
$r = http( 'GET', '/wp-login.php' );
ok( 200 === $r['status'] && false !== strpos( $r['body'], 'Logga in med Reklam &amp; Co' ), 'knappen visas på inloggningssidan' );

// === 2. Start ===
$s = start();
ok( 302 === $s['r']['status'] && 0 === strpos( $s['r']['location'], 'https://login.microsoftonline.com/' . TENANT . '/oauth2/v2.0/authorize?' ), 'start skickar till Microsoft', $s['r']['location'] );
ok( 'id_token' === ( $s['q']['response_type'] ?? '' ) && 'form_post' === ( $s['q']['response_mode'] ?? '' ) && CLIENT === ( $s['q']['client_id'] ?? '' ), 'rätt response_type, response_mode och client_id' );
ok( 'https://sso.reklamco.se/api/wp-sso/callback' === ( $s['q']['redirect_uri'] ?? '' ) && 'openid profile email' === ( $s['q']['scope'] ?? '' ), 'rätt redirect_uri och scope' );
ok( 1 === preg_match( '/^127\.0\.0\.1\.[A-Za-z0-9_-]{43}$/', $s['q']['state'] ?? '' ), 'state = värdnamn + cookiens hash', $s['q']['state'] ?? '' );
$c = $s['r']['setcookie']['__Host-rco_sso_c'] ?? '';
ok( false !== stripos( $c, 'SameSite=None' ) && false !== stripos( $c, 'HttpOnly' ) && false !== stripos( $c, 'secure' ) && 1 === preg_match( '/path=\/(;|$)/i', $c ) && false === stripos( $c, 'domain=' ), 'nonce-cookien har rätt flaggor och prefixet __Host-', $c );
$c_hash = RCO_SSO_Token::b64url_encode( hash( 'sha256', $s['cookies']['__Host-rco_sso_c'], true ) );
ok( $s['q']['state'] === '127.0.0.1.' . $c_hash && $s['q']['nonce'] !== $s['cookies']['__Host-rco_sso_c'] && $s['q']['nonce'] !== $c_hash, 'cookien lämnar aldrig sajten: state bär hashen, nonce något annat' );
$r = http( 'POST', '/wp-login.php?action=rco_sso', array() );
ok( 'invalid' === error_code( $r ), 'start via POST nekas' );

// === 3. Befintligt personalkonto kopplas ===
$byran = fresh_user( 'byran@reklamco.se' );
$old_hash = $byran->user_pass;
list( $r, $tok ) = callback( $s, array( 'oid' => 'oid-byran', 'preferred_username' => 'Byran@Reklamco.se', 'roles' => array( 'wp.editor' ) ) );
// Sajten svarar med en sida som går vidare, inte med en omdirigering: annars
// stoppar Chrome kedjan när målet leder vidare till en annan värd (reläets form-action).
ok( 200 === $r['status'] && '' === $r['location'] && false !== strpos( $r['body'], '<meta http-equiv="refresh" content="0;url=' . esc_url( $base . '/wp-admin/profile.php' ) . '">' ), 'inloggning lyckas och går till redirect_to', $r['status'] . ' ' . $r['location'] . ' ' . error_code( $r ) );
ok( false !== stripos( $r['headers'], 'no-store' ) || false !== stripos( $r['headers'], 'no-cache' ), 'sidan efter inloggningen cachas inte' );
$logged = array_filter( $r['cookies'], function ( $k ) { return 0 === strpos( $k, 'wordpress_logged_in_' ); }, ARRAY_FILTER_USE_KEY );
ok( (bool) $logged, 'inloggningscookie sätts' );
$byran = fresh_user( 'byran@reklamco.se' );
ok( array( 'editor' ) === array_values( $byran->roles ), 'rollen sätts från wp.editor', implode( ',', $byran->roles ) );
ok( 'oid-byran' === get_user_meta( $byran->ID, 'rco_sso_oid', true ) && get_user_meta( $byran->ID, 'rco_sso_linked', true ), 'kontot kopplas på oid' );
ok( $old_hash !== $byran->user_pass, 'lösenordet slumpas om vid första kopplingen' );
ok( 'Test Person' === $byran->display_name, 'visningsnamnet uppdateras' );
ok( 1 === count( get_users( array( 'search' => 'byran*', 'search_columns' => array( 'user_login' ) ) ) ), 'inget dubbelkonto skapas' );

// Inloggningscookien fungerar
$all = array_merge( $r['cookies'] );
$r2  = http( 'GET', '/wp-admin/profile.php', null, $all );
ok( 200 === $r2['status'], 'adminpanelen nås med cookien', (string) $r2['status'] );

// === 4. Samma token igen ===
list( $r ) = array( http( 'POST', '/wp-login.php?action=rco_sso_callback', array( 'id_token' => $tok, 'state' => $s['q']['state'] ), $s['cookies'] ) );
ok( 'invalid' === error_code( $r ), 'återanvänd token nekas', error_code( $r ) );
// Samma token med ändrade utfyllnadsbitar i signaturens sista tecken: signaturen
// är fortfarande giltig, men token ska ändå räknas som använd.
$alfa = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
$tok2 = substr( $tok, 0, -1 ) . $alfa[ strpos( $alfa, substr( $tok, -1 ) ) ^ 1 ];
$sig_same = RCO_SSO_Token::b64url_decode( substr( strrchr( $tok, '.' ), 1 ) ) === RCO_SSO_Token::b64url_decode( substr( strrchr( $tok2, '.' ), 1 ) );
$r = http( 'POST', '/wp-login.php?action=rco_sso_callback', array( 'id_token' => $tok2, 'state' => $s['q']['state'] ), $s['cookies'] );
ok( $tok2 !== $tok && $sig_same && 'invalid' === error_code( $r ), 'återanvänd token med ändrat sista tecken nekas', error_code( $r ) );

// === 5. Ingen cookie ===
$s2 = start();
list( $r ) = callback( $s2, array( 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.editor' ) ), null, array() );
ok( 'expired' === error_code( $r ), 'utan nonce-cookie: meddelandet om att försöka igen', error_code( $r ) );
$r = http( 'GET', '/wp-login.php?rco_sso_error=expired' );
ok( false !== strpos( $r['body'], 'tog för lång tid' ), 'felmeddelandet visas på inloggningssidan' );

// === 6. Fel nonce (cookie från en annan start) ===
$s3 = start();
$s4 = start();
list( $r ) = callback( $s3, array( 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.editor' ) ), null, $s4['cookies'] );
ok( 'invalid' === error_code( $r ), 'token med en annan webbläsares nonce nekas', error_code( $r ) );

// === 7. State för en annan sajt ===
$s5 = start();
list( $r ) = callback( $s5, array( 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.editor' ) ), 'annan.se.abcdefghijklmnopqrstuv' );
ok( 'invalid' === error_code( $r ), 'state för en annan sajt nekas', error_code( $r ) );

// === 8. Nytt konto, administratör ===
$s6 = start();
list( $r ) = callback( $s6, array( 'oid' => 'oid-ny', 'preferred_username' => 'ny.person@reklamco.se', 'roles' => array( 'wp.editor', 'wp.admin' ) ) );
$ny = fresh_user( 'ny.person@reklamco.se' );
ok( '' === error_code( $r ) && $ny && array( 'administrator' ) === array_values( $ny->roles ), 'nytt konto skapas, wp.admin vinner över wp.editor', error_code( $r ) );
ok( $ny && 'ny.person' === $ny->user_login, 'användarnamn från e-postens lokala del', $ny ? $ny->user_login : '' );

// === 9. Oid hittar kontot även om e-posten ändrats ===
$s7 = start();
list( $r ) = callback( $s7, array( 'oid' => 'oid-ny', 'preferred_username' => 'nytt.namn@reklamco.se', 'roles' => array( 'wp.editor' ) ) );
$ny = fresh_user( 'ny.person' );
ok( '' === error_code( $r ) && 'nytt.namn@reklamco.se' === $ny->user_email && array( 'editor' ) === array_values( $ny->roles ), 'samma oid: e-post och roll uppdateras på samma konto', error_code( $r ) );

// === 10. Kontot är kopplat till annan person ===
$s8 = start();
list( $r ) = callback( $s8, array( 'oid' => 'oid-inkraktare', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.admin' ) ) );
ok( 'account' === error_code( $r ), 'annat oid får inte ta över ett kopplat konto', error_code( $r ) );
ok( array( 'editor' ) === array_values( fresh_user( 'byran@reklamco.se' )->roles ), 'kontot behåller sin roll efter försöket' );

// === 11. Ingen roll / fel domän / fel signatur ===
$s9 = start();
list( $r ) = callback( $s9, array( 'oid' => 'oid-x', 'preferred_username' => 'x@reklamco.se', 'roles' => array() ) );
ok( 'role' === error_code( $r ) && ! fresh_user( 'x@reklamco.se' ), 'utan approll: nekas och inget konto skapas', error_code( $r ) );
$s10 = start();
list( $r ) = callback( $s10, array( 'oid' => 'oid-y', 'preferred_username' => 'y@kund.se', 'roles' => array( 'wp.admin' ) ) );
ok( 'invalid' === error_code( $r ) && ! fresh_user( 'y@kund.se' ), 'adress utanför reklamco.se nekas', error_code( $r ) );
$s11 = start();
$t   = token( array( 'nonce' => $s11['q']['nonce'], 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.admin' ) ) );
$p   = explode( '.', $t );
$p[1] = RCO_SSO_Token::b64url_encode( json_encode( array_merge( json_decode( RCO_SSO_Token::b64url_decode( $p[1] ), true ), array( 'roles' => array( 'wp.admin' ), 'preferred_username' => 'byran@reklamco.se' ) ) ) . ' ' );
$r   = http( 'POST', '/wp-login.php?action=rco_sso_callback', array( 'id_token' => implode( '.', $p ), 'state' => $s11['q']['state'] ), $s11['cookies'] );
ok( 'invalid' === error_code( $r ), 'manipulerad token nekas', error_code( $r ) );

// === 11b. Bara UPN räknas, inte claimet email ===
$s13 = start();
list( $r ) = callback( $s13, array( 'oid' => 'oid-z', 'preferred_username' => null, 'email' => 'z@reklamco.se', 'roles' => array( 'wp.admin' ) ) );
ok( 'invalid' === error_code( $r ) && ! fresh_user( 'z@reklamco.se' ), 'utan UPN nekas inloggningen även om email är en personaladress', error_code( $r ) );
$s14 = start();
list( $r ) = callback( $s14, array( 'oid' => 'oid-gast', 'preferred_username' => 'gast_kund.se#EXT#@reklamco.onmicrosoft.com', 'email' => 'byran@reklamco.se', 'roles' => array( 'wp.admin' ) ) );
ok( 'invalid' === error_code( $r ) && 'oid-byran' === get_user_meta( fresh_user( 'byran@reklamco.se' )->ID, 'rco_sso_oid', true ), 'gästkonto med personalens adress i email kommer inte in', error_code( $r ) );

// === 12. Lösenord ===
wp_set_password( 'kandpass456', fresh_user( 'byran@reklamco.se' )->ID );
$r = http( 'POST', '/wp-login.php', array( 'log' => 'byran', 'pwd' => 'kandpass456', 'testcookie' => 1 ), array( 'wordpress_test_cookie' => 'WP%20Cookie%20check' ) );
ok( 200 === $r['status'] && false !== strpos( $r['body'], 'Personal på Reklam &amp; Co loggar in med knappen' ), 'personal kan inte logga in med lösenord', (string) $r['status'] );
$r = http( 'POST', '/wp-login.php', array( 'log' => 'kundadmin', 'pwd' => 'kundpass123', 'testcookie' => 1 ), array( 'wordpress_test_cookie' => 'WP%20Cookie%20check' ) );
ok( 302 === $r['status'] && false !== strpos( $r['location'], 'wp-admin' ), 'kundens administratör loggar in med lösenord', (string) $r['status'] );

// === 13. 30-dagarsregeln för applikationslösenord ===
$uid = fresh_user( 'byran@reklamco.se' )->ID;
list( $app_pass ) = WP_Application_Passwords::create_new_application_password( $uid, array( 'name' => 'MCP-test' ) );
$auth = array( 'Authorization: Basic ' . base64_encode( 'byran:' . $app_pass ) );
// Applikationslösenord kräver https eller lokal miljö.
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), $auth );
ok( 200 === $r['status'], 'applikationslösenord fungerar efter färsk SSO-inloggning', $r['status'] . ' ' . substr( $r['body'], 0, 150 ) );
update_user_meta( $uid, 'rco_sso_last_login', time() - 31 * DAY_IN_SECONDS );
update_user_meta( $uid, 'rco_sso_linked', time() - 31 * DAY_IN_SECONDS );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), $auth );
ok( 401 === $r['status'] && false !== strpos( $r['body'], 'pausad' ), 'efter 31 dagar: pausad med förklaring', $r['status'] . ' ' . substr( $r['body'], 0, 150 ) );
$s12 = start();
list( $r ) = callback( $s12, array( 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.editor' ) ) );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), $auth );
ok( 200 === $r['status'], 'ny SSO-inloggning öppnar kopplingen igen', (string) $r['status'] );

// === 13b. Beaver Builder AI:s molnkoppling (simulator i mu-plugins) ===
function bb_token( $wp_user_id, $iss = 'https://connect.wpbeaverbuilder.com' ) {
	global $key;
	$h = RCO_SSO_Token::b64url_encode( json_encode( array( 'alg' => 'RS256', 'kid' => 'bb' ) ) );
	$b = RCO_SSO_Token::b64url_encode( json_encode( array( 'iss' => $iss, 'aud' => 'http://127.0.0.1:8099', 'wp_user_id' => $wp_user_id, 'exp' => time() + 600 ) ) );
	openssl_sign( "$h.$b", $sig, $key, OPENSSL_ALGO_SHA256 );
	return array( 'Authorization: Bearer ' . "$h.$b." . RCO_SSO_Token::b64url_encode( $sig ) );
}
$kund = fresh_user( 'kundadmin' );
ok( file_exists( WPMU_PLUGIN_DIR . '/bb-ai-simulator.php' ), 'BB-simulatorn är installerad på testsajten' );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), bb_token( $uid ) );
ok( 200 === $r['status'], 'BB-token för SSO-kopplat konto med färsk inloggning släpps in', $r['status'] . ' ' . substr( $r['body'], 0, 120 ) );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), bb_token( $kund->ID ) );
ok( 403 === $r['status'] && false !== strpos( $r['body'], 'rco_sso_personal_account_required' ), 'BB-token för kundens administratör nekas', $r['status'] . ' ' . substr( $r['body'], 0, 120 ) );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), bb_token( $kund->ID, 'https://bb-mcp-connect.info-288.workers.dev' ) );
ok( 403 === $r['status'] && false !== strpos( $r['body'], 'rco_sso_personal_account_required' ), 'BB-token från den äldre utfärdaren nekas också för kundens administratör', $r['status'] . ' ' . substr( $r['body'], 0, 120 ) );
update_user_meta( $uid, 'rco_sso_last_login', time() - 31 * DAY_IN_SECONDS );
update_user_meta( $uid, 'rco_sso_linked', time() - 31 * DAY_IN_SECONDS );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), bb_token( $uid ) );
ok( 401 === $r['status'] && false !== strpos( $r['body'], 'pausad' ), 'BB-token efter 31 dagar nekas trots att BB sätter användaren direkt', $r['status'] . ' ' . substr( $r['body'], 0, 120 ) );
update_user_meta( $uid, 'rco_sso_last_login', time() );

$blocklist_file = getenv( 'BLOCKLIST_DIR' ) . '/sparrade.json';
function set_blocklist( $hashes, $dev_hosts = array() ) {
	global $blocklist_file;
	if ( null === $hashes ) {
		@unlink( $blocklist_file );
	} else {
		file_put_contents( $blocklist_file, json_encode( array( 'version' => 1, 'hashes' => array_values( $hashes ), 'dev_hosts' => array_values( $dev_hosts ) ) ) );
	}
	delete_transient( RCO_SSO_Blocklist::TRANSIENT );
}

// === 13c. Applikationslösenord för personliga konton bara lokalt och på utvecklingssajter i registret ===
$byra = fresh_user( 'byrakonto@reklamco.se' );
if ( ! $byra ) {
	$byra = get_userdata( wp_insert_user( array( 'user_login' => 'byrakonto', 'user_email' => 'byrakonto@reklamco.se', 'user_pass' => wp_generate_password(), 'role' => 'administrator' ) ) );
}
$personlig = fresh_user( 'byran@reklamco.se' );
delete_option( RCO_SSO_Blocklist::LAST_OPTION );
set_blocklist( array() );
ok( false === rco_sso_staff_app_passwords( true, $personlig, 'production' ), 'personligt konto: inga applikationslösenord i produktion' );
ok( false === rco_sso_staff_app_passwords( true, $personlig, 'staging' ), 'personligt konto: staging i wp-config räcker inte' );
ok( true === rco_sso_staff_app_passwords( true, $personlig, 'local' ), 'personligt konto: applikationslösenord tillåts lokalt' );
set_blocklist( array(), array( RCO_SSO_Blocklist::hash( 'host', RCO_SSO_Login::own_host() ) ) );
ok( true === rco_sso_staff_app_passwords( true, $personlig, 'production' ), 'personligt konto: tillåts på utvecklingssajt i registret' );
set_blocklist( array(), array( RCO_SSO_Blocklist::hash( 'host', 'annan.hemsida.eu' ) ) );
ok( false === rco_sso_staff_app_passwords( true, $personlig, 'production' ), 'personligt konto: en annan sajts utvecklingsmarkering gäller inte här' );
set_blocklist( null );
delete_option( RCO_SSO_Blocklist::LAST_OPTION );
ok( false === rco_sso_staff_app_passwords( true, $personlig, 'production' ), 'personligt konto: ingen lista alls ger produktionsregler' );
set_blocklist( array() );
ok( true === rco_sso_staff_app_passwords( true, $byra, 'production' ), 'byråkontot (ej SSO-kopplat) påverkas inte' );
ok( true === rco_sso_staff_app_passwords( true, $kund, 'production' ), 'kundens konto påverkas inte' );

// === 13d. Spärrlistan (serveras från BLOCKLIST_DIR på port 8098) ===
function login_byran() {
	$s = start();
	list( $r ) = callback( $s, array( 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.editor' ) ) );
	return $r;
}
delete_option( RCO_SSO_Blocklist::LAST_OPTION );
set_blocklist( array() );
$r = login_byran();
$cookies = $r['cookies'];
ok( '' === error_code( $r ), 'tom spärrlista: inloggning fungerar', error_code( $r ) );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), bb_token( $uid ) );
ok( 200 === $r['status'], 'tom spärrlista: Beaver Builders token fungerar', (string) $r['status'] );
list( $app_pass2 ) = WP_Application_Passwords::create_new_application_password( $uid, array( 'name' => 'före spärr' ) );

// Spärra på oid. Webbläsarsessionen loggas ut vid nästa sidvisning.
set_blocklist( array( RCO_SSO_Blocklist::hash( 'oid', 'oid-byran' ) ) );
$r = http( 'GET', '/wp-admin/profile.php', null, $cookies );
ok( 302 === $r['status'] && false !== strpos( $r['location'], 'wp-login.php' ), 'spärrad: inloggad webbläsarsession loggas ut', $r['status'] . ' ' . $r['location'] );
$sparrad = fresh_user( 'byran@reklamco.se' );
ok( array() === array_values( $sparrad->roles ), 'spärrad: rollen tas bort', implode( ',', $sparrad->roles ) );
ok( array() === WP_Application_Passwords::get_user_application_passwords( $uid ), 'spärrad: applikationslösenorden raderas' );
ok( array() === WP_Session_Tokens::get_instance( $uid )->get_all(), 'spärrad: alla sessioner avslutas' );
$r = http( 'GET', '/?rest_route=/wp/v2/users/me', null, array(), bb_token( $uid ) );
ok( in_array( $r['status'], array( 401, 403 ), true ), 'spärrad: Beaver Builders token nekas', (string) $r['status'] );
$r = login_byran();
ok( 'blocked' === error_code( $r ) && array() === array_values( fresh_user( 'byran@reklamco.se' )->roles ), 'spärrad: ny inloggning nekas och ger ingen roll', error_code( $r ) );
$r = http( 'GET', '/wp-login.php?rco_sso_error=blocked' );
ok( false !== strpos( $r['body'], 'spärrat' ), 'spärrad: meddelandet visas på inloggningssidan' );

// Spärr på UPN fungerar också.
set_blocklist( array( RCO_SSO_Blocklist::hash( 'upn', 'byran@reklamco.se' ) ) );
ok( RCO_SSO_Blocklist::is_user_blocked( $uid ), 'spärr på UPN känns igen' );

// CoWeb svarar inte: senaste listan gäller fortfarande.
set_blocklist( null );
$r = login_byran();
ok( 'blocked' === error_code( $r ), 'listan går inte att hämta: senaste listan gäller', error_code( $r ) );

// Spärren tas bort: inloggning ger rollen tillbaka.
set_blocklist( array() );
$r = login_byran();
ok( '' === error_code( $r ) && array( 'editor' ) === array_values( fresh_user( 'byran@reklamco.se' )->roles ), 'spärren borttagen: inloggning ger rollen tillbaka', error_code( $r ) );

// Kundens konto påverkas aldrig, även om dess adress skulle stå på listan.
set_blocklist( array( RCO_SSO_Blocklist::hash( 'upn', 'kund@kund.se' ) ) );
ok( ! RCO_SSO_Blocklist::is_user_blocked( $kund->ID ), 'konto utan SSO-koppling spärras aldrig' );

// Aldrig hämtad lista och CoWeb nere: ingen spärras.
set_blocklist( null );
delete_option( RCO_SSO_Blocklist::LAST_OPTION );
ok( ! RCO_SSO_Blocklist::is_user_blocked( $uid ), 'ingen lista alls: ingen spärras' );
set_blocklist( array() );

// === 14. Sessionslängd ===
ok( 10 * HOUR_IN_SECONDS === apply_filters( 'auth_cookie_expiration', 14 * DAY_IN_SECONDS, $uid, true ), 'personalens session är högst 10 timmar' );

// === 14b. Rättningar efter säkerhetsgranskningen ===
set_blocklist( array() );
$egen = RCO_SSO_Login::own_host();

// Passiv variant: token från en inloggning på en annan sajt (A), uppspelad här med A:s cookie.
$s = start();
$c = RCO_SSO_Token::b64url_encode( hash( 'sha256', $s['cookies']['__Host-rco_sso_c'], true ) );
$tok_a = token( array( 'nonce' => RCO_SSO_Login::nonce_for( 'a.kund.se', $c ), 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.admin' ) ) );
$r = http( 'POST', '/wp-login.php?action=rco_sso_callback', array( 'id_token' => $tok_a, 'state' => "$egen.$c" ), $s['cookies'] );
ok( 'invalid' === error_code( $r ), 'token från inloggning på en annan sajt godtas inte här (passiv variant)', error_code( $r ) );
$s = start();
$c = RCO_SSO_Token::b64url_encode( hash( 'sha256', $s['cookies']['__Host-rco_sso_c'], true ) );
$tok_a = token( array( 'nonce' => RCO_SSO_Login::nonce_for( 'a.kund.se', $c ), 'oid' => 'oid-byran', 'preferred_username' => 'byran@reklamco.se', 'roles' => array( 'wp.admin' ) ) );
$r = http( 'POST', '/wp-login.php?action=rco_sso_callback', array( 'id_token' => $tok_a, 'state' => "a.kund.se.$c" ), $s['cookies'] );
ok( 'invalid' === error_code( $r ), 'state för en annan sajt med token bunden till den sajten godtas inte', error_code( $r ) );
$s = start();
ok( 0 === strpos( $s['q']['state'], $egen . '.' ) && $s['q']['nonce'] === RCO_SSO_Login::nonce_for( $egen, substr( $s['q']['state'], strlen( $egen ) + 1 ) ), 'nonce binder ihop sajtens värdnamn och cookiens hash i state' );

// Starten godtas bara från sajten själv eller en adress personen själv öppnat.
foreach ( array( 'cross-site', 'same-site' ) as $varifran ) {
	$r = http( 'GET', '/wp-login.php?action=rco_sso&redirect_to=' . rawurlencode( $base . '/wp-admin/plugins.php' ), null, array(), array( "Sec-Fetch-Site: $varifran" ) );
	ok( 'manual' === error_code( $r ) && ! isset( $r['setcookie']['__Host-rco_sso_c'] ) && false === strpos( $r['location'], 'microsoftonline' ), "start från annan webbplats ($varifran) loggar inte in", $r['location'] );
}
$r = http( 'GET', '/wp-login.php?action=rco_sso', null, array(), array( 'Sec-Fetch-Site: same-origin' ) );
ok( false !== strpos( $r['location'], 'login.microsoftonline.com' ), 'start från sajtens egen inloggningssida fungerar' );
$r = http( 'GET', '/wp-login.php?action=rco_sso', null, array(), array( 'Sec-Fetch-Site: none' ) );
ok( false !== strpos( $r['location'], 'login.microsoftonline.com' ), 'start från en adress personen själv öppnat fungerar' );
$r = http( 'GET', '/wp-login.php?rco_sso_error=manual' );
ok( false !== strpos( $r['body'], 'Klicka på knappen nedan' ), 'meddelandet om att klicka på knappen visas' );

// GET mot callback rör inte cookien.
$s = start();
$r = http( 'GET', '/wp-login.php?action=rco_sso_callback', null, $s['cookies'] );
ok( ! isset( $r['setcookie']['__Host-rco_sso_c'] ), 'GET mot callback tar inte bort nonce-cookien' );

// Kopplat konto: e-post och lösenord är låsta, och kontot räknas som personal även med annan adress.
$r = login_byran();
$b = fresh_user( 'byran@reklamco.se' );
$hash_fore = $b->user_pass;
wp_update_user( array( 'ID' => $b->ID, 'user_email' => 'privat@example.com', 'user_pass' => 'mitt-eget-lösenord' ) );
$b = fresh_user( 'byran' );
ok( 'byran@reklamco.se' === $b->user_email && $hash_fore === $b->user_pass, 'kopplat konto: e-post och lösenord går inte att ändra' );
global $wpdb;
$wpdb->update( $wpdb->users, array( 'user_email' => 'privat@example.com' ), array( 'ID' => $b->ID ) );
clean_user_cache( $b->ID );
ok( rco_sso_is_staff_user( $b->ID ), 'kopplat konto räknas som personal även med privat e-post' );
wp_set_password( 'mitt-eget-lösenord', $b->ID );
$r = http( 'POST', '/wp-login.php', array( 'log' => 'byran', 'pwd' => 'mitt-eget-lösenord', 'testcookie' => 1 ), array( 'wordpress_test_cookie' => 'WP%20Cookie%20check' ) );
ok( 200 === $r['status'] && false !== strpos( $r['body'], 'Personal på Reklam' ), 'kopplat konto med privat e-post kan ändå inte logga in med lösenord', (string) $r['status'] );
$wpdb->update( $wpdb->users, array( 'user_email' => 'byran@reklamco.se' ), array( 'ID' => $b->ID ) );
clean_user_cache( $b->ID );

// Första kopplingen tar bort applikationslösenord som fanns innan.
$forsta = get_userdata( wp_insert_user( array( 'user_login' => 'forsta', 'user_email' => 'forsta@reklamco.se', 'user_pass' => wp_generate_password(), 'role' => 'subscriber' ) ) );
WP_Application_Passwords::create_new_application_password( $forsta->ID, array( 'name' => 'angriparens' ) );
$s = start();
list( $r ) = callback( $s, array( 'oid' => 'oid-forsta', 'preferred_username' => 'forsta@reklamco.se', 'roles' => array( 'wp.editor' ) ) );
ok( '' === error_code( $r ) && array() === WP_Application_Passwords::get_user_application_passwords( $forsta->ID ), 'första kopplingen tar bort befintliga applikationslösenord', error_code( $r ) );

// Indragen roll tar bort rollen från kontot.
$s = start();
list( $r ) = callback( $s, array( 'oid' => 'oid-forsta', 'preferred_username' => 'forsta@reklamco.se', 'roles' => array() ) );
ok( 'role' === error_code( $r ) && array() === array_values( fresh_user( 'forsta' )->roles ), 'indragen roll tas bort från kontot' );
wp_delete_user( $forsta->ID );

// Ingen lista har någonsin kunnat hämtas: inloggning nekas.
set_blocklist( null );
delete_option( RCO_SSO_Blocklist::LAST_OPTION );
$r = login_byran();
ok( 'unavailable' === error_code( $r ), 'utan någon hämtad spärrlista nekas inloggning', error_code( $r ) );
set_blocklist( array() );
$r = login_byran();
ok( '' === error_code( $r ), 'när listan går att hämta fungerar inloggningen igen', error_code( $r ) );

// === 15. Uppdateraren (låtsas-GitHub på port 8098) ===
// Kräver RCO_SSO_RELEASE_PUBLIC_KEY, RCO_SSO_UPDATE_API och RCO_SSO_UPDATE_DOWNLOAD_PREFIX
// i wp-config och den privata testnyckeln i UPDATE_KEY (se README).
add_filter( 'http_request_host_is_external', '__return_true' ); // download_url nekar annars 127.0.0.1
add_filter( 'http_allowed_safe_ports', static function ( $ports ) { return array_merge( $ports, array( 8098 ) ); } ); // och andra portar än 80, 443 och 8080
$dl       = getenv( 'BLOCKLIST_DIR' ) . '/dl';
@mkdir( $dl );
$secret   = base64_decode( trim( file_get_contents( getenv( 'UPDATE_KEY' ) ) ) );
$zip_data = 'PK-låtsaszip-' . random_bytes( 2000 );
file_put_contents( "$dl/rco-sso.zip", $zip_data );
file_put_contents( "$dl/rco-sso.zip.sig", base64_encode( sodium_crypto_sign_detached( RCO_SSO_Updater::manifest( '9.9.9', $zip_data ), $secret ) ) );
$prefix   = RCO_SSO_UPDATE_DOWNLOAD_PREFIX;
function set_release( $tag, $zip_url, $sig_url ) {
	file_put_contents( getenv( 'BLOCKLIST_DIR' ) . '/release.json', json_encode( array(
		'tag_name' => $tag, 'body' => 'Ändringar', 'html_url' => 'https://github.com/x',
		'assets'   => array( array( 'name' => 'rco-sso.zip', 'browser_download_url' => $zip_url ), array( 'name' => 'rco-sso.zip.sig', 'browser_download_url' => $sig_url ) ),
	) ) );
	delete_transient( RCO_SSO_Updater::TRANSIENT );
}
set_release( 'v9.9.9', $prefix . 'rco-sso.zip', $prefix . 'rco-sso.zip.sig' );
ok( RCO_SSO_Updater::has_public_key(), 'uppdateraren har en publik nyckel' );
// Servrar utan PHP-tillägget sodium: WordPress eget bibliotek i ren PHP ska ge samma svar.
require_once ABSPATH . WPINC . '/sodium_compat/autoload.php';
ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
$man     = RCO_SSO_Updater::manifest( '9.9.9', $zip_data );
$sig_raw = sodium_crypto_sign_detached( $man, $secret );
$pub_raw = base64_decode( RCO_SSO_RELEASE_PUBLIC_KEY );
ok( true === ParagonIE_Sodium_Compat::crypto_sign_verify_detached( $sig_raw, $man, $pub_raw ), 'WordPress eget sodium-bibliotek godtar signaturen' );
try {
	$fel = ParagonIE_Sodium_Compat::crypto_sign_verify_detached( $sig_raw, $man . 'x', $pub_raw );
} catch ( Throwable $e ) {
	$fel = false;
}
ok( false === $fel, 'och avvisar ändrat innehåll' );
ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = false;
ok( RCO_SSO_Updater::has_sodium(), 'signaturkontrollen finns att tillgå' );
$t = RCO_SSO_Updater::check_for_update( (object) array( 'checked' => array( 'x' => '1' ), 'response' => array() ) );
$u = $t->response[ RCO_SSO_Updater::basename() ] ?? null;
ok( $u && '9.9.9' === $u->new_version && $prefix . 'rco-sso.zip' === $u->package, 'nyare version visas som uppdatering' );
$info = RCO_SSO_Updater::plugin_info( false, 'plugin_information', (object) array( 'slug' => 'rco-sso' ) );
ok( is_object( $info ) && '9.9.9' === $info->version, 'versionsdetaljer visas' );

$fil = RCO_SSO_Updater::verified_download( false, $prefix . 'rco-sso.zip' );
ok( is_string( $fil ) && file_get_contents( $fil ) === $zip_data, 'signerad zip laddas ner och godtas', is_wp_error( $fil ) ? $fil->get_error_code() : '' );
if ( is_string( $fil ) ) { @unlink( $fil ); }

file_put_contents( "$dl/rco-sso.zip", $zip_data . 'manipulerad' );
$fil = RCO_SSO_Updater::verified_download( false, $prefix . 'rco-sso.zip' );
ok( is_wp_error( $fil ) && 'rco_sso_bad_signature' === $fil->get_error_code(), 'manipulerad zip installeras inte', is_wp_error( $fil ) ? $fil->get_error_code() : 'godtogs' );
file_put_contents( "$dl/rco-sso.zip", $zip_data );

$fil = RCO_SSO_Updater::verified_download( false, 'https://evil.example/rco-sso.zip' );
ok( is_wp_error( $fil ) && 'rco_sso_unknown_release' === $fil->get_error_code(), 'vårt filnamn från annan källa installeras inte' );
ok( false === RCO_SSO_Updater::verified_download( false, 'https://downloads.wordpress.org/plugin/annat.zip' ), 'andra pluginers paket påverkas inte' );
$fil = RCO_SSO_Updater::verified_download( false, 'https://evil.example/annat-namn.zip', null, array( 'plugin' => RCO_SSO_Updater::basename() ) );
ok( is_wp_error( $fil ), 'vårt plugin känns igen på namnet i uppgraderingen, även med annat filnamn' );
$annan = wp_tempnam( 'annan' );
file_put_contents( $annan, 'osignerat' );
$fil = RCO_SSO_Updater::verified_download( $annan, $prefix . 'rco-sso.zip', null, array( 'plugin' => RCO_SSO_Updater::basename() ) );
ok( is_string( $fil ) && $fil !== $annan && file_get_contents( $fil ) === $zip_data && ! file_exists( $annan ), 'en fil från ett annat filter används inte för vårt plugin' );
if ( is_string( $fil ) ) { @unlink( $fil ); }
// Nedgradering: en gammal signerad zip publicerad under ett nytt versionsnummer.
file_put_contents( "$dl/rco-sso.zip.sig", base64_encode( sodium_crypto_sign_detached( RCO_SSO_Updater::manifest( '0.1.0', $zip_data ), $secret ) ) );
delete_transient( RCO_SSO_Updater::TRANSIENT );
$fil = RCO_SSO_Updater::verified_download( false, $prefix . 'rco-sso.zip' );
ok( is_wp_error( $fil ) && 'rco_sso_bad_signature' === $fil->get_error_code(), 'gammal zip under nytt versionsnummer installeras inte' );
file_put_contents( "$dl/rco-sso.zip.sig", base64_encode( sodium_crypto_sign_detached( RCO_SSO_Updater::manifest( '9.9.9', $zip_data ), $secret ) ) );

set_release( 'v9.9.9', 'https://evil.example/rco-sso.zip', 'https://evil.example/rco-sso.zip.sig' );
$t = RCO_SSO_Updater::check_for_update( (object) array( 'checked' => array( 'x' => '1' ), 'response' => array() ) );
ok( ! isset( $t->response[ RCO_SSO_Updater::basename() ] ), 'release med nedladdning utanför repot visas inte' );

set_release( 'v' . RCO_SSO_VERSION, $prefix . 'rco-sso.zip', $prefix . 'rco-sso.zip.sig' );
$t = RCO_SSO_Updater::check_for_update( (object) array( 'checked' => array( 'x' => '1' ), 'response' => array() ) );
ok( ! isset( $t->response[ RCO_SSO_Updater::basename() ] ), 'samma version ger ingen uppdatering' );
delete_transient( RCO_SSO_Updater::TRANSIENT );

// === 16. Sidan efter inloggningen går aldrig till en främmande adress ===
foreach ( array( 'främmande värd' => 'https://evil.example/stjal', 'html i adressen' => $base . '/wp-admin/"><script>alert(1)</script>' ) as $vad => $mal ) {
	$r0 = http( 'GET', '/wp-login.php?action=rco_sso&redirect_to=' . rawurlencode( $mal ) );
	parse_str( (string) parse_url( $r0['location'], PHP_URL_QUERY ), $q0 );
	$s0 = array( 'r' => $r0, 'q' => $q0, 'cookies' => array_intersect_key( $r0['cookies'], array( '__Host-rco_sso_c' => 1, '__Host-rco_sso_to' => 1 ) ) );
	list( $r ) = callback( $s0, array( 'oid' => 'oid-vidare', 'preferred_username' => 'vidare@reklamco.se', 'roles' => array( 'wp.editor' ) ) );
	ok( 200 === $r['status'] && false === strpos( $r['body'], 'evil.example' ) && false === stripos( $r['body'], '<script' ) && 1 === preg_match( '/content="0;url=http:\/\/127\.0\.0\.1:8099\/wp-admin\/[^"<>]*">/', $r['body'] ), "vidare efter inloggning ($vad) stannar på sajten", substr( $r['body'], 0, 300 ) );
}

echo "\n" . ( $fail ? "$fail av $n tester misslyckades" : "Alla $n tester gick igenom" ) . "\n";
exit( $fail ? 1 : 0 );
