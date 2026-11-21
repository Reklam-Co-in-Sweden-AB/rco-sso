<?php
/**
 * Signerar en fil med den privata nyckeln och skriver <fil>.sig (base64).
 *
 *   php scripts/signera.php <fil> <fil med privata nyckeln>
 *
 * Kontrollerar signaturen mot den publika nyckeln i rco-sso.php innan den
 * skrivs, så att en release aldrig signeras med fel nyckel.
 */

if ( $argc !== 3 ) {
	fwrite( STDERR, "Användning: php scripts/signera.php <fil> <fil med privata nyckeln>\n" );
	exit( 1 );
}
list( , $file, $key_file ) = $argv;

$secret = base64_decode( trim( (string) file_get_contents( $key_file ) ), true );
if ( ! is_string( $secret ) || SODIUM_CRYPTO_SIGN_SECRETKEYBYTES !== strlen( $secret ) ) {
	fwrite( STDERR, "Den privata nyckeln har fel form.\n" );
	exit( 1 );
}

$header = (string) file_get_contents( __DIR__ . '/../rco-sso.php' );
if ( ! preg_match( "/'RCO_SSO_RELEASE_PUBLIC_KEY', '([A-Za-z0-9+\/=]+)'/", $header, $m ) ) {
	fwrite( STDERR, "Ingen publik nyckel i rco-sso.php. Fyll i RCO_SSO_RELEASE_PUBLIC_KEY först.\n" );
	exit( 1 );
}
if ( base64_encode( sodium_crypto_sign_publickey_from_secretkey( $secret ) ) !== $m[1] ) {
	fwrite( STDERR, "Den privata nyckeln hör inte ihop med den publika i rco-sso.php.\n" );
	exit( 1 );
}

$signature = base64_encode( sodium_crypto_sign_detached( (string) file_get_contents( $file ), $secret ) );
sodium_memzero( $secret );
file_put_contents( $file . '.sig', $signature . "\n" );
echo "Signerad: $file.sig\n";
