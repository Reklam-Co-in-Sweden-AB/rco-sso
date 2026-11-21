<?php
/**
 * Signerar en release och skriver <fil>.sig (base64). Det som signeras är
 * manifestet "rco-sso|<version>|<sha256 av filen>", så att versionen ingår.
 *
 *   php scripts/signera.php <fil> <fil med privata nyckeln> <version>
 *
 * Kontrollerar signaturen mot den publika nyckeln i rco-sso.php innan den
 * skrivs, så att en release aldrig signeras med fel nyckel.
 */

if ( $argc !== 4 || ! preg_match( '/^\d+\.\d+\.\d+$/', $argv[3] ) ) {
	fwrite( STDERR, "Användning: php scripts/signera.php <fil> <fil med privata nyckeln> <version>\n" );
	exit( 1 );
}
list( , $file, $key_file, $version ) = $argv;

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

$manifest  = 'rco-sso|' . $version . '|' . hash( 'sha256', (string) file_get_contents( $file ) );
$signature = base64_encode( sodium_crypto_sign_detached( $manifest, $secret ) );
sodium_memzero( $secret );
file_put_contents( $file . '.sig', $signature . "\n" );
echo "Signerad: $file.sig\n";
