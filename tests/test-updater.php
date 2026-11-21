<?php
/**
 * Test av signaturkontrollen i uppdateraren. Körs utan WordPress:
 * php tests/test-updater.php
 *
 * @package RCO_SSO
 */

define( 'ABSPATH', __DIR__ );
require __DIR__ . '/../includes/class-rco-sso-updater.php';

$fail = 0;
$n    = 0;
function check( $ok, $name ) {
	global $fail, $n;
	$n++;
	if ( ! $ok ) {
		$fail++;
		echo "FEL: $name\n";
	}
}

$pair   = sodium_crypto_sign_keypair();
$other  = sodium_crypto_sign_keypair();
$public = base64_encode( sodium_crypto_sign_publickey( $pair ) );
$zip    = random_bytes( 5000 );
$sig    = base64_encode( sodium_crypto_sign_detached( $zip, sodium_crypto_sign_secretkey( $pair ) ) );

check( RCO_SSO_Updater::signature_is_valid( $zip, $sig, $public ), 'giltig signatur godtas' );
check( RCO_SSO_Updater::signature_is_valid( $zip, $sig . "\n", $public ), 'radbrytning efter signaturen godtas' );
check( ! RCO_SSO_Updater::signature_is_valid( $zip . 'x', $sig, $public ), 'ändrad zip avvisas' );
check( ! RCO_SSO_Updater::signature_is_valid( $zip, base64_encode( sodium_crypto_sign_detached( $zip, sodium_crypto_sign_secretkey( $other ) ) ), $public ), 'signatur med annan nyckel avvisas' );
check( ! RCO_SSO_Updater::signature_is_valid( $zip, '', $public ), 'tom signatur avvisas' );
check( ! RCO_SSO_Updater::signature_is_valid( $zip, 'inte base64!!', $public ), 'trasig signatur avvisas' );
check( ! RCO_SSO_Updater::signature_is_valid( $zip, base64_encode( 'för kort' ), $public ), 'för kort signatur avvisas' );
check( ! RCO_SSO_Updater::signature_is_valid( $zip, $sig, '' ), 'tom publik nyckel avvisas' );
check( ! RCO_SSO_Updater::signature_is_valid( $zip, $sig, base64_encode( 'kort' ) ), 'felaktig publik nyckel avvisas' );

echo $fail ? "\n$fail av $n tester misslyckades\n" : "Alla $n tester gick igenom\n";
exit( $fail ? 1 : 0 );
