<?php
/**
 * Skapar byråns signeringsnyckel för rco-sso-releaser (Ed25519).
 *
 *   php scripts/ny-signeringsnyckel.php <fil för privata nyckeln>
 *
 * Den privata nyckeln skrivs till filen (läs- och skrivbar bara för dig) och
 * visas aldrig. Lägg den i byråns lösenordshanterare och radera filen. Den
 * publika nyckeln skrivs ut och förs in i RCO_SSO_RELEASE_PUBLIC_KEY.
 *
 * Den privata nyckeln ger ingen åtkomst till sajterna. Den gör det bara möjligt
 * att släppa en version som sajterna installerar, så den ska förvaras som en
 * nyckel till alla sajter ändå.
 */

if ( $argc !== 2 ) {
	fwrite( STDERR, "Användning: php scripts/ny-signeringsnyckel.php <fil för privata nyckeln>\n" );
	exit( 1 );
}
$path = $argv[1];
if ( file_exists( $path ) ) {
	fwrite( STDERR, "Filen finns redan. Skriver inte över en befintlig nyckel.\n" );
	exit( 1 );
}

$pair   = sodium_crypto_sign_keypair();
$secret = base64_encode( sodium_crypto_sign_secretkey( $pair ) );
$public = base64_encode( sodium_crypto_sign_publickey( $pair ) );

umask( 077 );
file_put_contents( $path, $secret . "\n" );
chmod( $path, 0600 );

echo "Privat nyckel sparad i $path (visas inte).\n";
echo "Publik nyckel: $public\n";
