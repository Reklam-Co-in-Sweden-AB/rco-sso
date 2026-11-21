<?php
/**
 * Test av tokenkontrollen. Körs utan WordPress: php tests/test-token.php
 *
 * @package RCO_SSO
 */

define( 'ABSPATH', __DIR__ );
require __DIR__ . '/../includes/class-rco-sso-token.php';

$failures = 0;
$count    = 0;

/**
 * Kontrollera att ett villkor stämmer.
 *
 * @param bool   $ok   Villkor.
 * @param string $name Testets namn.
 */
function check( $ok, $name ) {
	global $failures, $count;
	$count++;
	if ( ! $ok ) {
		$failures++;
		echo "FEL: $name\n";
	}
}

/**
 * Förväntar sig att verify kastar.
 *
 * @param callable $fn   Anrop.
 * @param string   $name Testets namn.
 */
function rejects( $fn, $name ) {
	try {
		$fn();
		check( false, $name . ' (godtogs)' );
	} catch ( RCO_SSO_Token_Exception $e ) {
		check( true, $name );
	}
}

const TENANT = '11111111-2222-3333-4444-555555555555';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const NONCE  = 'nonce-hash';

$key     = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
$other   = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
$details = openssl_pkey_get_details( $key );
$jwk     = array(
	'kty' => 'RSA',
	'kid' => 'k1',
	'n'   => RCO_SSO_Token::b64url_encode( $details['rsa']['n'] ),
	'e'   => RCO_SSO_Token::b64url_encode( $details['rsa']['e'] ),
);

$refreshes = 0;
$keys      = function ( $refresh ) use ( $jwk, &$refreshes ) {
	if ( $refresh ) {
		$refreshes++;
	}
	return array( $jwk );
};

/**
 * Skapa en signerad token.
 */
function make( $claims = array(), $header = array(), $signer = null ) {
	global $key;
	$now     = time();
	$payload = array_merge(
		array(
			'iss'   => 'https://login.microsoftonline.com/' . TENANT . '/v2.0',
			'aud'   => CLIENT,
			'tid'   => TENANT,
			'oid'   => 'oid-1',
			'email' => 'anna@reklamco.se',
			'roles' => array( 'wp.admin' ),
			'nonce' => NONCE,
			'iat'   => $now,
			'nbf'   => $now,
			'exp'   => $now + 3600,
		),
		$claims
	);
	$payload = array_filter( $payload, static function ( $v ) { return null !== $v; } );
	$h       = RCO_SSO_Token::b64url_encode( json_encode( array_merge( array( 'alg' => 'RS256', 'kid' => 'k1', 'typ' => 'JWT' ), $header ) ) );
	$p       = RCO_SSO_Token::b64url_encode( json_encode( $payload ) );
	openssl_sign( "$h.$p", $sig, $signer ? $signer : $key, OPENSSL_ALGO_SHA256 );
	return "$h.$p." . RCO_SSO_Token::b64url_encode( $sig );
}

$verify = function ( $jwt, $nonce = NONCE ) use ( $keys ) {
	return RCO_SSO_Token::verify( $jwt, TENANT, CLIENT, $nonce, $keys );
};

// Giltig token.
$claims = $verify( make() );
check( 'oid-1' === $claims['oid'] && array( 'wp.admin' ) === $claims['roles'], 'giltig token godtas' );
check( 'oid-1' === $verify( make( array( 'aud' => array( 'annan', CLIENT ) ) ) )['oid'], 'aud som lista godtas' );

// Signatur och format.
rejects( function () use ( $verify, $other ) { $verify( make( array(), array(), $other ) ); }, 'fel nyckel' );
rejects(
	function () use ( $verify ) {
		list( $h, , $s ) = explode( '.', make() );
		$p = RCO_SSO_Token::b64url_encode( json_encode( array( 'oid' => 'x' ) ) );
		$verify( "$h.$p.$s" );
	},
	'manipulerad payload'
);
rejects(
	function () use ( $verify ) {
		$h = RCO_SSO_Token::b64url_encode( json_encode( array( 'alg' => 'none', 'kid' => 'k1' ) ) );
		$p = explode( '.', make() )[1];
		$verify( "$h.$p." );
	},
	'alg none'
);
rejects( function () use ( $verify ) { $verify( make( array(), array( 'alg' => 'HS256' ) ) ); }, 'alg HS256' );
rejects( function () use ( $verify ) { $verify( 'inte.en.token' ); }, 'skräp' );
rejects( function () use ( $verify ) { $verify( make( array(), array( 'kid' => 'okand' ) ) ); }, 'okänd kid' );
check( $refreshes > 0, 'okänd kid hämtar nycklarna igen' );

// Claims.
rejects( function () use ( $verify ) { $verify( make( array( 'aud' => 'annan-app' ) ) ); }, 'fel aud' );
rejects( function () use ( $verify ) { $verify( make( array( 'iss' => 'https://login.microsoftonline.com/annan/v2.0' ) ) ); }, 'fel iss' );
rejects( function () use ( $verify ) { $verify( make( array( 'tid' => '99999999-2222-3333-4444-555555555555' ) ) ); }, 'fel tid' );
rejects( function () use ( $verify ) { $verify( make( array( 'exp' => time() - 600 ) ) ); }, 'utgången' );
rejects( function () use ( $verify ) { $verify( make( array( 'nbf' => time() + 3600 ) ) ); }, 'framtida nbf' );
rejects( function () use ( $verify ) { $verify( make( array( 'iat' => time() - 1200 ) ) ); }, 'för gammal iat' );
rejects( function () use ( $verify ) { $verify( make( array( 'exp' => null ) ) ); }, 'exp saknas' );
rejects( function () use ( $verify ) { $verify( make(), 'annan-nonce' ); }, 'fel nonce' );
rejects( function () use ( $verify ) { $verify( make(), '' ); }, 'tom förväntad nonce' );
rejects( function () use ( $verify ) { $verify( make( array( 'nonce' => null ) ) ); }, 'nonce saknas' );
rejects( function () use ( $verify ) { $verify( make( array( 'oid' => null ) ) ); }, 'oid saknas' );

echo $failures ? "\n$failures av $count tester misslyckades\n" : "Alla $count tester gick igenom\n";
exit( $failures ? 1 : 0 );
