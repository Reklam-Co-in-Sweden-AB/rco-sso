<?php
/**
 * Kontroll av ID-token från Microsoft Entra ID.
 *
 * Klassen är fristående från WordPress så att den kan testas utan en
 * WordPress-installation. Nycklarna hämtas via en callback som pluginet
 * skickar in (JWKS med cache i en transient).
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Fel vid kontroll av token. Meddelandet är bara till för error_log.
 */
class RCO_SSO_Token_Exception extends Exception {}

/**
 * Kontroll av signatur och claims i en ID-token.
 */
class RCO_SSO_Token {

	/**
	 * Tillåten avvikelse mellan klockor, sekunder.
	 */
	const CLOCK_SKEW = 120;

	/**
	 * Hur gammal en token får vara (iat), sekunder.
	 */
	const MAX_AGE = 600;

	/**
	 * Kontrollera en ID-token och returnera dess claims.
	 *
	 * @param string   $jwt            Token.
	 * @param string   $tenant_id      Vår tenant (GUID, gemener).
	 * @param string   $client_id      Appregistreringens client-id (GUID, gemener).
	 * @param string   $expected_nonce Nonce som sajten skickade till Microsoft.
	 * @param callable $get_keys       function( bool $refresh ): array med JWK:er (som arrayer).
	 * @param int|null $now            Tidpunkt att räkna från (för test).
	 * @return array Claims.
	 * @throws RCO_SSO_Token_Exception Vid minsta fel.
	 */
	public static function verify( $jwt, $tenant_id, $client_id, $expected_nonce, $get_keys, $now = null ) {
		$now = null === $now ? time() : (int) $now;

		if ( ! is_string( $jwt ) || strlen( $jwt ) > 16000 ) {
			throw new RCO_SSO_Token_Exception( 'token saknas eller är för lång' );
		}

		$parts = explode( '.', $jwt );
		if ( 3 !== count( $parts ) || '' === $parts[2] ) {
			throw new RCO_SSO_Token_Exception( 'fel format' );
		}

		$header  = json_decode( self::b64url_decode( $parts[0] ), true );
		$payload = json_decode( self::b64url_decode( $parts[1] ), true );
		$sig     = self::b64url_decode( $parts[2] );

		if ( ! is_array( $header ) || ! is_array( $payload ) || '' === $sig ) {
			throw new RCO_SSO_Token_Exception( 'går inte att avkoda' );
		}

		// Bara RS256. Allt annat, även "none", avvisas.
		if ( ! isset( $header['alg'] ) || 'RS256' !== $header['alg'] ) {
			throw new RCO_SSO_Token_Exception( 'fel alg' );
		}
		if ( empty( $header['kid'] ) || ! is_string( $header['kid'] ) ) {
			throw new RCO_SSO_Token_Exception( 'kid saknas' );
		}

		$jwk = self::find_key( call_user_func( $get_keys, false ), $header['kid'] );
		if ( null === $jwk ) {
			// Microsoft byter nycklar ibland. Hämta om en gång.
			$jwk = self::find_key( call_user_func( $get_keys, true ), $header['kid'] );
		}
		if ( null === $jwk ) {
			throw new RCO_SSO_Token_Exception( 'okänd kid' );
		}

		$pem = self::jwk_to_pem( $jwk );
		if ( 1 !== openssl_verify( $parts[0] . '.' . $parts[1], $sig, $pem, OPENSSL_ALGO_SHA256 ) ) {
			throw new RCO_SSO_Token_Exception( 'fel signatur' );
		}

		self::check_claims( $payload, $tenant_id, $client_id, $expected_nonce, $now );

		return $payload;
	}

	/**
	 * Kontrollera claims efter att signaturen godkänts.
	 *
	 * @param array  $c              Claims.
	 * @param string $tenant_id      Tenant.
	 * @param string $client_id      Client-id.
	 * @param string $expected_nonce Förväntad nonce.
	 * @param int    $now            Nu.
	 * @throws RCO_SSO_Token_Exception Vid fel.
	 */
	private static function check_claims( $c, $tenant_id, $client_id, $expected_nonce, $now ) {
		$issuer = 'https://login.microsoftonline.com/' . $tenant_id . '/v2.0';

		if ( ! isset( $c['iss'] ) || $issuer !== $c['iss'] ) {
			throw new RCO_SSO_Token_Exception( 'fel iss' );
		}
		if ( ! isset( $c['tid'] ) || ! is_string( $c['tid'] ) || strtolower( $c['tid'] ) !== $tenant_id ) {
			throw new RCO_SSO_Token_Exception( 'fel tid' );
		}

		$aud = isset( $c['aud'] ) ? (array) $c['aud'] : array();
		if ( ! in_array( $client_id, array_map( 'strtolower', array_map( 'strval', $aud ) ), true ) ) {
			throw new RCO_SSO_Token_Exception( 'fel aud' );
		}

		foreach ( array( 'exp', 'iat' ) as $claim ) {
			if ( ! isset( $c[ $claim ] ) || ! is_numeric( $c[ $claim ] ) ) {
				throw new RCO_SSO_Token_Exception( $claim . ' saknas' );
			}
		}
		if ( (int) $c['exp'] <= $now - self::CLOCK_SKEW ) {
			throw new RCO_SSO_Token_Exception( 'utgången' );
		}
		if ( isset( $c['nbf'] ) && (int) $c['nbf'] > $now + self::CLOCK_SKEW ) {
			throw new RCO_SSO_Token_Exception( 'inte giltig än' );
		}
		if ( (int) $c['iat'] < $now - self::MAX_AGE || (int) $c['iat'] > $now + self::CLOCK_SKEW ) {
			throw new RCO_SSO_Token_Exception( 'fel iat' );
		}

		if ( '' === (string) $expected_nonce || ! isset( $c['nonce'] ) || ! is_string( $c['nonce'] ) || ! hash_equals( (string) $expected_nonce, $c['nonce'] ) ) {
			throw new RCO_SSO_Token_Exception( 'fel nonce' );
		}

		if ( empty( $c['oid'] ) || ! is_string( $c['oid'] ) ) {
			throw new RCO_SSO_Token_Exception( 'oid saknas' );
		}
	}

	/**
	 * Hitta nyckeln med rätt kid.
	 *
	 * @param mixed  $keys JWK:er.
	 * @param string $kid  Nyckel-id.
	 * @return array|null
	 */
	private static function find_key( $keys, $kid ) {
		if ( ! is_array( $keys ) ) {
			return null;
		}
		foreach ( $keys as $key ) {
			if ( is_array( $key ) && isset( $key['kid'], $key['kty'], $key['n'], $key['e'] ) && $key['kid'] === $kid && 'RSA' === $key['kty'] ) {
				return $key;
			}
		}
		return null;
	}

	/**
	 * Base64url-avkodning. Returnerar tom sträng vid fel.
	 *
	 * @param string $value Kodat värde.
	 * @return string
	 */
	public static function b64url_decode( $value ) {
		if ( ! is_string( $value ) || ! preg_match( '/^[A-Za-z0-9_-]*$/', $value ) ) {
			return '';
		}
		$decoded = base64_decode( strtr( $value, '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( $value ) % 4 ) % 4 ), true );
		return false === $decoded ? '' : $decoded;
	}

	/**
	 * Base64url-kodning.
	 *
	 * @param string $value Rådata.
	 * @return string
	 */
	public static function b64url_encode( $value ) {
		return rtrim( strtr( base64_encode( $value ), '+/', '-_' ), '=' );
	}

	/**
	 * Gör om en RSA-JWK (n, e) till en publik nyckel i PEM-format.
	 *
	 * @param array $jwk JWK.
	 * @return string PEM.
	 * @throws RCO_SSO_Token_Exception Vid ogiltig nyckel.
	 */
	public static function jwk_to_pem( $jwk ) {
		$n = self::b64url_decode( (string) $jwk['n'] );
		$e = self::b64url_decode( (string) $jwk['e'] );
		if ( strlen( $n ) < 256 || '' === $e ) {
			throw new RCO_SSO_Token_Exception( 'ogiltig nyckel' );
		}

		$rsa_key = self::der( 0x30, self::der_int( $n ) . self::der_int( $e ) );
		// AlgorithmIdentifier för rsaEncryption (1.2.840.113549.1.1.1) med NULL.
		$algorithm = hex2bin( '300d06092a864886f70d0101010500' );
		$spki      = self::der( 0x30, $algorithm . self::der( 0x03, "\x00" . $rsa_key ) );

		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $spki ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}

	/**
	 * DER-kodat heltal (positivt).
	 *
	 * @param string $bytes Big-endian bytes.
	 * @return string
	 */
	private static function der_int( $bytes ) {
		$bytes = ltrim( $bytes, "\x00" );
		if ( '' === $bytes || ord( $bytes[0] ) > 0x7f ) {
			$bytes = "\x00" . $bytes;
		}
		return self::der( 0x02, $bytes );
	}

	/**
	 * DER-element med längd.
	 *
	 * @param int    $tag  Tagg.
	 * @param string $data Innehåll.
	 * @return string
	 */
	private static function der( $tag, $data ) {
		$len = strlen( $data );
		if ( $len < 0x80 ) {
			$length = chr( $len );
		} else {
			$bin    = ltrim( pack( 'N', $len ), "\x00" );
			$length = chr( 0x80 | strlen( $bin ) ) . $bin;
		}
		return chr( $tag ) . $length . $data;
	}
}
