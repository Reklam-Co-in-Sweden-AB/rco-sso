<?php
/**
 * Spärrlistan: personer som inte längre ska komma åt WordPress-sajterna.
 *
 * Listan publiceras av CoWeb på sso.reklamco.se och innehåller bara hashar,
 * så den avslöjar inte vilka som är spärrade. Den kan bara neka, aldrig ge
 * åtkomst. En kapad CoWeb kan därför låsa ute personal men inte logga in.
 *
 * Format: {"version":1,"hashes":["<sha256 hex>", ...],"dev_hosts":["<sha256 hex>", ...]}
 * Hash: sha256( "oid:" + oid ) eller sha256( "upn:" + upn ), gemener.
 *
 * dev_hosts är utvecklingssajterna i CoWebs register, som sha256( "host:" + värdnamn ).
 * Bara där får personliga konton använda applikationslösenord. Domänen säger
 * ingenting (hemsida.eu är Oderlands och delas av alla deras kunder), och
 * WP_ENVIRONMENT_TYPE följer med till produktion och glöms lätt vid lansering.
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Hämtning, cache och kontroll av spärrlistan.
 */
class RCO_SSO_Blocklist {

	const TRANSIENT   = 'rco_sso_blocklist';
	const LAST_OPTION = 'rco_sso_blocklist_last';
	const TTL         = 300;
	const MAX_ENTRIES = 10000;

	/**
	 * Hashen för ett värde av ett visst slag.
	 *
	 * @param string $kind  "oid" eller "upn".
	 * @param string $value Värdet.
	 * @return string
	 */
	public static function hash( $kind, $value ) {
		return hash( 'sha256', $kind . ':' . strtolower( trim( (string) $value ) ) );
	}

	/**
	 * Är personen spärrad?
	 *
	 * @param string $oid Entra oid (kan vara tomt).
	 * @param string $upn Inloggningsnamn (kan vara tomt).
	 * @return bool
	 */
	public static function is_blocked( $oid, $upn ) {
		$hashes = self::lists()['blocked'];
		if ( ! $hashes ) {
			return false;
		}
		$candidates = array();
		if ( '' !== (string) $oid ) {
			$candidates[] = self::hash( 'oid', $oid );
		}
		if ( '' !== (string) $upn ) {
			$candidates[] = self::hash( 'upn', $upn );
		}
		foreach ( $candidates as $candidate ) {
			if ( isset( $hashes[ $candidate ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Är ett SSO-kopplat konto spärrat? Konton utan koppling är aldrig det.
	 *
	 * @param int $user_id Användar-id.
	 * @return bool
	 */
	public static function is_user_blocked( $user_id ) {
		$oid = (string) get_user_meta( $user_id, 'rco_sso_oid', true );
		if ( '' === $oid ) {
			return false;
		}
		$user = get_userdata( $user_id );
		return self::is_blocked( $oid, $user ? $user->user_email : '' );
	}

	/**
	 * Ta bort all åtkomst för kontot: roll, applikationslösenord och sessioner.
	 * Rollen kommer tillbaka vid nästa inloggning via Microsoft när spärren tagits bort.
	 *
	 * @param int $user_id Användar-id.
	 */
	public static function revoke( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		if ( $user->roles ) {
			$user->set_role( '' );
		}
		if ( class_exists( 'WP_Application_Passwords' ) ) {
			WP_Application_Passwords::delete_all_application_passwords( $user_id );
		}
		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		update_user_meta( $user_id, 'rco_sso_blocked', time() );
		error_log( 'rco-sso: konto ' . $user_id . ' spärrat enligt spärrlistan' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}

	/**
	 * Är sajten en utvecklingssajt enligt CoWebs register?
	 * Okänt (ingen lista har någonsin hämtats) räknas som nej.
	 *
	 * @param string $host Sajtens värdnamn.
	 * @return bool
	 */
	public static function is_dev_host( $host ) {
		return isset( self::lists()['dev'][ self::hash( 'host', $host ) ] );
	}

	/**
	 * Listorna som uppslagstabeller. Hämtas högst var femte minut.
	 * Kan de inte hämtas används de senast hämtade.
	 *
	 * @return array{blocked: array<string,bool>, dev: array<string,bool>}
	 */
	public static function lists() {
		$cached = get_transient( self::TRANSIENT );
		if ( is_array( $cached ) && isset( $cached['blocked'], $cached['dev'] ) ) {
			return $cached;
		}

		$fresh = self::fetch();
		if ( null !== $fresh ) {
			set_transient( self::TRANSIENT, $fresh, self::TTL );
			update_option( self::LAST_OPTION, $fresh, false );
			return $fresh;
		}

		// CoWeb svarar inte: använd senaste listan och försök igen om en minut.
		$last = get_option( self::LAST_OPTION );
		$last = is_array( $last ) && isset( $last['blocked'], $last['dev'] ) ? $last : array( 'blocked' => array(), 'dev' => array() );
		set_transient( self::TRANSIENT, $last, MINUTE_IN_SECONDS );
		return $last;
	}

	/**
	 * Hämta listan. Null om den inte gick att hämta eller hade fel form.
	 *
	 * @return array{blocked: array<string,bool>, dev: array<string,bool>}|null
	 */
	private static function fetch() {
		$url    = (string) RCO_SSO_BLOCKLIST_URL;
		$scheme = wp_parse_url( $url, PHP_URL_SCHEME );
		if ( 'https' !== $scheme && ! ( 'http' === $scheme && 'local' === wp_get_environment_type() ) ) {
			return null;
		}

		$response = wp_remote_get( $url, array( 'timeout' => 3, 'redirection' => 0 ) );
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			error_log( 'rco-sso: kunde inte hämta spärrlistan' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return null;
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || 1 !== ( $body['version'] ?? null ) || ! isset( $body['hashes'] ) || ! is_array( $body['hashes'] ) || count( $body['hashes'] ) > self::MAX_ENTRIES ) {
			error_log( 'rco-sso: spärrlistan har fel form' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return null;
		}

		$dev = isset( $body['dev_hosts'] ) && is_array( $body['dev_hosts'] ) && count( $body['dev_hosts'] ) <= self::MAX_ENTRIES ? $body['dev_hosts'] : array();

		return array(
			'blocked' => self::to_set( $body['hashes'] ),
			'dev'     => self::to_set( $dev ),
		);
	}

	/**
	 * Giltiga hashar som uppslagstabell.
	 *
	 * @param array $list Hashar.
	 * @return array<string,bool>
	 */
	private static function to_set( $list ) {
		$set = array();
		foreach ( $list as $hash ) {
			if ( is_string( $hash ) && preg_match( '/^[0-9a-f]{64}$/', $hash ) ) {
				$set[ $hash ] = true;
			}
		}
		return $set;
	}
}
