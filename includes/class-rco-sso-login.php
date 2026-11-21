<?php
/**
 * Inloggningen: knappen, starten mot Microsoft och mottagandet av token.
 *
 * Flöde: wp-login.php?action=rco_sso → Microsoft → CoWeb (sso.reklamco.se)
 * → wp-login.php?action=rco_sso_callback. Designspec: internt repo rco-sso-docs.
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Inloggning med Microsoft via CoWeb.
 */
class RCO_SSO_Login {

	const COOKIE_NONCE    = 'rco_sso_c';
	const COOKIE_REDIRECT = 'rco_sso_to';
	const COOKIE_LIFETIME = 600;

	/**
	 * Koppla in hookarna.
	 */
	public static function init() {
		add_action( 'login_form', array( __CLASS__, 'render_button' ) );
		add_action( 'login_form_rco_sso', array( __CLASS__, 'start' ) );
		add_action( 'login_form_rco_sso_callback', array( __CLASS__, 'callback' ) );
		add_filter( 'login_message', array( __CLASS__, 'error_message' ) );
	}

	/**
	 * Knappen på inloggningssidan.
	 */
	public static function render_button() {
		$args = array( 'action' => 'rco_sso' );
		if ( ! empty( $_REQUEST['redirect_to'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$args['redirect_to'] = rawurlencode( wp_unslash( $_REQUEST['redirect_to'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		printf(
			'<p class="rco-sso-button" style="margin:0 0 16px"><a class="button button-large" style="display:block;text-align:center" href="%s">%s</a></p>',
			esc_url( add_query_arg( $args, wp_login_url() ) ),
			esc_html__( 'Logga in med Reklam & Co', 'rco-sso' )
		);
	}

	/**
	 * Start: sätt nonce-cookien och skicka personen till Microsoft.
	 */
	public static function start() {
		// Bara GET: en POST hit från en annan sajt ska inte kunna starta en inloggning.
		if ( 'GET' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			self::fail( 'invalid' );
		}

		$secret = RCO_SSO_Token::b64url_encode( random_bytes( 32 ) );
		$nonce  = self::nonce_for( $secret );
		$state  = self::own_host() . '.' . RCO_SSO_Token::b64url_encode( random_bytes( 16 ) );

		self::set_cookie( self::COOKIE_NONCE, $secret, time() + self::COOKIE_LIFETIME );

		$redirect = isset( $_GET['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_GET['redirect_to'] ), admin_url() ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		self::set_cookie( self::COOKIE_REDIRECT, $redirect, time() + self::COOKIE_LIFETIME );

		$url = add_query_arg(
			array(
				'client_id'     => RCO_SSO_CLIENT_ID,
				'response_type' => 'id_token',
				'response_mode' => 'form_post',
				'redirect_uri'  => rawurlencode( RCO_SSO_RELAY_URL ),
				'scope'         => rawurlencode( 'openid profile email' ),
				'nonce'         => $nonce,
				'state'         => $state,
			),
			'https://login.microsoftonline.com/' . RCO_SSO_TENANT_ID . '/oauth2/v2.0/authorize'
		);

		nocache_headers();
		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- Microsofts adress.
		exit;
	}

	/**
	 * Mottagandet: kontrollera allt och logga in.
	 */
	public static function callback() {
		nocache_headers();

		// Nonce-cookien läses och tas bort direkt, oavsett hur det går.
		$secret = isset( $_COOKIE[ self::COOKIE_NONCE ] ) ? (string) wp_unslash( $_COOKIE[ self::COOKIE_NONCE ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$target = isset( $_COOKIE[ self::COOKIE_REDIRECT ] ) ? (string) wp_unslash( $_COOKIE[ self::COOKIE_REDIRECT ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		self::set_cookie( self::COOKIE_NONCE, '', time() - YEAR_IN_SECONDS );
		self::set_cookie( self::COOKIE_REDIRECT, '', time() - YEAR_IN_SECONDS );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- skyddet är nonce i token, bunden till cookien.
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) || empty( $_POST['id_token'] ) || empty( $_POST['state'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			self::fail( 'invalid', 'id_token eller state saknas' );
		}
		$token = (string) wp_unslash( $_POST['id_token'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$state = (string) wp_unslash( $_POST['state'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		// phpcs:enable

		if ( '' === $secret ) {
			// Vanligaste orsaken: inloggningen tog mer än tio minuter, eller cookies blockeras.
			self::fail( 'expired', 'nonce-cookien saknas' );
		}

		$dot = strrpos( $state, '.' );
		if ( false === $dot || substr( $state, 0, $dot ) !== self::own_host() ) {
			self::fail( 'invalid', 'state gäller en annan sajt' );
		}

		try {
			$claims = RCO_SSO_Token::verify(
				$token,
				strtolower( RCO_SSO_TENANT_ID ),
				strtolower( RCO_SSO_CLIENT_ID ),
				self::nonce_for( $secret ),
				array( __CLASS__, 'keys' )
			);
		} catch ( RCO_SSO_Token_Exception $e ) {
			self::fail( 'invalid', $e->getMessage() );
		}

		// Varje token får bara användas en gång.
		$used_key = 'rco_sso_used_' . hash( 'sha256', $token );
		if ( get_transient( $used_key ) ) {
			self::fail( 'invalid', 'token redan använd' );
		}
		set_transient( $used_key, 1, max( 60, (int) $claims['exp'] - time() + RCO_SSO_Token::CLOCK_SKEW ) );

		if ( ! rco_sso_is_staff_email( RCO_SSO_Accounts::email_from_claims( $claims ) ) ) {
			self::fail( 'invalid', 'inte en personaladress' );
		}

		// Spärrad person: ta bort åtkomsten från ett befintligt konto och neka.
		if ( RCO_SSO_Blocklist::is_blocked( (string) $claims['oid'], RCO_SSO_Accounts::email_from_claims( $claims ) ) ) {
			$blocked = RCO_SSO_Accounts::find_by_oid( (string) $claims['oid'] );
			if ( $blocked ) {
				RCO_SSO_Blocklist::revoke( $blocked->ID );
			}
			self::fail( 'blocked', 'personen finns på spärrlistan' );
		}

		$role = RCO_SSO_Accounts::role_from_claims( $claims );
		if ( null === $role ) {
			self::fail( 'role', 'ingen WordPress-roll i token' );
		}

		$user = RCO_SSO_Accounts::sign_in_user( $claims, $role );
		if ( is_wp_error( $user ) ) {
			self::fail( 'account', $user->get_error_code() . ': ' . $user->get_error_message() );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress egen hook, för loggplugin.

		wp_safe_redirect( wp_validate_redirect( $target, admin_url() ) );
		exit;
	}

	/**
	 * Microsofts signeringsnycklar, cachade i ett dygn.
	 *
	 * @param bool $refresh Hämta om (högst var femte minut).
	 * @return array JWK:er.
	 */
	public static function keys( $refresh ) {
		$cached = get_transient( 'rco_sso_jwks' );
		if ( is_array( $cached ) && ( ! $refresh || get_transient( 'rco_sso_jwks_refetch' ) ) ) {
			return $cached;
		}

		set_transient( 'rco_sso_jwks_refetch', 1, 5 * MINUTE_IN_SECONDS );
		$response = wp_remote_get(
			'https://login.microsoftonline.com/' . RCO_SSO_TENANT_ID . '/discovery/v2.0/keys',
			array( 'timeout' => 5 )
		);
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) || empty( $body['keys'] ) || ! is_array( $body['keys'] ) ) {
			error_log( 'rco-sso: kunde inte hämta Microsofts nycklar' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return is_array( $cached ) ? $cached : array();
		}

		set_transient( 'rco_sso_jwks', $body['keys'], DAY_IN_SECONDS );
		return $body['keys'];
	}

	/**
	 * Visa felmeddelandet på inloggningssidan.
	 *
	 * @param string $message Befintligt meddelande.
	 * @return string
	 */
	public static function error_message( $message ) {
		$code     = isset( $_GET['rco_sso_error'] ) ? sanitize_key( wp_unslash( $_GET['rco_sso_error'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$messages = array(
			'expired' => __( 'Inloggningen tog för lång tid eller så blockerar webbläsaren cookies. Försök igen.', 'rco-sso' ),
			'invalid' => __( 'Inloggningen med Reklam & Co kunde inte kontrolleras. Försök igen.', 'rco-sso' ),
			'role'    => __( 'Ditt Microsoft-konto saknar en WordPress-roll. Be en administratör om åtkomst.', 'rco-sso' ),
			'account' => __( 'Kontot kunde inte kopplas. Kontakta en administratör.', 'rco-sso' ),
			'blocked' => __( 'Ditt konto är spärrat för Reklam & Co:s WordPress-sajter. Kontakta en administratör.', 'rco-sso' ),
		);
		if ( isset( $messages[ $code ] ) ) {
			$message .= '<div id="login_error" class="notice notice-error"><p>' . esc_html( $messages[ $code ] ) . '</p></div>';
		}
		return $message;
	}

	/**
	 * Avbryt: logga detaljen och visa ett generiskt fel.
	 *
	 * @param string $code   Felkod till inloggningssidan.
	 * @param string $detail Detalj till error_log.
	 */
	private static function fail( $code, $detail = '' ) {
		if ( '' !== $detail ) {
			error_log( 'rco-sso: inloggning nekad: ' . $detail ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
		wp_safe_redirect( add_query_arg( 'rco_sso_error', $code, wp_login_url() ) );
		exit;
	}

	/**
	 * Nonce som skickas till Microsoft: hashen av cookiens hemliga värde.
	 *
	 * @param string $secret Cookiens värde.
	 * @return string
	 */
	private static function nonce_for( $secret ) {
		return RCO_SSO_Token::b64url_encode( hash( 'sha256', $secret, true ) );
	}

	/**
	 * Sajtens eget värdnamn, gemener.
	 *
	 * @return string
	 */
	public static function own_host() {
		return strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Sätt en cookie för inloggningsflödet.
	 *
	 * SameSite=None krävs: svaret kommer som en POST från sso.reklamco.se, och
	 * med Lax skickar webbläsaren inte cookien. Sökvägen begränsas till wp-login.php.
	 *
	 * @param string $name    Namn.
	 * @param string $value   Värde.
	 * @param int    $expires Utgångstid.
	 */
	private static function set_cookie( $name, $value, $expires ) {
		$path = (string) wp_parse_url( wp_login_url(), PHP_URL_PATH );
		setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => '' !== $path ? $path : '/',
				'secure'   => true,
				'httponly' => true,
				'samesite' => 'None',
			)
		);
	}
}
