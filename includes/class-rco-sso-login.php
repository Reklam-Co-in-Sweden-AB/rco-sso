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

	// Prefixet __Host- gör att webbläsaren bara godtar cookien från sajten själv
	// (Secure, Path=/, ingen Domain). En annan subdomän på en delad domän som
	// hemsida.eu kan då inte plantera den.
	const COOKIE_NONCE    = '__Host-rco_sso_c';
	const COOKIE_REDIRECT = '__Host-rco_sso_to';
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

		// Starten ska komma från sajtens egen inloggningssida eller från en adress
		// som personen själv öppnat. En annan webbplats ska inte kunna logga in en
		// anställd här i bakgrunden. Även "same-site" nekas: på en delad domän
		// som hemsida.eu är grannens subdomän samma "site". Webbläsare som inte
		// skickar headern släpps igenom.
		$fetch_site = isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ? strtolower( (string) $_SERVER['HTTP_SEC_FETCH_SITE'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( '' !== $fetch_site && ! in_array( $fetch_site, array( 'same-origin', 'none' ), true ) ) {
			self::fail( 'manual', 'start från en annan webbplats (' . sanitize_key( $fetch_site ) . ')' );
		}

		if ( ! self::is_at_host_root() ) {
			self::fail( 'invalid', 'installationen ligger inte i värdnamnets rot' );
		}

		// Cookien bär hemligheten. state bär hashen av den, och nonce binder ihop
		// hashen med sajtens värdnamn. Microsoft signerar nonce, så en token kan
		// bara användas på den sajt där inloggningen startade, och reläet skickar
		// den bara vidare dit (det kontrollerar nonce mot state).
		$secret = RCO_SSO_Token::b64url_encode( random_bytes( 32 ) );
		$host   = self::own_host();
		$nonce  = self::nonce_for( $host, self::cookie_hash( $secret ) );
		$state  = $host . '.' . self::cookie_hash( $secret );

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

		// Bara POST. Ett GET-anrop hit får inte röra cookien, annars kan en
		// tredje part avbryta en pågående inloggning med en länk.
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- skyddet är nonce i token, bunden till cookien och sajten.
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) || empty( $_POST['id_token'] ) || empty( $_POST['state'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			self::fail( 'invalid', 'id_token eller state saknas' );
		}

		// Token är bunden till värdnamnet och cookien, och cookien delas av allt
		// på värdnamnet. Därför tar bara installationen i roten emot inloggningar,
		// se is_at_host_root().
		if ( ! self::is_at_host_root() ) {
			self::fail( 'invalid', 'installationen ligger inte i värdnamnets rot' );
		}

		// Nonce-cookien läses och tas bort direkt, oavsett hur det går.
		$secret = isset( $_COOKIE[ self::COOKIE_NONCE ] ) ? (string) wp_unslash( $_COOKIE[ self::COOKIE_NONCE ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$target = isset( $_COOKIE[ self::COOKIE_REDIRECT ] ) ? (string) wp_unslash( $_COOKIE[ self::COOKIE_REDIRECT ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		self::set_cookie( self::COOKIE_NONCE, '', time() - YEAR_IN_SECONDS );
		self::set_cookie( self::COOKIE_REDIRECT, '', time() - YEAR_IN_SECONDS );

		$token = (string) wp_unslash( $_POST['id_token'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$state = (string) wp_unslash( $_POST['state'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		// phpcs:enable

		if ( '' === $secret ) {
			// Vanligaste orsaken: inloggningen tog mer än tio minuter, eller cookies blockeras.
			self::fail( 'expired', 'nonce-cookien saknas' );
		}

		$host = self::own_host();
		if ( ! hash_equals( $host . '.' . self::cookie_hash( $secret ), $state ) ) {
			self::fail( 'invalid', 'state gäller en annan sajt eller en annan inloggning' );
		}

		// Inloggning kräver att spärrlistan har kunnat hämtas minst en gång.
		// Reläet ligger på samma server, så det kostar ingen tillgänglighet.
		if ( ! RCO_SSO_Blocklist::lists()['known'] ) {
			self::fail( 'unavailable', 'spärrlistan har aldrig kunnat hämtas' );
		}

		try {
			$claims = RCO_SSO_Token::verify(
				$token,
				strtolower( RCO_SSO_TENANT_ID ),
				strtolower( RCO_SSO_CLIENT_ID ),
				self::nonce_for( $host, self::cookie_hash( $secret ) ),
				array( __CLASS__, 'keys' )
			);
		} catch ( RCO_SSO_Token_Exception $e ) {
			self::fail( 'invalid', $e->getMessage() );
		}

		// Varje token får bara användas en gång. Spärren går på den signerade
		// delen: signaturens sista tecken kan ändras utan att den blir ogiltig.
		$used_key = 'rco_sso_used_' . hash( 'sha256', substr( $token, 0, (int) strrpos( $token, '.' ) ) );
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
			// Rollen är indragen i Entra: ta bort den från ett befintligt konto också.
			$utan_roll = RCO_SSO_Accounts::find_by_oid( (string) $claims['oid'] );
			if ( $utan_roll ) {
				RCO_SSO_Blocklist::revoke( $utan_roll->ID, 'ingen WordPress-roll i token' );
			}
			self::fail( 'role', 'ingen WordPress-roll i token' );
		}

		$user = RCO_SSO_Accounts::sign_in_user( $claims, $role );
		if ( is_wp_error( $user ) ) {
			self::fail( 'account', $user->get_error_code() . ': ' . $user->get_error_message() );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress egen hook, för loggplugin.

		self::continue_to( wp_validate_redirect( $target, admin_url() ) );
	}

	/**
	 * Gå vidare efter inloggningen med en sida i stället för en omdirigering.
	 *
	 * Inloggningen kommer hit som ett formulär från reläet, och reläets CSP
	 * tillåter bara att formuläret går till den här sajten. Chrome tillämpar
	 * den regeln på hela kedjan av omdirigeringar efter formuläret. Leder målet
	 * vidare till en annan värd, som när Beaver Builder AI kopplas och wp-admin
	 * skickar vidare till deras inloggningsserver, stoppas kedjan och personen
	 * blir stående på reläets sida. En sida som själv går vidare börjar en ny
	 * navigering, och då gäller reläets regel inte längre.
	 *
	 * @param string $url Adress på den egna sajten, redan kontrollerad med wp_validate_redirect().
	 */
	private static function continue_to( $url ) {
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Referrer-Policy: no-referrer' );
		header( 'X-Robots-Tag: noindex' );
		printf(
			'<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=%1$s"><title>%2$s</title></head><body><p><a href="%1$s">%3$s</a></p></body></html>',
			esc_url( $url ),
			esc_html__( 'Loggar in …', 'rco-sso' ),
			esc_html__( 'Fortsätt', 'rco-sso' )
		);
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
		// Hämtas högst var femte minut, även när cachen saknas: annars kan vem som
		// helst göra varje inloggningsförsök fem sekunder långsamt.
		if ( ! is_array( $cached ) && get_transient( 'rco_sso_jwks_refetch' ) ) {
			return array();
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
			'manual'  => __( 'Klicka på knappen nedan för att logga in med Reklam & Co.', 'rco-sso' ),
			'unavailable' => __( 'Inloggningen med Reklam & Co går inte att nå just nu. Försök igen om en stund, eller använd nödkontot.', 'rco-sso' ),
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
	 * Hashen av cookiens hemliga värde. Står i state; själva värdet lämnar aldrig sajten.
	 *
	 * @param string $secret Cookiens värde.
	 * @return string
	 */
	private static function cookie_hash( $secret ) {
		return RCO_SSO_Token::b64url_encode( hash( 'sha256', $secret, true ) );
	}

	/**
	 * Nonce som skickas till Microsoft: binder ihop sajtens värdnamn och
	 * inloggningens cookie. Samma beräkning görs i reläet (CoWeb).
	 *
	 * @param string $host        Sajtens värdnamn.
	 * @param string $cookie_hash Hashen av cookien.
	 * @return string
	 */
	public static function nonce_for( $host, $cookie_hash ) {
		return RCO_SSO_Token::b64url_encode( hash( 'sha256', 'rco-sso-v1|' . $host . '|' . $cookie_hash, true ) );
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
	 * Ligger WordPress i värdnamnets rot?
	 *
	 * Reläet skickar alltid token till https://<värdnamn>/wp-login.php, så det
	 * är bara där en inloggning kan sluta. En installation i en undermapp på
	 * samma värdnamn delar inloggningens cookie med den i roten (__Host- kräver
	 * Path=/). Utan den här kontrollen kunde den som styr den ena sajten läsa
	 * cookien och token och återanvända dem på den andra inom tio minuter.
	 * En sajt per värdnamn är därför ett krav.
	 *
	 * @return bool
	 */
	public static function is_at_host_root() {
		return '' === trim( (string) wp_parse_url( site_url(), PHP_URL_PATH ), '/' );
	}

	/**
	 * Sätt en cookie för inloggningsflödet.
	 *
	 * SameSite=None krävs: svaret kommer som en POST från sso.reklamco.se, och
	 * med Lax skickar webbläsaren inte cookien. Prefixet __Host- kräver Path=/.
	 *
	 * @param string $name    Namn.
	 * @param string $value   Värde.
	 * @param int    $expires Utgångstid.
	 */
	private static function set_cookie( $name, $value, $expires ) {
		setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => '/',
				'secure'   => true,
				'httponly' => true,
				'samesite' => 'None',
			)
		);
	}
}
