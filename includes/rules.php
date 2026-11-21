<?php
/**
 * Regler för personalkonton: ingen lösenordsinloggning, API-åtkomst kräver
 * en färsk SSO-inloggning, korta sessioner och varningar i adminpanelen.
 *
 * Flyttade från rco-sso v0.3.0 (avsnitt 4, 4b, 5 och 7). Logiken är oförändrad
 * utom att pluginet nu sköter inloggningen själv. Kommentaren om
 * wp_set_auth_cookie gäller RCO_SSO_Login::callback().
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/*
 * 4. Inget lösenord för personal
 *
 * Personalkonton loggar bara in via SSO. Gäller vanlig inloggning,
 * XML-RPC och lösenordsåterställning.
 * Pluginet loggar in SSO-användare med wp_set_auth_cookie(), inte via
 * authenticate-filtret, så SSO påverkas inte av spärren.
 */
add_filter( 'authenticate', 'rco_sso_block_password_login', 30 );
add_filter( 'allow_password_reset', 'rco_sso_block_password_reset', 10, 2 );

/**
 * Stoppa lösenordsinloggning för personalkonton.
 *
 * @param WP_User|WP_Error|null $user Resultat från tidigare autentisering.
 * @return WP_User|WP_Error|null
 */
function rco_sso_block_password_login( $user ) {
	if ( ! rco_sso_is_configured() ) {
		return $user;
	}

	if ( $user instanceof WP_User && rco_sso_is_staff_user( $user ) ) {
		return new WP_Error(
			'rco_sso_required',
			esc_html__( 'Personal på Reklam & Co loggar in med knappen "Logga in med Reklam & Co".', 'rco-sso' )
		);
	}

	return $user;
}

/**
 * Stoppa lösenordsåterställning för personalkonton.
 *
 * @param bool $allow   Tillåts återställning.
 * @param int  $user_id Användar-id.
 * @return bool
 */
function rco_sso_block_password_reset( $allow, $user_id ) {
	if ( rco_sso_is_configured() && rco_sso_is_staff_user( $user_id ) ) {
		return false;
	}

	return $allow;
}

/*
 * 4b. API-åtkomst kräver en färsk SSO-inloggning
 *
 * Applikationslösenord och MCP-kopplingar är långlivade nycklar som ligger
 * på sajten och fortsätter fungera även om personen stängs av i Entra.
 * Därför gäller de bara om kontot har loggat in via SSO de senaste
 * RCO_SSO_API_MAX_DAYS dagarna.
 *
 * Regeln gäller bara konton som har kopplats till SSO. Byråkontot och
 * kundens konton påverkas inte, så befintliga integrationer fortsätter fungera.
 *
 * Inloggade webbläsarsessioner berörs inte: de är högst
 * RCO_SSO_SESSION_HOURS timmar gamla, eller skapade via WP Toolkit (nödvägen).
 */
add_action( 'wp_authenticate_application_password_errors', 'rco_sso_check_application_password', 10, 2 );
add_filter( 'rest_authentication_errors', 'rco_sso_rest_paused_error', 101 );
add_filter( 'determine_current_user', 'rco_sso_check_api_user', 9999 );

/**
 * Har kontot kopplats till SSO men saknar en färsk SSO-inloggning?
 *
 * @param int $user_id Användar-id.
 * @return bool
 */
function rco_sso_api_access_expired( $user_id ) {
	if ( ! rco_sso_is_configured() ) {
		return false;
	}

	$linked = (int) get_user_meta( $user_id, 'rco_sso_linked', true );
	if ( ! $linked ) {
		return false;
	}

	$last_login = max( $linked, (int) get_user_meta( $user_id, 'rco_sso_last_login', true ) );

	return time() - $last_login > RCO_SSO_API_MAX_DAYS * DAY_IN_SECONDS;
}

/**
 * Neka applikationslösenord med ett tydligt felmeddelande.
 *
 * @param WP_Error $error Felobjekt som WordPress kontrollerar efteråt.
 * @param WP_User  $user  Användaren som applikationslösenordet tillhör.
 */
function rco_sso_check_application_password( $error, $user ) {
	if ( $error instanceof WP_Error && $user instanceof WP_User && rco_sso_api_access_expired( $user->ID ) ) {
		$error->add(
			'rco_sso_login_required',
			sprintf(
				/* translators: %d: antal dagar. */
				__( 'Kopplingen är pausad eftersom kontot inte har loggat in via Microsoft på %d dagar. Logga in på sajten och försök igen.', 'rco-sso' ),
				RCO_SSO_API_MAX_DAYS
			)
		);
	}
}

/**
 * Visa meddelandet om pausad koppling i REST-svaret.
 *
 * WordPress kontrollerar fel från applikationslösenord på prioritet 90, men
 * prövar lösenordet i REST-läge först när rest_cookie_check_errors (100)
 * hämtar användaren. Felet ovan kommer därför för sent, och användaren får
 * bara "You are not currently logged in". Uppmätt i WordPress 7.1.5 i lokal
 * test 2026-11-20. Gäller bara vårt eget fel.
 *
 * @param WP_Error|true|null $result Tidigare resultat.
 * @return WP_Error|true|null
 */
function rco_sso_rest_paused_error( $result ) {
	global $wp_rest_application_password_status;

	// rest_cookie_check_errors lämnar true när ingen cookie används, så villkoret
	// är "inget fel än", inte "tomt".
	if ( ! is_wp_error( $result ) && is_wp_error( $wp_rest_application_password_status ) && $wp_rest_application_password_status->get_error_message( 'rco_sso_login_required' ) ) {
		return new WP_Error(
			'rco_sso_login_required',
			$wp_rest_application_password_status->get_error_message( 'rco_sso_login_required' ),
			array( 'status' => 401 )
		);
	}

	return $result;
}

/**
 * Neka all annan inloggning utan webbläsarsession (t.ex. API-nycklar och
 * MCP-kopplingar) för konton utan färsk SSO-inloggning.
 *
 * @param int|false $user_id Användaren som WordPress har identifierat.
 * @return int|false
 */
function rco_sso_check_api_user( $user_id ) {
	if ( ! $user_id || ! rco_sso_api_access_expired( (int) $user_id ) ) {
		return $user_id;
	}

	// En giltig webbläsarsession för samma konto släpps igenom.
	if ( (int) wp_validate_auth_cookie( '', 'logged_in' ) === (int) $user_id || (int) wp_validate_auth_cookie() === (int) $user_id ) {
		return $user_id;
	}

	return false;
}

/*
 * 4c. Spärr före varje REST-anrop
 *
 * Beaver Builder AI:s molnkoppling (OAuth via connect.wpbeaverbuilder.com)
 * sätter användaren på tre sätt, och två av dem går förbi determine_current_user
 * och därmed rco_sso_check_api_user: resolve_token_user_early i rest_api_init
 * (prioritet 0) och ett skyddsnät i rest_authentication_errors (prioritet 99),
 * som slår till just när vår regel har nekat. Kontrollerat i BB AI 1.0.3.
 *
 * rest_pre_dispatch körs före varje REST-anrop, oavsett hur användaren sattes.
 * Här gäller två regler för anrop utan webbläsarsession:
 * 1. En token från Beaver Builder godtas bara för konton som är kopplade till
 *    SSO. Beaver Builders server kan signera en token för vilket konto som
 *    helst. Om den kapas ska den bara nå personalens konton, aldrig kundens
 *    eller byråkontot.
 * 2. 30-dagarsregeln, samma som i 4b.
 */
add_filter( 'rest_pre_dispatch', 'rco_sso_gate_rest_request', 1 );

/**
 * Är anropet autentiserat med en token från Beaver Builder AI?
 *
 * Läser utfärdaren ur token utan att kontrollera signaturen. Det räcker här:
 * svaret används bara för att neka, och en förfalskad token släpps ändå inte
 * in av Beaver Builder.
 *
 * @return bool
 */
function rco_sso_is_beaver_builder_token() {
	$header = '';
	foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
		if ( ! empty( $_SERVER[ $key ] ) ) {
			$header = (string) wp_unslash( $_SERVER[ $key ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			break;
		}
	}
	if ( 0 !== stripos( $header, 'Bearer ' ) ) {
		return false;
	}

	$parts   = explode( '.', trim( substr( $header, 7 ) ) );
	$payload = 3 === count( $parts ) ? json_decode( RCO_SSO_Token::b64url_decode( $parts[1] ), true ) : null;
	$host    = is_array( $payload ) && isset( $payload['iss'] ) && is_string( $payload['iss'] ) ? (string) wp_parse_url( $payload['iss'], PHP_URL_HOST ) : '';

	return 'wpbeaverbuilder.com' === $host || '.wpbeaverbuilder.com' === substr( $host, -20 );
}

/**
 * Neka REST-anrop som inte uppfyller reglerna ovan.
 *
 * @param mixed $result Tidigare resultat (null om inget annat svarat).
 * @return mixed
 */
function rco_sso_gate_rest_request( $result ) {
	if ( null !== $result || ! rco_sso_is_configured() ) {
		return $result;
	}

	$user_id = get_current_user_id();
	if ( ! $user_id ) {
		return $result;
	}

	// En inloggad webbläsarsession för samma konto berörs inte.
	if ( (int) wp_validate_auth_cookie( '', 'logged_in' ) === $user_id ) {
		return $result;
	}

	if ( rco_sso_is_beaver_builder_token() && ! get_user_meta( $user_id, 'rco_sso_oid', true ) ) {
		return new WP_Error(
			'rco_sso_personal_account_required',
			__( 'Beaver Builder AI kan bara kopplas till ett personligt konto som loggar in med "Logga in med Reklam & Co". Koppla om med ditt eget konto.', 'rco-sso' ),
			array( 'status' => 403 )
		);
	}

	if ( RCO_SSO_Blocklist::is_user_blocked( $user_id ) ) {
		RCO_SSO_Blocklist::revoke( $user_id );
		return new WP_Error(
			'rco_sso_blocked',
			__( 'Kontot är spärrat för Reklam & Co:s WordPress-sajter.', 'rco-sso' ),
			array( 'status' => 403 )
		);
	}

	if ( rco_sso_api_access_expired( $user_id ) ) {
		return new WP_Error(
			'rco_sso_login_required',
			sprintf(
				/* translators: %d: antal dagar. */
				__( 'Kopplingen är pausad eftersom kontot inte har loggat in via Microsoft på %d dagar. Logga in på sajten och försök igen.', 'rco-sso' ),
				RCO_SSO_API_MAX_DAYS
			),
			array( 'status' => 401 )
		);
	}

	return $result;
}

/*
 * 4c2. Spärrlistan för inloggade webbläsarsessioner
 *
 * En spärrad person som redan är inloggad loggas ut vid nästa sidvisning.
 * Kontrollen gäller bara SSO-kopplade konton, och listan är cachad i fem
 * minuter, så den kostar ingenting för andra besökare.
 */
add_action( 'init', 'rco_sso_logout_blocked_user', 1 );

/**
 * Logga ut och ta bort åtkomsten för en spärrad, inloggad person.
 */
function rco_sso_logout_blocked_user() {
	if ( ! rco_sso_is_configured() || ! is_user_logged_in() ) {
		return;
	}
	$user_id = get_current_user_id();
	if ( ! get_user_meta( $user_id, 'rco_sso_oid', true ) || ! RCO_SSO_Blocklist::is_user_blocked( $user_id ) ) {
		return;
	}
	RCO_SSO_Blocklist::revoke( $user_id );
	wp_clear_auth_cookie();
	wp_set_current_user( 0 );
}

/*
 * 4d. Inga applikationslösenord för personliga konton på driftade sajter
 *
 * Personalen kopplar MCP via Beaver Builder AI:s molnkoppling, som bygger på
 * inloggning och inte på ett lösenord som personen bär med sig. Den manuella
 * kopplingen med applikationslösenord behövs bara på utvecklingssajter och
 * lokalt. Tillåts därför bara när WP_ENVIRONMENT_TYPE är local, eller när
 * sajten är markerad som utvecklingssajt i CoWebs register. Domänen avgör
 * inte (hemsida.eu delas av alla Oderlands kunder), och WP_ENVIRONMENT_TYPE
 * development/staging räcker inte eftersom konstanten följer med till
 * produktion. Vid lansering byter sajten domän och stängs då automatiskt.
 * Gäller både nya och befintliga lösenord.
 */
add_filter( 'wp_is_application_passwords_available_for_user', 'rco_sso_staff_app_passwords', 10, 2 );

/**
 * Får kontot använda applikationslösenord?
 *
 * @param bool        $available Tidigare svar.
 * @param WP_User     $user      Kontot.
 * @param string|null $env       Miljö (för test). Standard: wp_get_environment_type().
 * @return bool
 */
function rco_sso_staff_app_passwords( $available, $user, $env = null ) {
	// Bara personliga konton som är kopplade till SSO. Byråkontot och kundens
	// konton påverkas inte, samma avgränsning som 30-dagarsregeln.
	if ( ! $available || ! rco_sso_is_configured() || ! $user instanceof WP_User || ! get_user_meta( $user->ID, 'rco_sso_oid', true ) ) {
		return $available;
	}

	$env = null === $env ? wp_get_environment_type() : $env;
	if ( 'local' === $env ) {
		return true;
	}

	return RCO_SSO_Blocklist::is_dev_host( RCO_SSO_Login::own_host() );
}

/*
 * 5. Kortare sessioner för personal
 */
add_filter( 'auth_cookie_expiration', 'rco_sso_session_length', 10, 2 );

/**
 * Begränsa sessionslängden för personalkonton.
 *
 * @param int $length  Sessionslängd i sekunder.
 * @param int $user_id Användar-id.
 * @return int
 */
function rco_sso_session_length( $length, $user_id ) {
	if ( rco_sso_is_configured() && rco_sso_is_staff_user( $user_id ) ) {
		return min( (int) $length, RCO_SSO_SESSION_HOURS * HOUR_IN_SECONDS );
	}

	return $length;
}


/*
 * 7. Varningar i adminpanelen
 */
add_action( 'admin_notices', 'rco_sso_admin_notices' );

/**
 * Varna personalen om SSO inte är i gång. Kundens användare ser inget.
 */
function rco_sso_admin_notices() {
	if ( ! current_user_can( 'manage_options' ) || ! rco_sso_is_staff_user( get_current_user_id() ) ) {
		return;
	}

	if ( defined( 'RCO_SSO_DISABLE' ) && RCO_SSO_DISABLE ) {
		$message = __( 'Reklam & Co SSO är avstängt med RCO_SSO_DISABLE i wp-config.php. Lösenordsinloggning är öppen för personal.', 'rco-sso' );
	} elseif ( ! rco_sso_is_configured() ) {
		$message = __( 'Reklam & Co SSO saknar tenant-id, client-id eller adressen till inloggningstjänsten. Lösenordsinloggning är fortfarande öppen för personal.', 'rco-sso' );
	} else {
		return;
	}

	printf( '<div class="notice notice-warning"><p>%s</p></div>', esc_html( $message ) );
}
