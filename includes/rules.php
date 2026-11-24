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
// Sist av alla, så att inget annat plugin kan släppa in kontot efter spärren.
add_filter( 'authenticate', 'rco_sso_block_password_login', PHP_INT_MAX, 3 );
add_filter( 'allow_password_reset', 'rco_sso_block_password_reset', 10, 2 );
add_filter( 'lostpassword_user_data', 'rco_sso_hide_staff_from_lostpassword', 10, 1 );

// 4c. Dölj personalkonton för uppräkning utifrån (author-arkiv, REST och sitemappar).
//     Personalens inloggningsnamn är adresser på @reklamco.se, och den publika
//     spärrlistan har osaltade hashar av dem. Kan en utomstående räkna upp
//     vilka anställda som finns på sajterna går det att lista ut vilka som är
//     spärrade. Kundens egna konton rörs inte.
add_action( 'template_redirect', 'rco_sso_block_staff_author_enum', 0 );
add_filter( 'rest_user_query', 'rco_sso_hide_staff_in_rest', 10, 2 );
add_filter( 'rest_prepare_user', 'rco_sso_block_single_staff_in_rest', 10, 3 );
add_filter( 'wp_sitemaps_users_query_args', 'rco_sso_hide_staff_in_sitemap' );
add_filter( 'wpseo_sitemap_exclude_author', 'rco_sso_hide_staff_in_yoast_sitemap' );

/**
 * Stoppa lösenordsinloggning för personalkonton.
 *
 * Rätt lösenord ger en hänvisning till knappen. Fel lösenord ger samma svar
 * som för ett konto som inte finns, så att inloggningsformuläret inte går
 * att använda för att ta reda på vilka anställda som har konto på sajten.
 *
 * @param WP_User|WP_Error|null $user     Resultat från tidigare autentisering.
 * @param string                $username Det inskrivna användarnamnet eller adressen.
 * @return WP_User|WP_Error|null
 */
function rco_sso_block_password_login( $user, $username = '' ) {
	if ( ! rco_sso_is_configured() ) {
		return $user;
	}

	if ( $user instanceof WP_User && rco_sso_is_staff_user( $user ) ) {
		return new WP_Error(
			'rco_sso_required',
			esc_html__( 'Personal på Reklam & Co loggar in med knappen "Logga in med Reklam & Co".', 'rco-sso' )
		);
	}

	if ( is_wp_error( $user ) && in_array( 'incorrect_password', $user->get_error_codes(), true ) ) {
		$username = (string) $username;
		$account  = get_user_by( 'login', $username );
		if ( ! $account && is_email( $username ) ) {
			$account = get_user_by( 'email', $username );
		}
		if ( $account && rco_sso_is_staff_user( $account ) ) {
			return rco_sso_unknown_account_error( $username );
		}
	}

	return $user;
}

/**
 * WordPress eget fel för ett konto som inte finns, med det inskrivna namnet.
 *
 * Felet hämtas från WordPress med ett låtsasnamn, så att texten och
 * översättningen alltid är exakt den som ett okänt konto ger.
 *
 * @param string $username Det inskrivna användarnamnet eller adressen.
 * @return WP_Error
 */
function rco_sso_unknown_account_error( $username ) {
	$fake  = 'rcosso' . strtolower( wp_generate_password( 20, false ) );
	$error = is_email( $username )
		? wp_authenticate_email_password( null, $fake . '@invalid.invalid', 'x' )
		: wp_authenticate_username_password( null, $fake, 'x' );

	$result = new WP_Error();
	if ( is_wp_error( $error ) ) {
		foreach ( $error->get_error_codes() as $code ) {
			foreach ( $error->get_error_messages( $code ) as $message ) {
				$result->add( $code, str_replace( $fake, esc_html( $username ), $message ) );
			}
		}
	}
	if ( ! $result->has_errors() ) {
		$result->add( 'invalid_username', esc_html__( 'Okänt användarnamn eller lösenord.', 'rco-sso' ) );
	}
	return $result;
}

/**
 * Glömt lösenord: ett personalkonto ser ut som ett konto som inte finns.
 *
 * Utan det här svarar WordPress "Lösenordsåterställning är inte tillåten för
 * denna användare", och det pekar ut just personalkontona.
 *
 * @param WP_User|false $user_data Kontot, eller false.
 * @return WP_User|false
 */
function rco_sso_hide_staff_from_lostpassword( $user_data ) {
	if ( rco_sso_is_configured() && $user_data instanceof WP_User && rco_sso_is_staff_user( $user_data ) ) {
		return false;
	}
	return $user_data;
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

/**
 * Visa 404 för ett personalkontos author-arkiv (/?author=ID och /author/slug/).
 *
 * Körs före redirect_canonical (prioritet 0), så att /?author=ID inte hinner
 * omdirigeras till /author/slug/ och avslöja inloggningsnamnet på vägen.
 * Kundens egna författararkiv påverkas inte.
 */
function rco_sso_block_staff_author_enum() {
	if ( ! rco_sso_is_configured() || ! is_author() ) {
		return;
	}
	$author = get_queried_object();
	if ( $author instanceof WP_User && rco_sso_is_staff_user( $author ) ) {
		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
	}
}

/**
 * Personalens id, för att utesluta dem ur publika REST-listor.
 *
 * @return int[]
 */
function rco_sso_staff_user_ids() {
	$oid = get_users(
		array(
			'fields'       => 'ID',
			'meta_key'     => 'rco_sso_oid', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
			'meta_compare' => 'EXISTS',
		)
	);
	$epost = get_users(
		array(
			'fields'        => 'ID',
			'search'        => '*@reklamco.se',
			'search_columns' => array( 'user_email', 'user_login' ),
		)
	);
	return array_values( array_unique( array_map( 'intval', array_merge( $oid, $epost ) ) ) );
}

/**
 * Uteslut personalkonton ur /wp-json/wp/v2/users för utloggade och för konton som inte
 * får redigera inlägg. Redaktörer, både personalens och kundens, behöver se
 * författarna i redigeraren.
 *
 * @param array           $args    Argument till WP_User_Query.
 * @param WP_REST_Request $request Begäran.
 * @return array
 */
function rco_sso_hide_staff_in_rest( $args, $request ) {
	if ( ! rco_sso_is_configured() || current_user_can( 'edit_posts' ) ) {
		return $args;
	}
	$staff = rco_sso_staff_user_ids();
	if ( $staff ) {
		$args['exclude'] = array_merge( isset( $args['exclude'] ) ? (array) $args['exclude'] : array(), $staff );
	}
	return $args;
}

/**
 * Neka direkt uppslag av ett personalkonto via /wp-json/wp/v2/users/ID.
 *
 * @param WP_REST_Response $response Svaret.
 * @param WP_User          $user     Kontot.
 * @param WP_REST_Request  $request  Begäran.
 * @return WP_REST_Response|WP_Error
 */
function rco_sso_block_single_staff_in_rest( $response, $user, $request ) {
	// Bara enskilda uppslag (/users/ID), inte listan: listan filtreras med rest_user_query.
	if ( ! rco_sso_is_configured() || current_user_can( 'edit_posts' ) ) {
		return $response;
	}
	$route = method_exists( $request, 'get_route' ) ? (string) $request->get_route() : '';
	if ( preg_match( '#/wp/v2/users/\d+$#', $route ) && rco_sso_is_staff_user( $user ) ) {
		return new WP_Error( 'rest_user_invalid_id', __( 'Ogiltigt användar-id.', 'rco-sso' ), array( 'status' => 404 ) );
	}
	return $response;
}

/**
 * Uteslut personalkonton ur WordPress egen sitemap över författare
 * (/wp-sitemap-users-1.xml). Den pekar på author-arkiven, där adressen är
 * inloggningsnamnet, och de arkiven ger ändå 404 för personal.
 *
 * @param array $args Argument till WP_User_Query.
 * @return array
 */
function rco_sso_hide_staff_in_sitemap( $args ) {
	if ( ! rco_sso_is_configured() ) {
		return $args;
	}
	$staff = rco_sso_staff_user_ids();
	if ( $staff ) {
		$args['exclude'] = array_merge( isset( $args['exclude'] ) ? (array) $args['exclude'] : array(), $staff );
	}
	return $args;
}

/**
 * Samma sak för Yoast SEO, som ersätter WordPress sitemap med sin egen
 * (/author-sitemap.xml).
 *
 * @param array $users Konton som Yoast tänker ta med.
 * @return array
 */
function rco_sso_hide_staff_in_yoast_sitemap( $users ) {
	if ( ! rco_sso_is_configured() || ! is_array( $users ) ) {
		return $users;
	}
	return array_values(
		array_filter(
			$users,
			static function ( $user ) {
				return ! rco_sso_is_staff_user( $user );
			}
		)
	);
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
 * Känns igen på fältet wp_user_id, som Beaver Builder kräver i varje token,
 * eller på utfärdaren. Bara utfärdarens domän räcker inte: BB AI godtar
 * även en äldre utfärdare på en annan domän (bb-mcp-connect.info-288.workers.dev).
 * Token läses utan att signaturen kontrolleras. Det räcker här: svaret används
 * bara för att neka, och en förfalskad token släpps ändå inte in av Beaver Builder.
 *
 * Headern och token läses på samma sätt som Beaver Builder gör (kontrollerat
 * i BB AI 1.1.0: sanitize_text_field på headern, och firebase/php-jwt som
 * avkodar base64 tillåtande, med utfyllnad, "+/" och skräptecken). Annars kan
 * den som har kapat Beaver Builders server koda sin token så att den godtas
 * där men inte känns igen här. En token i tre delar som ändå inte går att
 * tolka räknas som Beaver Builders, så att ett framtida glapp nekar i stället
 * för att släppa igenom.
 *
 * @return bool
 */
function rco_sso_is_beaver_builder_token() {
	// Samma källor, i samma ordning och med samma tvätt, som Beaver Builder AI.
	$header = '';
	foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
		$candidate = isset( $_SERVER[ $key ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) : '';
		if ( '' !== trim( $candidate ) ) {
			$header = $candidate;
			break;
		}
	}
	if ( '' === $header && function_exists( 'apache_request_headers' ) ) {
		foreach ( (array) apache_request_headers() as $name => $value ) {
			$candidate = 'authorization' === strtolower( (string) $name ) ? sanitize_text_field( (string) $value ) : '';
			if ( '' !== trim( $candidate ) ) {
				$header = $candidate;
				break;
			}
		}
	}
	if ( 0 !== stripos( $header, 'Bearer ' ) ) {
		return false;
	}

	$parts = explode( '.', trim( substr( $header, 7 ) ) );
	if ( 3 !== count( $parts ) ) {
		// Beaver Builder nekar allt som inte har tre delar.
		return false;
	}

	// Tillåtande avkodning, som JWT::urlsafeB64Decode i firebase/php-jwt.
	$body    = $parts[1] . str_repeat( '=', ( 4 - strlen( $parts[1] ) % 4 ) % 4 );
	$payload = json_decode( (string) base64_decode( strtr( $body, '-_', '+/' ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
	if ( ! is_array( $payload ) ) {
		return true;
	}
	if ( isset( $payload['wp_user_id'] ) ) {
		return true;
	}
	$host = isset( $payload['iss'] ) && is_string( $payload['iss'] ) ? (string) wp_parse_url( $payload['iss'], PHP_URL_HOST ) : '';

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
 * 4c3. E-post och lösenord är låsta på kopplade konton
 *
 * Annars kunde personal byta till en privat e-postadress, sätta ett eget
 * lösenord och få ett konto som överlever avstängningen i Entra. E-posten
 * uppdateras bara av pluginet självt, från Entra, vid inloggning.
 */
add_filter( 'wp_pre_insert_user_data', 'rco_sso_lock_linked_account', 10, 3 );
add_filter( 'show_password_fields', 'rco_sso_hide_password_fields', 10, 2 );
add_action( 'user_profile_update_errors', 'rco_sso_profile_errors', 10, 3 );

/**
 * Behåll e-post och lösenord på kopplade konton, hur ändringen än görs
 * (profilsidan, REST, WP-CLI eller ett annat plugin).
 *
 * @param array    $data    Raden som ska sparas.
 * @param bool     $update  Uppdatering eller nytt konto.
 * @param int|null $user_id Användar-id vid uppdatering.
 * @return array
 */
function rco_sso_lock_linked_account( $data, $update, $user_id = null ) {
	if ( ! $update || ! $user_id || RCO_SSO_Accounts::$syncing || ! get_user_meta( $user_id, 'rco_sso_oid', true ) ) {
		return $data;
	}
	$current = get_userdata( $user_id );
	if ( $current ) {
		$data['user_email'] = $current->user_email;
		$data['user_pass']  = $current->user_pass;
	}
	return $data;
}

/**
 * Dölj lösenordsfälten i profilen för kopplade konton.
 *
 * @param bool    $show Visa fälten.
 * @param WP_User $user Kontot som visas.
 * @return bool
 */
function rco_sso_hide_password_fields( $show, $user = null ) {
	return $user instanceof WP_User && get_user_meta( $user->ID, 'rco_sso_oid', true ) ? false : $show;
}

/**
 * Säg tydligt till i profilen i stället för att tyst behålla det gamla.
 *
 * @param WP_Error $errors Fel.
 * @param bool     $update Uppdatering.
 * @param object   $user   Det som ska sparas.
 */
function rco_sso_profile_errors( $errors, $update, $user ) {
	if ( ! $update || empty( $user->ID ) || ! get_user_meta( $user->ID, 'rco_sso_oid', true ) ) {
		return;
	}
	$current = get_userdata( $user->ID );
	if ( $current && isset( $user->user_email ) && strtolower( $user->user_email ) !== strtolower( $current->user_email ) ) {
		$errors->add( 'rco_sso_email_locked', __( 'E-postadressen styrs av Microsoft-kontot och kan inte ändras här.', 'rco-sso' ) );
	}
	if ( ! empty( $user->user_pass ) ) {
		$errors->add( 'rco_sso_password_locked', __( 'Kontot loggar in med Microsoft och har inget eget lösenord.', 'rco-sso' ) );
	}
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
