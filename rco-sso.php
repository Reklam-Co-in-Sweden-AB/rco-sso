<?php
/**
 * Plugin Name: Reklam & Co SSO
 * Description: Inloggning med Microsoft Entra ID för Reklam & Co-personal, utan nycklar på sajten. Microsoft signerar, sso.reklamco.se skickar vidare och pluginet kontrollerar.
 * Version: 0.5.1
 * Requires PHP: 7.4
 * Author: Reklam & Co
 * Update URI: https://github.com/Reklam-Co-in-Sweden-AB/rco-sso
 * Text Domain: rco-sso
 *
 * Installeras som vanligt plugin i wp-content/plugins/rco-sso/.
 * Ingen konfiguration behövs på sajten. Sajten läggs in i registret i CoWeb.
 * Nödbrytare i wp-config.php: define( 'RCO_SSO_DISABLE', true );
 *
 * Designspec och beslut: internt repo rco-sso-docs.
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/*
 * Appregistreringen "Reklam & Co – WordPress" i Entra. Inget av värdena är
 * hemligt. Sajten kontrollerar Microsofts signatur, så det finns ingen
 * client secret.
 *
 * TODO: Fyll i när appregistreringen är skapad. Så länge värdena är
 * nollor är pluginet avstängt och lösenordsinloggningen öppen.
 */
// Kan sättas i wp-config.php för test. Den som kan ändra wp-config.php äger
// redan sajten, så det öppnar inget nytt.
defined( 'RCO_SSO_TENANT_ID' ) || define( 'RCO_SSO_TENANT_ID', '00000000-0000-0000-0000-000000000000' );
defined( 'RCO_SSO_CLIENT_ID' ) || define( 'RCO_SSO_CLIENT_ID', '00000000-0000-0000-0000-000000000000' );

/**
 * Inloggningstjänsten i CoWeb som tar emot svaret från Microsoft.
 */
defined( 'RCO_SSO_RELAY_URL' ) || define( 'RCO_SSO_RELAY_URL', 'https://sso.reklamco.se/api/wp-sso/callback' );

/**
 * Spärrlistan i CoWeb. Bara hashar, och den kan bara neka.
 */
defined( 'RCO_SSO_BLOCKLIST_URL' ) || define( 'RCO_SSO_BLOCKLIST_URL', 'https://sso.reklamco.se/api/wp-sso/sparrade' );

/**
 * Domänen som räknas som personal. Konton med den här domänen måste logga in via SSO.
 */
const RCO_SSO_DOMAIN = 'reklamco.se';

/**
 * Hur länge en SSO-inloggning gäller (timmar). Kort tid gör att den som
 * stängs av i Entra snabbt tappar åtkomst även till öppna sessioner.
 */
const RCO_SSO_SESSION_HOURS = 10;

/**
 * Hur många dagar efter senaste SSO-inloggningen som kontots API-åtkomst
 * gäller (applikationslösenord, MCP-kopplingar och liknande).
 */
const RCO_SSO_API_MAX_DAYS = 30;

/**
 * Är SSO i gång? Kräver riktiga GUID och att nödbrytaren inte är på.
 *
 * @return bool
 */
function rco_sso_is_configured() {
	if ( defined( 'RCO_SSO_DISABLE' ) && RCO_SSO_DISABLE ) {
		return false;
	}

	$guid = '/^(?!0{8}-0{4}-0{4}-0{4}-0{12}$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

	return (bool) preg_match( $guid, RCO_SSO_TENANT_ID )
		&& (bool) preg_match( $guid, RCO_SSO_CLIENT_ID )
		&& 0 === strpos( RCO_SSO_RELAY_URL, 'https://' );
}

/**
 * Är e-postadressen en personaladress?
 *
 * @param string $email E-postadress.
 * @return bool
 */
function rco_sso_is_staff_email( $email ) {
	$suffix = '@' . RCO_SSO_DOMAIN;
	$email  = strtolower( trim( (string) $email ) );

	return strlen( $email ) > strlen( $suffix ) && substr( $email, -strlen( $suffix ) ) === $suffix;
}

/**
 * Är användaren ett personalkonto?
 *
 * @param WP_User|int $user Användare eller användar-id.
 * @return bool
 */
function rco_sso_is_staff_user( $user ) {
	if ( ! $user instanceof WP_User ) {
		$user = get_userdata( (int) $user );
	}

	return $user instanceof WP_User && rco_sso_is_staff_email( $user->user_email );
}

require_once __DIR__ . '/includes/class-rco-sso-token.php';
require_once __DIR__ . '/includes/class-rco-sso-accounts.php';
require_once __DIR__ . '/includes/class-rco-sso-blocklist.php';
require_once __DIR__ . '/includes/class-rco-sso-login.php';
require_once __DIR__ . '/includes/rules.php';

if ( rco_sso_is_configured() ) {
	RCO_SSO_Login::init();
}
