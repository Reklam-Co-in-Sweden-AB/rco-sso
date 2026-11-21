<?php
/**
 * Plugin Name: Simulator för Beaver Builder AI:s molnkoppling (bara för test)
 *
 * Gör samma sak som BB AI 1.0.3 (packages/mcp-oauth) när en Bearer-token
 * kommer in: sätter användaren direkt med wp_set_current_user på två ställen
 * som går förbi determine_current_user.
 *  - resolve_token_user_early: rest_api_init, prioritet 0
 *  - rest_bearer_auth_safety_net: rest_authentication_errors, prioritet 99
 *
 * Signaturen kontrolleras inte här: testet gäller vad rco-sso gör efteråt.
 * Läggs i wp-content/mu-plugins/ på testsajten, aldrig på en riktig sajt.
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Användar-id ur en Bearer-token från Beaver Builder, annars 0.
 *
 * @return int
 */
function rco_test_bb_user_from_bearer() {
	$header = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? (string) $_SERVER['HTTP_AUTHORIZATION'] : '';
	if ( 0 !== stripos( $header, 'Bearer ' ) ) {
		return 0;
	}
	$parts   = explode( '.', trim( substr( $header, 7 ) ) );
	$payload = 3 === count( $parts ) ? json_decode( base64_decode( strtr( $parts[1], '-_', '+/' ) ), true ) : null;
	if ( ! is_array( $payload ) || 'https://connect.wpbeaverbuilder.com' !== ( $payload['iss'] ?? '' ) ) {
		return 0;
	}
	$user = get_userdata( (int) ( $payload['wp_user_id'] ?? 0 ) );
	return $user && user_can( $user, 'unfiltered_html' ) ? $user->ID : 0;
}

add_action(
	'rest_api_init',
	static function () {
		if ( get_current_user_id() > 0 ) {
			return;
		}
		$id = rco_test_bb_user_from_bearer();
		if ( $id ) {
			wp_set_current_user( $id );
		}
	},
	0
);

add_filter(
	'rest_authentication_errors',
	static function ( $errors ) {
		if ( null !== $errors && false !== $errors ) {
			return $errors;
		}
		if ( get_current_user_id() > 0 ) {
			return $errors;
		}
		$id = rco_test_bb_user_from_bearer();
		if ( $id ) {
			wp_set_current_user( $id );
			return true;
		}
		return $errors;
	},
	99
);
