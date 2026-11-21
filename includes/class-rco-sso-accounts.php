<?php
/**
 * Konton för personal: hitta, koppla eller skapa utifrån verifierade claims.
 *
 * Konton kopplas på Entras oid (usermeta rco_sso_oid), inte på e-post.
 * En e-postadress kan byta ägare, oid kan det inte.
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Kontohantering.
 */
class RCO_SSO_Accounts {

	/**
	 * Approller i Entra och WordPress-rollen de ger, i prioritetsordning.
	 */
	const ROLE_MAP = array(
		'wp.admin'  => 'administrator',
		'wp.editor' => 'editor',
	);

	/**
	 * WordPress-roll utifrån claimet roles, eller null.
	 *
	 * @param array $claims Claims.
	 * @return string|null
	 */
	public static function role_from_claims( $claims ) {
		$roles = isset( $claims['roles'] ) && is_array( $claims['roles'] ) ? $claims['roles'] : array();
		foreach ( self::ROLE_MAP as $app_role => $wp_role ) {
			if ( in_array( $app_role, $roles, true ) && get_role( $wp_role ) ) {
				return $wp_role;
			}
		}
		return null;
	}

	/**
	 * Inloggningsnamnet (UPN) från claims, gemener. Tom sträng om det saknas.
	 *
	 * Används som personens adress: för kontrollen att det är personal, för
	 * första kopplingen till ett befintligt konto och som kontots e-post.
	 * Claimet email används medvetet inte. Det kan komma från andra attribut
	 * i Entra och är inte tänkt för behörighet. UPN är unikt i vår tenant,
	 * och gästkonton har ett UPN som inte slutar på vår domän.
	 *
	 * @param array $claims Claims.
	 * @return string
	 */
	public static function email_from_claims( $claims ) {
		$upn = ! empty( $claims['preferred_username'] ) && is_string( $claims['preferred_username'] ) ? $claims['preferred_username'] : '';
		return strtolower( trim( $upn ) );
	}

	/**
	 * Hitta, koppla eller skapa kontot och sätt rollen.
	 *
	 * @param array  $claims Verifierade claims.
	 * @param string $role   WordPress-roll.
	 * @return WP_User|WP_Error
	 */
	public static function sign_in_user( $claims, $role ) {
		$oid   = (string) $claims['oid'];
		$email = self::email_from_claims( $claims );
		$name  = isset( $claims['name'] ) && is_string( $claims['name'] ) ? sanitize_text_field( $claims['name'] ) : '';

		$user = self::find_by_oid( $oid );

		if ( ! $user ) {
			$existing = get_user_by( 'email', $email );
			if ( $existing ) {
				// Ett konto som redan är kopplat till en annan person får aldrig tas över.
				$linked_oid = (string) get_user_meta( $existing->ID, 'rco_sso_oid', true );
				if ( '' !== $linked_oid && ! hash_equals( $linked_oid, $oid ) ) {
					return new WP_Error( 'rco_sso_conflict', 'kontot är kopplat till ett annat oid' );
				}
				$user = $existing;
			} else {
				$user = self::create_user( $email, $name, $role );
				if ( is_wp_error( $user ) ) {
					return $user;
				}
			}
		}

		if ( ! get_user_meta( $user->ID, 'rco_sso_linked', true ) ) {
			// Första kopplingen: lösenordet slumpas om och gamla sessioner avslutas,
			// så att ingen som kände till det gamla lösenordet kommer in längre.
			wp_set_password( wp_generate_password( 64, true, true ), $user->ID );
			WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
			update_user_meta( $user->ID, 'rco_sso_linked', time() );
		}
		update_user_meta( $user->ID, 'rco_sso_oid', $oid );
		update_user_meta( $user->ID, 'rco_sso_last_login', time() );

		self::sync_profile( $user, $email, $name );

		if ( array( $role ) !== array_values( $user->roles ) ) {
			$user->set_role( $role );
		}

		return get_userdata( $user->ID );
	}

	/**
	 * Konto kopplat till oid.
	 *
	 * @param string $oid Entra oid.
	 * @return WP_User|null
	 */
	public static function find_by_oid( $oid ) {
		$users = get_users(
			array(
				'meta_key'    => 'rco_sso_oid', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value'  => $oid, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'      => 2,
				'count_total' => false,
			)
		);
		return 1 === count( $users ) ? $users[0] : null;
	}

	/**
	 * Skapa ett nytt personalkonto.
	 *
	 * @param string $email E-post.
	 * @param string $name  Visningsnamn.
	 * @param string $role  Roll.
	 * @return WP_User|WP_Error
	 */
	private static function create_user( $email, $name, $role ) {
		$base  = sanitize_user( strstr( $email, '@', true ), true );
		$base  = '' === $base ? 'reklamco' : $base;
		$login = $base;
		for ( $i = 2; username_exists( $login ); $i++ ) {
			$login = $base . $i;
		}

		$user_id = wp_insert_user(
			array(
				'user_login'   => $login,
				'user_email'   => $email,
				'user_pass'    => wp_generate_password( 64, true, true ),
				'display_name' => '' !== $name ? $name : $login,
				'role'         => $role,
			)
		);
		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}
		return get_userdata( $user_id );
	}

	/**
	 * Uppdatera e-post och namn om de ändrats i Entra.
	 *
	 * @param WP_User $user  Konto.
	 * @param string  $email E-post.
	 * @param string  $name  Visningsnamn.
	 */
	private static function sync_profile( $user, $email, $name ) {
		$update = array();
		if ( strtolower( $user->user_email ) !== $email ) {
			$owner = get_user_by( 'email', $email );
			if ( ! $owner || (int) $owner->ID === (int) $user->ID ) {
				$update['user_email'] = $email;
			}
		}
		if ( '' !== $name && $user->display_name !== $name ) {
			$update['display_name'] = $name;
		}
		if ( $update ) {
			$update['ID'] = $user->ID;
			wp_update_user( $update );
		}
	}
}
