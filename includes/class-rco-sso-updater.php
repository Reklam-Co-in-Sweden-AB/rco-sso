<?php
/**
 * Uppdateringar från GitHub, med signaturkontroll.
 *
 * Nya versioner hämtas från de publika releaserna i Reklam-Co-in-Sweden-AB/rco-sso.
 * Varje release har två filer: rco-sso.zip och rco-sso.zip.sig. Signaturen är
 * en Ed25519-signatur (base64) av manifestet "rco-sso|<version>|<sha256 av zip>",
 * gjord med byråns privata signeringsnyckel. Versionen ingår, så en gammal
 * signerad zip kan inte publiceras som en ny version (nedgradering). Den
 * publika nyckeln står i RCO_SSO_RELEASE_PUBLIC_KEY.
 *
 * Pluginet styr inloggningen på alla sajter, så en manipulerad uppdatering vore
 * en väg in överallt. Därför installeras ingenting som inte är signerat, och
 * utan publik nyckel vägrar pluginet alla uppdateringar.
 *
 * @package RCO_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Uppdaterare.
 */
class RCO_SSO_Updater {

	const REPO      = 'Reklam-Co-in-Sweden-AB/rco-sso';
	const TRANSIENT = 'rco_sso_release';
	const ZIP_NAME  = 'rco-sso.zip';
	const SIG_NAME  = 'rco-sso.zip.sig';

	// Längderna för Ed25519. De står här som tal, eftersom PHP:s konstanter
	// SODIUM_* saknas på servrar utan sodium-tillägget.
	const SIGNATURE_BYTES  = 64;
	const PUBLIC_KEY_BYTES = 32;

	/**
	 * Koppla in hookarna.
	 */
	public static function init() {
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'check_for_update' ) );
		add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 20, 3 );
		// Sist, så att inget annat filter kan svara med en osignerad fil för vårt plugin.
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'verified_download' ), PHP_INT_MAX, 4 );
	}

	/**
	 * Pluginets basnamn, till exempel rco-sso/rco-sso.php.
	 *
	 * @return string
	 */
	public static function basename() {
		return plugin_basename( RCO_SSO_FILE );
	}

	/**
	 * Är den publika nyckeln ifylld och giltig?
	 *
	 * @return bool
	 */
	public static function has_public_key() {
		$key = base64_decode( (string) RCO_SSO_RELEASE_PUBLIC_KEY, true );
		return is_string( $key ) && self::PUBLIC_KEY_BYTES === strlen( $key );
	}

	/**
	 * Finns funktionen som kontrollerar signaturer?
	 *
	 * PHP-tillägget sodium saknas på en del servrar. WordPress har ett eget
	 * bibliotek med samma funktioner (sodium_compat) som laddas vid behov.
	 *
	 * @return bool
	 */
	public static function has_sodium() {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) && defined( 'WPINC' ) ) {
			$compat = ABSPATH . WPINC . '/sodium_compat/autoload.php';
			if ( is_readable( $compat ) ) {
				require_once $compat;
			}
		}
		return function_exists( 'sodium_crypto_sign_verify_detached' );
	}

	/**
	 * Manifestet som signeras: version och zip-filens hash.
	 *
	 * @param string $version  Version.
	 * @param string $contents Zip-filens innehåll.
	 * @return string
	 */
	public static function manifest( $version, $contents ) {
		return 'rco-sso|' . $version . '|' . hash( 'sha256', (string) $contents );
	}

	/**
	 * Kontrollera en signatur. Ren funktion, används även i test.
	 *
	 * @param string $contents      Filens innehåll.
	 * @param string $signature_b64 Signaturen, base64.
	 * @param string $public_b64    Publik nyckel, base64.
	 * @return bool
	 */
	public static function signature_is_valid( $contents, $signature_b64, $public_b64 ) {
		$signature = base64_decode( trim( (string) $signature_b64 ), true );
		$public    = base64_decode( (string) $public_b64, true );
		if ( ! is_string( $signature ) || self::SIGNATURE_BYTES !== strlen( $signature ) ) {
			return false;
		}
		if ( ! is_string( $public ) || self::PUBLIC_KEY_BYTES !== strlen( $public ) ) {
			return false;
		}
		// Går signaturen inte att kontrollera godtas den inte.
		if ( ! self::has_sodium() ) {
			return false;
		}
		try {
			return true === sodium_crypto_sign_verify_detached( $signature, (string) $contents, $public );
		} catch ( Throwable $e ) {
			return false;
		}
	}

	/**
	 * Senaste releasen, cachad i sex timmar. Null om den inte gick att hämta.
	 *
	 * @return array{version: string, zip: string, sig: string, notes: string, url: string}|null
	 */
	public static function latest_release() {
		$cached = get_transient( self::TRANSIENT );
		if ( is_array( $cached ) ) {
			return $cached['version'] ? $cached : null;
		}

		$release  = null;
		$response = wp_remote_get(
			RCO_SSO_UPDATE_API,
			array(
				'timeout' => 5,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'rco-sso',
				),
			)
		);
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( 200 === (int) wp_remote_retrieve_response_code( $response ) && is_array( $body ) ) {
			$version = ltrim( (string) ( $body['tag_name'] ?? '' ), 'v' );
			$zip     = '';
			$sig     = '';
			foreach ( (array) ( $body['assets'] ?? array() ) as $asset ) {
				$name = $asset['name'] ?? '';
				$url  = (string) ( $asset['browser_download_url'] ?? '' );
				if ( self::ZIP_NAME === $name ) {
					$zip = $url;
				} elseif ( self::SIG_NAME === $name ) {
					$sig = $url;
				}
			}
			// Bara versionsnummer och nedladdningar från vårt eget repo godtas.
			if ( preg_match( '/^\d+\.\d+\.\d+$/', $version ) && self::is_trusted_url( $zip ) && self::is_trusted_url( $sig ) ) {
				$release = array(
					'version' => $version,
					'zip'     => $zip,
					'sig'     => $sig,
					'notes'   => (string) ( $body['body'] ?? '' ),
					'url'     => (string) ( $body['html_url'] ?? 'https://github.com/' . self::REPO ),
				);
			}
		}

		// Misslyckad hämtning cachas kortare, så att nästa försök kommer snart.
		set_transient( self::TRANSIENT, $release ? $release : array( 'version' => '' ), $release ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
		return $release;
	}

	/**
	 * Kommer adressen från vårt repos releaser?
	 *
	 * @param string $url Adress.
	 * @return bool
	 */
	private static function is_trusted_url( $url ) {
		return '' !== $url && 0 === strpos( $url, RCO_SSO_UPDATE_DOWNLOAD_PREFIX );
	}

	/**
	 * Lägg till uppdateringen i WordPress lista när en nyare version finns.
	 *
	 * @param object $transient Uppdateringslistan.
	 * @return object
	 */
	public static function check_for_update( $transient ) {
		if ( ! is_object( $transient ) || empty( $transient->checked ) ) {
			return $transient;
		}
		$release = self::latest_release();
		if ( ! $release || ! version_compare( $release['version'], RCO_SSO_VERSION, '>' ) ) {
			return $transient;
		}
		$transient->response[ self::basename() ] = (object) array(
			'slug'        => 'rco-sso',
			'plugin'      => self::basename(),
			'new_version' => $release['version'],
			'package'     => $release['zip'],
			'url'         => $release['url'],
		);
		return $transient;
	}

	/**
	 * Information i rutan "Visa versionsdetaljer".
	 *
	 * @param mixed  $result Tidigare resultat.
	 * @param string $action Åtgärd.
	 * @param object $args   Argument.
	 * @return mixed
	 */
	public static function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! isset( $args->slug ) || 'rco-sso' !== $args->slug ) {
			return $result;
		}
		$release = self::latest_release();
		if ( ! $release ) {
			return $result;
		}
		return (object) array(
			'name'          => 'Reklam & Co SSO',
			'slug'          => 'rco-sso',
			'version'       => $release['version'],
			'author'        => 'Reklam & Co',
			'homepage'      => 'https://github.com/' . self::REPO,
			'download_link' => $release['zip'],
			'sections'      => array( 'changelog' => wpautop( esc_html( $release['notes'] ) ) ),
		);
	}

	/**
	 * Ladda ner uppdateringen själv och installera den bara om signaturen stämmer.
	 *
	 * WordPress använder den nedladdade filen om filtret returnerar en sökväg,
	 * och avbryter om det returnerar ett fel.
	 *
	 * @param bool|string|WP_Error $reply   Tidigare svar.
	 * @param string               $package Paketets adress.
	 * @param object               $upgrader Uppgraderaren.
	 * @return bool|string|WP_Error
	 */
	public static function verified_download( $reply, $package, $upgrader = null, $hook_extra = array() ) {
		// Vårt plugin känns igen på namnet i uppgraderingen, och för säkerhets
		// skull även på filnamnet och adressen. Andra pluginers paket rör vi inte.
		$name = basename( (string) wp_parse_url( (string) $package, PHP_URL_PATH ) );
		$ours = ( is_array( $hook_extra ) && isset( $hook_extra['plugin'] ) && self::basename() === $hook_extra['plugin'] )
			|| self::ZIP_NAME === $name
			|| self::is_trusted_url( (string) $package );
		if ( ! $ours ) {
			return $reply;
		}
		// Har ett annat filter redan laddat ner något för vårt plugin används det inte.
		if ( is_string( $reply ) && '' !== $reply && file_exists( $reply ) ) {
			wp_delete_file( $reply );
		}
		// Vårt paket godtas bara om det är exakt den senaste releasen från vårt repo.
		$release = self::latest_release();
		if ( ! $release || $package !== $release['zip'] ) {
			return new WP_Error( 'rco_sso_unknown_release', __( 'Uppdateringen av Reklam & Co SSO kommer inte från byråns senaste release och installeras inte.', 'rco-sso' ) );
		}
		if ( ! self::has_public_key() ) {
			return new WP_Error( 'rco_sso_no_public_key', __( 'Reklam & Co SSO saknar publik signeringsnyckel och installerar inga uppdateringar.', 'rco-sso' ) );
		}
		if ( ! self::has_sodium() ) {
			return new WP_Error( 'rco_sso_no_sodium', __( 'Servern kan inte kontrollera signaturen (sodium saknas), så uppdateringen av Reklam & Co SSO installeras inte.', 'rco-sso' ) );
		}

		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$file = download_url( $release['zip'], 60 );
		if ( is_wp_error( $file ) ) {
			return $file;
		}

		$sig_response = wp_remote_get( $release['sig'], array( 'timeout' => 10 ) );
		$signature    = 200 === (int) wp_remote_retrieve_response_code( $sig_response ) ? (string) wp_remote_retrieve_body( $sig_response ) : '';
		$contents     = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

		if ( ! self::signature_is_valid( self::manifest( $release['version'], $contents ), $signature, RCO_SSO_RELEASE_PUBLIC_KEY ) ) {
			wp_delete_file( $file );
			error_log( 'rco-sso: uppdatering ' . $release['version'] . ' nekad, signaturen stämmer inte' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return new WP_Error( 'rco_sso_bad_signature', __( 'Uppdateringen av Reklam & Co SSO är inte signerad av Reklam & Co och installeras inte.', 'rco-sso' ) );
		}

		return $file;
	}
}
