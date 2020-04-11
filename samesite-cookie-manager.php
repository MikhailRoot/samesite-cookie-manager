<?php
/**
 * Plugin Name: Same Site Cookie Manager
 * Description: Same site cookie manager allows to explicitly specify SameSite Lax|None|Strict for WP authentication cookie. Requires php 7.3.0 and above.
 * Author: Mikhail Durnev
 * Version: 0.1
 * Author URI: https://mikhailroot.ru/
 *
 * @package samesite-cookie-manager;
 */

// we do this change only for php 7.3.0+ which supports SameSite natively.
if ( version_compare( PHP_VERSION, '7.3.0' ) >= 0 ) {
	if ( ! function_exists( 'wp_set_auth_cookie' ) ) :

		/**
		 * Log in a user by setting authentication cookies.
		 *
		 * The $remember parameter increases the time that the cookie will be kept. The
		 * default the cookie is kept without remembering is two days. When $remember is
		 * set, the cookies will be kept for 14 days or two weeks.
		 *
		 * @param int $user_id User ID
		 * @param bool $remember Whether to remember the user
		 * @param mixed $secure Whether the admin cookies should only be sent over HTTPS.
		 *                         Default is_ssl().
		 * @param string $token Optional. User's session token to use for this cookie.
		 *
		 * @since 2.5.0
		 * @since 4.3.0 Added the `$token` parameter.
		 *
		 */
		function wp_set_auth_cookie( $user_id, $remember = false, $secure = '', $token = '' ) {
			if ( $remember ) {
				/**
				 * Filters the duration of the authentication cookie expiration period.
				 *
				 * @param int $length Duration of the expiration period in seconds.
				 * @param int $user_id User ID.
				 * @param bool $remember Whether to remember the user login. Default false.
				 *
				 * @since 2.8.0
				 *
				 */
				$expiration = time() + apply_filters( 'auth_cookie_expiration', 14 * DAY_IN_SECONDS, $user_id, $remember );

				/*
				 * Ensure the browser will continue to send the cookie after the expiration time is reached.
				 * Needed for the login grace period in wp_validate_auth_cookie().
				 */
				$expire = $expiration + ( 12 * HOUR_IN_SECONDS );
			} else {
				/** This filter is documented in wp-includes/pluggable.php */
				$expiration = time() + apply_filters( 'auth_cookie_expiration', 2 * DAY_IN_SECONDS, $user_id, $remember );
				$expire     = 0;
			}

			if ( '' === $secure ) {
				$secure = is_ssl();
			}

			// Front-end cookie is secure when the auth cookie is secure and the site's home URL is forced HTTPS.
			$secure_logged_in_cookie = $secure && 'https' === parse_url( get_option( 'home' ), PHP_URL_SCHEME );

			/**
			 * Filters whether the connection is secure.
			 *
			 * @param bool $secure Whether the connection is secure.
			 * @param int $user_id User ID.
			 *
			 * @since 3.1.0
			 *
			 */
			$secure = apply_filters( 'secure_auth_cookie', $secure, $user_id );

			/**
			 * Filters whether to use a secure cookie when logged-in.
			 *
			 * @param bool $secure_logged_in_cookie Whether to use a secure cookie when logged-in.
			 * @param int $user_id User ID.
			 * @param bool $secure Whether the connection is secure.
			 *
			 * @since 3.1.0
			 *
			 */
			$secure_logged_in_cookie = apply_filters( 'secure_logged_in_cookie', $secure_logged_in_cookie, $user_id, $secure );

			if ( $secure ) {
				$auth_cookie_name = SECURE_AUTH_COOKIE;
				$scheme           = 'secure_auth';
			} else {
				$auth_cookie_name = AUTH_COOKIE;
				$scheme           = 'auth';
			}

			if ( '' === $token ) {
				$manager = WP_Session_Tokens::get_instance( $user_id );
				$token   = $manager->create( $expiration );
			}

			$auth_cookie      = wp_generate_auth_cookie( $user_id, $expiration, $scheme, $token );
			$logged_in_cookie = wp_generate_auth_cookie( $user_id, $expiration, 'logged_in', $token );

			/**
			 * Fires immediately before the authentication cookie is set.
			 *
			 * @param string $auth_cookie Authentication cookie value.
			 * @param int $expire The time the login grace period expires as a UNIX timestamp.
			 *                            Default is 12 hours past the cookie's expiration time.
			 * @param int $expiration The time when the authentication cookie expires as a UNIX timestamp.
			 *                            Default is 14 days from now.
			 * @param int $user_id User ID.
			 * @param string $scheme Authentication scheme. Values include 'auth' or 'secure_auth'.
			 * @param string $token User's session token to use for this cookie.
			 *
			 * @since 2.5.0
			 * @since 4.9.0 The `$token` parameter was added.
			 *
			 */
			do_action( 'set_auth_cookie', $auth_cookie, $expire, $expiration, $user_id, $scheme, $token );

			/**
			 * Fires immediately before the logged-in authentication cookie is set.
			 *
			 * @param string $logged_in_cookie The logged-in cookie value.
			 * @param int $expire The time the login grace period expires as a UNIX timestamp.
			 *                                 Default is 12 hours past the cookie's expiration time.
			 * @param int $expiration The time when the logged-in authentication cookie expires as a UNIX timestamp.
			 *                                 Default is 14 days from now.
			 * @param int $user_id User ID.
			 * @param string $scheme Authentication scheme. Default 'logged_in'.
			 * @param string $token User's session token to use for this cookie.
			 *
			 * @since 2.6.0
			 * @since 4.9.0 The `$token` parameter was added.
			 *
			 */
			do_action( 'set_logged_in_cookie', $logged_in_cookie, $expire, $expiration, $user_id, 'logged_in', $token );

			/**
			 * Allows preventing auth cookies from actually being sent to the client.
			 *
			 * @param bool $send Whether to send auth cookies to the client.
			 *
			 * @since 4.7.4
			 *
			 */
			if ( ! apply_filters( 'send_auth_cookies', true ) ) {
				return;
			}

			$same_site = get_option( 'wp_auth_cookie_samesite', 'None' ); // Lax|Strict|None.

			// lets check PHP version if it's 7.3.0+.
			if ( version_compare( PHP_VERSION, '7.3.0' ) >= 0 ) {
				// lets use new setcookie function shipped with php 7.3.0 .

				//phpcs:ignore
				//setcookie( $auth_cookie_name, $auth_cookie, $expire, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN, $secure, true );
				setcookie(
					$auth_cookie_name,
					$auth_cookie,
					array(
						'expires'  => $expire,
						'path'     => PLUGINS_COOKIE_PATH,
						'domain'   => COOKIE_DOMAIN,
						'secure'   => $secure,
						'httponly' => true,
						'samesite' => $same_site,
					)
				);

				//phpcs:ignore
				//setcookie( $auth_cookie_name, $auth_cookie, $expire, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, $secure, true );
				setcookie(
					$auth_cookie_name,
					$auth_cookie,
					array(
						'expires'  => $expire,
						'path'     => ADMIN_COOKIE_PATH,
						'domain'   => COOKIE_DOMAIN,
						'secure'   => $secure,
						'httponly' => true,
						'samesite' => $same_site,
					)
				);

				//phpcs:ignore
				//setcookie( LOGGED_IN_COOKIE, $logged_in_cookie, $expire, COOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true );
				setcookie(
					LOGGED_IN_COOKIE,
					$logged_in_cookie,
					array(
						'expires'  => $expire,
						'path'     => COOKIEPATH,
						'domain'   => COOKIE_DOMAIN,
						'secure'   => $secure_logged_in_cookie,
						'httponly' => true,
						'samesite' => $same_site,
					)
				);

				if ( COOKIEPATH != SITECOOKIEPATH ) {
					//phpcs:ignore
					//setcookie( LOGGED_IN_COOKIE, $logged_in_cookie, $expire, SITECOOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true );
					setcookie(
						LOGGED_IN_COOKIE,
						$logged_in_cookie,
						array(
							'expires'  => $expire,
							'path'     => SITECOOKIEPATH,
							'domain'   => COOKIE_DOMAIN,
							'secure'   => $secure_logged_in_cookie,
							'httponly' => true,
							'samesite' => $same_site,
						)
					);
				}
			} else {
				// we no longer need this fallback but let's keep it for historical purposes.
				// set as before if PHP is lower then 7.3. - approach with headers doesn't work.
				setcookie( $auth_cookie_name, $auth_cookie, $expire, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN, $secure, true );
				setcookie( $auth_cookie_name, $auth_cookie, $expire, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, $secure, true );
				setcookie( LOGGED_IN_COOKIE, $logged_in_cookie, $expire, COOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true );
				if ( COOKIEPATH != SITECOOKIEPATH ) {
					setcookie( LOGGED_IN_COOKIE, $logged_in_cookie, $expire, SITECOOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true );
				}
			}

		}

	endif;
}

/**
 * Registers our Setting for SameSite cookie value.
 */
function sscm_register_setting() {

	$option_name = 'wp_auth_cookie_samesite';

	register_setting(
		'general',
		$option_name,
		array(
			'type'              => 'string',
			'group'             => 'general',
			'description'       => 'Authentication Cookie SameSite parameter',
			'sanitize_callback' => 'sscm_sanitize_value',
			'show_in_rest'      => false,
			'default'           => 'Lax',
		)
	);

	// add Field.
	add_settings_field(
		'sscm_setting-id',
		'Authentication SameSite Cookie parameter',
		'sscm_setting_callback_function',
		'general',
		'default',
		array(
			'id'          => 'myprefix_setting-id',
			'option_name' => $option_name,
		)
	);

}
add_action( 'admin_init', 'sscm_register_setting' );

/**
 * Sanitizes SameSite value.
 *
 * @param string $val Value to sanitize.
 *
 * @return string
 */
function sscm_sanitize_value( $val ) {

	$valid_values = sscm_get_valid_values();

	if ( in_array( $val, $valid_values, true ) ) {
		return $val;
	} else {
		return 'Lax'; // default one.
	}
}

/**
 * Valid values for SameSite Cookie attribute.
 *
 * @return array
 */
function sscm_get_valid_values() {
	return array(
		'None',
		'Lax',
		'Strict',
	);
}

/**
 * Renders Selector for our SameSite option field.
 *
 * @param array $val Data to render.
 */
function sscm_setting_callback_function( $val ) {
	$id           = $val['id'];
	$option_name  = $val['option_name'];
	$option_value = get_option( $option_name );
	$valid_values = sscm_get_valid_values();
	?>
	<select name="<?php echo esc_attr( $option_name ); ?>" id="<?php echo esc_attr( $id ); ?>">
		<?php foreach ( $valid_values as $valid_value ) : ?>
			<option value="<?php echo esc_attr( $valid_value ); ?>"  <?php echo esc_attr( $valid_value === $option_value ? ' selected ' : '' ); ?> > <?php echo esc_html( $valid_value ); ?> </option>		<?php endforeach; ?>
	</select>
	<?php if ( version_compare( PHP_VERSION, '7.3.0' ) < 0 ) : ?>
		<p class="description" style="color: red;">
			Warning: Upgrade to PHP 7.3.0 or above to be able to set SameSite Authentication Cookie,<br>
			Current PHP version is: <?php echo esc_html( PHP_VERSION ); ?><br>
			Otherwise setting will not be applied. <br>
		</p>
	<?php endif; ?>

	<p class="description">
		Authentication Cookie SameSite parameter, Use:
		<ul>
			<li>`None` if you need to display wp-admin in iframe on other site,</li>
			<li>`Strict` to allow cookie being used only on same site domain </li>
			<li>`Lax` to allow usage on subdomains as well (default is Lax)</li>
		</ul>
	</p>

	<?php
}
