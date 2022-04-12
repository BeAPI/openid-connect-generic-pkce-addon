<?php
/**
 * Plugin Name:       OpenID Connect Generic PKCE Addon
 * Description:       Add PKCE support in OpenID Connect Generic plugin.
 * Version:           1.0.0
 * Author:            Be API Technical team
 * Author URI:        https://beapi.fr
 */

namespace Beapi\Openid_Pkce_Addon;

/**
 * Set PKCE challenge in auth URL.
 *
 * This first step is used to append PKCE challenge to the auth URL. During this step PKCE codes (verifier and challenge)
 * are created and stored in a state. This is needed to access the verifier code later during the token exchange
 * request.
 *
 * @param string $url
 *
 * @return string
 */
function set_pkce_challenge_in_auth_url( string $url ): string {
	$state = get_state_from_url( $url );
	if ( is_wp_error( $state ) ) {
		return $url;
	}

	$pkce_code        = pkce_code_generator();
	/** @psalm-suppress PossiblyInvalidArgument - $state value is check by `is_wp_error` beforehand. */
	$pkce_code_stored = store_pkce_code_state( $state, $pkce_code );
	if ( is_wp_error( $pkce_code_stored ) ) {
		return $url;
	}

	$url = add_query_arg(
		[
			'code_challenge'        => $pkce_code['code_challenge'],
			'code_challenge_method' => $pkce_code['code_challenge_method'],
		],
		$url
	);

	return $url;
}

add_filter( 'openid-connect-generic-auth-url', __NAMESPACE__ . '\\set_pkce_challenge_in_auth_url' );

/**
 * Set PKCE verifier in token request.
 *
 * This second step add the verifier code to the auth token request. Verifier code is retrieve using the state contain
 * in the callback URL.
 *
 * @param array $request
 * @param string $request_type
 *
 * @return array
 */
function set_pkce_verifier_in_auth_token_request( array $request, string $request_type ) {
	if ( 'get-authentication-token' !== $request_type ) {
		return $request;
	}

	// look for state in $_GET
	$state = get_state_from_request( $_GET );
	if ( is_wp_error( $state ) ) {
		return $request;
	}

	/** @psalm-suppress PossiblyInvalidOperand - $state value is check by `is_wp_error` beforehand. */
	$pkce_data = get_transient( 'openid-connect-generic-state--' . $state . '--pkce' );
	if ( empty( $pkce_data ) || ! isset( $pkce_data[ $state ] ) ) {
		return $request;
	}

	$request['body']['code_verifier'] = $pkce_data[ $state ]['code_verifier'];

	return $request;
}

add_filter( 'openid-connect-generic-alter-request', __NAMESPACE__ . '\\set_pkce_verifier_in_auth_token_request', 10, 2 );

/**
 * Retrieve state param from request params.
 *
 * @param array $request_params
 *
 * @return string|\WP_Error
 */
function get_state_from_request( array $request_params ) {
	return $request_params['state'] ?? new \WP_Error( 'missing-state', 'Missing state.' );
}

/**
 * Retrieve state param from auth URL.
 *
 * @param string $url
 *
 * @return string|\WP_Error
 */
function get_state_from_url( string $url ) {

	// extract query string part from auth URL
	[ , $query ] = explode( '?', $url );
	if ( empty( $query ) ) {
		return new \WP_Error( 'missing-params', "URL doesn't contain expected params." );
	}

	// get state param from query string
	parse_str( $query, $params );
	if ( ! isset( $params['state'] ) || empty( $params['state'] ) ) {
		return new \WP_Error( 'missing-state-param', "URL doesn't contain state param." );
	}

	return $params['state'];
}

/**
 * Store PKCE code in auth flow state.
 *
 * Mimic OpenID Connect Generic state naming to take advantage of its garbage collection mechanism.
 *
 * @param string $state
 * @param array $pkce_code
 *
 * @return bool|\WP_Error
 */
function store_pkce_code_state( string $state, array $pkce_code ) {
	$pkce_state = [
		$state => $pkce_code,
	];
	set_transient( 'openid-connect-generic-state--' . $state . '--pkce', $pkce_state, get_state_time_limit() );

	return true;
}

/**
 * Generate PKCE code for OAuth flow.
 *
 * @see : https://help.aweber.com/hc/en-us/articles/360036524474-How-do-I-use-Proof-Key-for-Code-Exchange-PKCE-
 *
 * @return array{code_verifier: string, code_challenge: string, code_challenge_method: string}
 */
function pkce_code_generator(): array {
	$verifier_bytes = random_bytes( 64 );
	$verifier       = rtrim( strtr( base64_encode( $verifier_bytes ), '+/', '-_' ), '=' );

	// Very important, "raw_output" must be set to true or the challenge will not match the verifier.
	$challenge_bytes = hash( 'sha256', $verifier, true );
	$challenge       = rtrim( strtr( base64_encode( $challenge_bytes ), '+/', '-_' ), '=' );

	return [
		'code_verifier'         => $verifier,
		'code_challenge'        => $challenge,
		'code_challenge_method' => 'S256',
	];
}

/**
 * Get state time limit from plugin settings.
 *
 * @return int
 */
function get_state_time_limit(): int {
	$state_time_limit       = 180; // default value from plugin
	$openid_connect_options = get_option( 'openid_connect_generic_settings', [] );
	if ( ! empty( $openid_connect_options['state_time_limit'] ) ) {
		$state_time_limit = (int) $openid_connect_options['state_time_limit'];
	}

	return $state_time_limit;
}

