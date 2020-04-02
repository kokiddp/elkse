<?php
/**
 * @wordpress-plugin
 * Plugin Name:				ELK Security Enforcer
 * Plugin URI:				https://github.com/kokiddp/elkse
 * Description:				This simple plugin enforces security measures against march 2020 attacks and handles breach notification
 * Version:					1.0.3
 * Requires at least:		4.6
 * Tested up to:			5.3.2
 * Requires PHP:			7.1
 * Author:					ELK-Lab
 * Author URI:				https://www.elk-lab.com
 * License:					GPL-2.0+
 * License URI:				http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:				elkse
 * Domain Path:				/languages
 */

if ( !defined( 'ABSPATH' ) || !defined( 'WPINC' ) ) {
    die;
}


add_action( 'init', 'elkse_load_textdomain' );  
function elkse_load_textdomain() {
	load_plugin_textdomain( 'elkse', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' ); 
}

add_filter( 'cron_schedules', 'elkse_cron_schedules' );
function elkse_cron_schedules( $schedules ) {
	$schedules[ 'quarterhourly' ] = array(
		'interval' => 900,
		'display' => __( 'Quarter hourly', 'elkse' )
	);
    return $schedules;
}

add_action( 'after_setup_theme', 'elkse_start_cron' );
function elkse_start_cron() {
	if ( !wp_next_scheduled( 'elkse_cron' ) ) {
		wp_schedule_event( time(), 'quarterhourly', 'elkse_cron' );
	}
}

register_activation_hook( __FILE__, 'elkse_get_values' );
function elkse_get_values() {
	$site_url = get_option( 'siteurl' );
	update_option( 'elkse_site', $site_url );

	$home_url = get_option( 'home' );
	update_option( 'elkse_home', $home_url );

	$admin_email = get_option( 'admin_email' );
	update_option( 'elkse_mail', $admin_email );
}

add_action( 'elkse_cron', 'elkse_check_values', 10 );
function elkse_check_values() {
	$admin_email = get_option( 'elkse_mail' );

	$original_site_url = get_option( 'elkse_site' );
	$original_home_url = get_option( 'elkse_home' );
	$current_site_url = get_option( 'siteurl' );
	$current_home_url = get_option( 'home' );

	if ( $original_site_url != $current_site_url ) {
		elkse_send_email(
			sprintf( __( 'IMPORTANT: breach detected on %s', 'elkse' ), $original_site_url ),
			elkse_build_email( __( 'Site URL change', 'elkse' ) )
		);
		update_option( 'siteurl', $original_site_url );
	}	
	
	if ( $original_home_url != $current_home_url ) {
		elkse_send_email(
			sprintf( __( 'IMPORTANT: breach detected on %s', 'elkse' ), $original_site_url ),
			elkse_build_email( __( 'Home URL change', 'elkse' ) )
		);
		update_option( 'home', $original_home_url );
	}
}

add_filter( 'wp_insert_post_data', 'elkse_check_save_post', '99', 2 );
function elkse_check_save_post( $data, $postarr ) {
	$needles = array(
		'https://www.wow-robotics.xyz',
		'var _0x2cf4'
	);
	if ( elkse_strposa( $data['post_content'], $needles ) ) {
		elkse_send_email(
			sprintf( __( 'IMPORTANT: breach detected on %s', 'elkse' ), get_option( 'elkse_site' ) ),
			elkse_build_email( __( 'Post Script injection', 'elkse' ) )
		);
	}
	else {
		return $data;
	}
}

function elkse_send_email( $object, $body, $recipient = null ) {
	$recipient = $recipient ?? get_option( 'elkse_mail' );
	$headers = array(
		'From: ' . __( 'ELK Security Enforcer', 'elkse' ) . ' <noreply@' . $_SERVER['HTTP_HOST'] . '>',
		'Content-Type: text/html; charset=UTF-8'
	);
	$body = mb_convert_encoding( $body, 'UTF-8', mb_detect_encoding( $body ) );
	return wp_mail( $recipient, $object, $body, $headers );
}

function elkse_build_email( $breach ) {
	$template = '%1$s<br/><br/>%2$s<br/>%3$s<br/><br/>%4$s';
	return sprintf(
		$template,
		__( 'Dear administrator,', 'elkse' ),
		sprintf( __( 'ELK Security Enforcer detected a breach involving the following problem: <strong>%s</strong>.', 'elkse' ), $breach ),
		sprintf( __( 'The breach should have occurred in the 15 minutes before %s.', 'elkse' ), date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ) ),
		__( 'The ELK Security Enforcer Team', 'elkse' )
	);
}

function elkse_strposa( $haystack, $needles, $offset = 0 ) {
    if ( !is_array( $needles ) ) $needles = array( $needles );
    foreach( $needles as $needle ) {
        if ( strpos( $haystack, $needle, $offset ) !== false ) return true;
    }
    return false;
}