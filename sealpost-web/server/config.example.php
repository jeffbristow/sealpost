<?php
/* =====================================================================
 * Sealpost Sync Server — config.php
 * ---------------------------------------------------------------------
 * The only file you should ever need to edit.
 *
 * This file is read by api.php and index.php. Opening it directly in a
 * browser shows nothing (see the guard just below) and .htaccess blocks
 * it as well.
 *
 * Sections:
 *   1. Direct-access guard
 *   2. Setup code (used once, to create your vault)
 *   3. Where the encrypted vault is stored
 *   4. Security switches
 *   5. Limits
 * ===================================================================== */

/* ---------------------------------------------------------------------
 * 1. DIRECT-ACCESS GUARD
 *    api.php / index.php define SEALPOST before loading this file.
 * ------------------------------------------------------------------- */
if (!defined('SEALPOST')) {
    http_response_code(404);
    exit;
}

return [

    /* -----------------------------------------------------------------
     * 2. SETUP CODE
     *    Sealpost asks for this code the first time you choose
     *    "Create a new vault". It stops anyone else who finds this page
     *    from creating the vault before you do.
     *    After your vault exists the code is no longer accepted for
     *    anything, so you can leave it as is.
     *    Set it to '' to switch vault creation off completely.
     * --------------------------------------------------------------- */
    'setup_code' => 'CHANGE-THIS-CODE',

    /* -----------------------------------------------------------------
     * 3. VAULT LOCATION
     *    Folder that holds vault.sqlite (everything in it is encrypted
     *    by Sealpost before it is sent here).
     *    '' = automatic: a folder named "sealpost-data" one level ABOVE
     *         your public web folder, e.g. /home/jeffbris/sealpost-data
     *         — it can never be downloaded through the website.
     *    Or give a full path, e.g. '/home/jeffbris/sealpost-data'.
     * --------------------------------------------------------------- */
    'data_dir' => '',

    /* -----------------------------------------------------------------
     * 4. SECURITY SWITCHES
     *    require_https: refuse requests that didn't arrive over HTTPS
     *                   (requests from the server itself — localhost —
     *                   are always allowed, for testing).
     *    login_failures_per_user / per_ip: wrong passphrases allowed in
     *                   'lockout_minutes' before that username / that
     *                   internet address has to wait.
     * --------------------------------------------------------------- */
    'require_https'          => true,
    'login_failures_per_user'=> 5,
    'login_failures_per_ip'  => 20,
    'lockout_minutes'        => 15,

    /* -----------------------------------------------------------------
     * 5. LIMITS
     *    max_item_kb:     largest single synced item (one key, one
     *                     contact, one account …) after encryption.
     *    max_items:       most items one vault may hold.
     *    max_request_mb:  largest single upload from Sealpost.
     * --------------------------------------------------------------- */
    'max_item_kb'    => 1024,
    'max_items'      => 20000,
    'max_request_mb' => 16,
];
