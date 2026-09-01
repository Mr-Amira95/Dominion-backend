<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'key' => env('POSTMARK_API_KEY'),
    ],

    'resend' => [
        'key' => env('RESEND_API_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Steam OpenID
    |--------------------------------------------------------------------------
    |
    | Configuration for "Sign in through Steam" using OpenID 2.0. This does
    | NOT use the Steam Web API and requires no API key — it only verifies
    | the user's identity (SteamID64) via Steam's OpenID provider.
    |
    */

    'steam' => [
        'openid_url' => env('STEAM_OPENID_URL', 'https://steamcommunity.com/openid/login'),
        'realm' => env('STEAM_OPENID_REALM'),
    ],

];
