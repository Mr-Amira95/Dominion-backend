<?php

use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

const STEAM_OPENID_URL = 'https://steamcommunity.com/openid/login';

function steamCallbackParams(string $steamId, array $overrides = [], string $state = 'test-state-123'): array
{
    return array_merge([
        'openid.ns' => 'http://specs.openid.net/auth/2.0',
        'openid.mode' => 'id_res',
        'openid.op_endpoint' => STEAM_OPENID_URL,
        'openid.claimed_id' => "https://steamcommunity.com/openid/id/{$steamId}",
        'openid.identity' => "https://steamcommunity.com/openid/id/{$steamId}",
        'openid.return_to' => "http://localhost/auth/steam/callback?state={$state}",
        'openid.response_nonce' => '2026-09-01T10:00:00Zabcdef123',
        'openid.assoc_handle' => '1234567890',
        'openid.signed' => 'signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle,ns',
        'openid.sig' => 'ZmFrZS1zaWduYXR1cmU=',
        'state' => $state,
    ], $overrides);
}

function callSteamCallback(string $steamId, array $overrides = [], string $state = 'test-state-123')
{
    $query = http_build_query(steamCallbackParams($steamId, $overrides, $state));

    return test()->withSession(['steam_openid_state' => $state])
        ->get('/auth/steam/callback?'.$query);
}

test('the steam login route exists and redirects to steam', function () {
    $response = $this->get('/auth/steam');

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith(STEAM_OPENID_URL);
    expect($response->headers->get('Location'))->toContain('openid.mode=checkid_setup');
});

test('callback rejects a request with a missing or mismatched state', function () {
    $steamId = '76561197960287930';

    $query = http_build_query(steamCallbackParams($steamId, [], 'right-state'));

    $response = $this->withSession(['steam_openid_state' => 'right-state'])
        ->get('/auth/steam/callback?'.str_replace('right-state', 'wrong-state', $query));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('status=error');
    expect($response->headers->get('Location'))->toContain('reason=invalid_state');

    $this->assertGuest();
    expect(User::count())->toBe(0);
});

test('callback rejects an invalid or incomplete openid response', function () {
    $steamId = '76561197960287930';

    // Missing required openid.sig parameter.
    $params = steamCallbackParams($steamId);
    unset($params['openid.sig']);

    $query = http_build_query($params);

    $response = $this->withSession(['steam_openid_state' => 'test-state-123'])
        ->get('/auth/steam/callback?'.$query);

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('reason=invalid_response');

    $this->assertGuest();
    expect(User::count())->toBe(0);
});

test('callback rejects an assertion steam does not confirm as valid', function () {
    Http::fake([
        STEAM_OPENID_URL => Http::response("ns:http://specs.openid.net/auth/2.0\nis_valid:false\n"),
    ]);

    $response = callSteamCallback('76561197960287930');

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('reason=validation_failed');

    $this->assertGuest();
    expect(User::count())->toBe(0);
});

test('callback handles steam being unavailable', function () {
    Http::fake([
        STEAM_OPENID_URL => Http::response('Service Unavailable', 503),
    ]);

    $response = callSteamCallback('76561197960287930');

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('reason=steam_unavailable');

    $this->assertGuest();
});

test('a valid steamid is only extracted and a user created after successful steam validation', function () {
    $steamId = '76561197960287930';

    Http::fake([
        STEAM_OPENID_URL => Http::response("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n"),
    ]);

    $response = callSteamCallback($steamId);

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('status=success');

    $this->assertAuthenticated();

    $user = User::where('steam_id', $steamId)->first();
    expect($user)->not->toBeNull();
    expect(auth()->id())->toBe($user->id);
});

test('an existing steam user is found and reused instead of duplicated', function () {
    $steamId = '76561197960287930';

    $existing = User::factory()->create(['steam_id' => $steamId]);

    Http::fake([
        STEAM_OPENID_URL => Http::response("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n"),
    ]);

    $response = callSteamCallback($steamId);

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('status=success');

    expect(User::where('steam_id', $steamId)->count())->toBe(1);
    expect(auth()->id())->toBe($existing->id);
});

test('a steamid cannot be assigned to more than one user account', function () {
    User::factory()->create(['steam_id' => '76561197960287930']);

    expect(fn () => User::factory()->create(['steam_id' => '76561197960287930']))
        ->toThrow(QueryException::class);
});
