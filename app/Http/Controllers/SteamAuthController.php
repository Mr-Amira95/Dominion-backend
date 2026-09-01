<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;

/**
 * Authenticates users via Steam OpenID 2.0.
 *
 * This intentionally does NOT use the Steam Web API (no API key involved).
 * It only verifies the user's identity and extracts their SteamID64.
 */
class SteamAuthController extends Controller
{
    private const OPENID_NS = 'http://specs.openid.net/auth/2.0';

    private const IDENTIFIER_SELECT = 'http://specs.openid.net/auth/2.0/identifier_select';

    private const CLAIMED_ID_PATTERN = '/^https:\/\/steamcommunity\.com\/openid\/id\/(7\d{16})$/';

    private const STATE_SESSION_KEY = 'steam_openid_state';

    /**
     * PHP mangles dots in incoming query-string keys to underscores (e.g.
     * "openid.ns" arrives as $request->query('openid_ns')). This maps the
     * mangled key we can actually read back to the real "openid.*" key
     * Steam expects when we echo the assertion back for verification.
     */
    private const OPENID_FIELDS = [
        'openid_ns' => 'openid.ns',
        'openid_mode' => 'openid.mode',
        'openid_op_endpoint' => 'openid.op_endpoint',
        'openid_claimed_id' => 'openid.claimed_id',
        'openid_identity' => 'openid.identity',
        'openid_return_to' => 'openid.return_to',
        'openid_response_nonce' => 'openid.response_nonce',
        'openid_assoc_handle' => 'openid.assoc_handle',
        'openid_signed' => 'openid.signed',
        'openid_sig' => 'openid.sig',
    ];

    /**
     * Redirect the browser to Steam's OpenID login page.
     */
    public function redirect(Request $request): RedirectResponse
    {
        $state = Str::random(40);

        $request->session()->put(self::STATE_SESSION_KEY, $state);

        $params = [
            'openid.ns' => self::OPENID_NS,
            'openid.mode' => 'checkid_setup',
            'openid.return_to' => route('steam.callback', ['state' => $state]),
            // Falls back to the current request's own host (not APP_URL) so realm always
            // matches return_to's host — otherwise Steam rejects the assertion outright
            // whenever the app is reached via a different host/port than APP_URL declares
            // (e.g. 127.0.0.1 vs localhost during local development).
            'openid.realm' => config('services.steam.realm') ?: $request->getSchemeAndHttpHost(),
            'openid.identity' => self::IDENTIFIER_SELECT,
            'openid.claimed_id' => self::IDENTIFIER_SELECT,
        ];

        return redirect()->away(
            config('services.steam.openid_url').'?'.http_build_query($params, '', '&', PHP_QUERY_RFC3986)
        );
    }

    /**
     * Handle Steam's redirect back after the user authenticates (or cancels).
     */
    public function callback(Request $request): RedirectResponse
    {
        $expectedState = $request->session()->pull(self::STATE_SESSION_KEY);

        if (! is_string($expectedState) || $expectedState === ''
            || ! is_string($request->query('state'))
            || ! hash_equals($expectedState, $request->query('state'))) {
            Log::warning('Steam login: missing or mismatched state parameter.');

            return $this->redirectWithError('invalid_state');
        }

        if ($request->query('openid_mode') === 'cancel') {
            return $this->redirectWithError('cancelled');
        }

        $openIdParams = $this->extractOpenIdParams($request);

        if ($openIdParams === null) {
            Log::warning('Steam login: callback missing or malformed OpenID parameters.');

            return $this->redirectWithError('invalid_response');
        }

        try {
            $isValid = $this->validateWithSteam($openIdParams);
        } catch (Throwable $e) {
            Log::error('Steam login: verification request to Steam failed.', [
                'exception' => $e->getMessage(),
            ]);

            return $this->redirectWithError('steam_unavailable');
        }

        if (! $isValid) {
            Log::warning('Steam login: OpenID assertion failed Steam verification.');

            return $this->redirectWithError('validation_failed');
        }

        $steamId = $this->extractSteamId($openIdParams['openid.claimed_id']);

        if ($steamId === null) {
            Log::warning('Steam login: could not extract a valid SteamID64 from claimed_id.');

            return $this->redirectWithError('extraction_failed');
        }

        try {
            $user = $this->findOrCreateUser($steamId);
        } catch (Throwable $e) {
            Log::error('Steam login: failed to find or create local user.', [
                'exception' => $e->getMessage(),
            ]);

            return $this->redirectWithError('server_error');
        }

        $this->authenticate($request, $user);

        return $this->redirectToFrontend('success');
    }

    /**
     * Pull the openid.* parameters we need off the request, translated back
     * from PHP's underscore-mangled query keys to their real dotted names.
     *
     * @return array<string, string>|null
     */
    private function extractOpenIdParams(Request $request): ?array
    {
        $params = [];

        foreach (self::OPENID_FIELDS as $mangledKey => $realKey) {
            $value = $request->query($mangledKey);

            if (! is_string($value) || $value === '') {
                return null;
            }

            $params[$realKey] = $value;
        }

        if ($params['openid.mode'] !== 'id_res' || $params['openid.ns'] !== self::OPENID_NS) {
            return null;
        }

        return $params;
    }

    /**
     * Re-verify the assertion directly with Steam. This is what makes the
     * flow trustworthy — we never accept openid.claimed_id at face value.
     *
     * @param  array<string, string>  $openIdParams
     */
    private function validateWithSteam(array $openIdParams): bool
    {
        $verificationParams = $openIdParams;
        $verificationParams['openid.mode'] = 'check_authentication';

        $response = Http::asForm()
            ->timeout(10)
            ->post(config('services.steam.openid_url'), $verificationParams);

        if ($response->failed()) {
            throw new RuntimeException('Steam OpenID verification endpoint returned a failed HTTP response.');
        }

        return (bool) preg_match('/is_valid\s*:\s*true/i', $response->body());
    }

    /**
     * Extract and validate a SteamID64 from an already-verified claimed_id.
     */
    private function extractSteamId(string $claimedId): ?string
    {
        if (preg_match(self::CLAIMED_ID_PATTERN, $claimedId, $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    /**
     * Find the local user linked to this SteamID64, or create a new one.
     *
     * Steam-only accounts don't have a real email/password. A placeholder
     * email (unique per SteamID) and a random password hash are used to
     * satisfy the existing users table constraints without weakening them.
     */
    private function findOrCreateUser(string $steamId): User
    {
        return User::firstOrCreate(
            ['steam_id' => $steamId],
            [
                'name' => 'SteamUser'.$steamId,
                'email' => "steam-{$steamId}@steam.local",
                'password' => Str::password(32),
            ]
        );
    }

    /**
     * Log the user into the application's existing session-based auth guard.
     */
    private function authenticate(Request $request, User $user): void
    {
        $request->session()->regenerate();

        Auth::login($user, remember: true);
    }

    private function redirectToFrontend(string $status, ?string $reason = null): RedirectResponse
    {
        $query = ['status' => $status];

        if ($reason !== null) {
            $query['reason'] = $reason;
        }

        return redirect()->away(
            rtrim(config('app.frontend_url'), '/').'/auth/callback?'.http_build_query($query)
        );
    }

    private function redirectWithError(string $reason): RedirectResponse
    {
        return $this->redirectToFrontend('error', $reason);
    }
}
