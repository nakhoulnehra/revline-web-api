<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

class AuthenticatedSessionTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('session.driver', 'database');
        $this->app['session']->forgetDrivers();
        $this->app['env'] = 'local';
    }

    public function test_authenticated_user_can_be_retrieved_through_the_safe_resource(): void
    {
        $user = User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);
        $browser = $this->loginBrowser($user);

        $this->asBrowser($browser)
            ->getJson('/api/user')
            ->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'email',
                    'email_verified_at',
                    'created_at',
                    'updated_at',
                ],
            ])
            ->assertJsonPath('data.id', $user->id)
            ->assertJsonPath('data.email', 'nakhoul@example.com')
            ->assertJsonMissingPath('data.password')
            ->assertJsonMissingPath('data.remember_token')
            ->assertJsonMissingPath('data.session')
            ->assertJsonMissingPath('data.token')
            ->assertHeaderMissing('Authorization');

        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_unauthenticated_user_and_logout_requests_return_json_unauthorized_responses(): void
    {
        $this->withHeaders($this->spaHeaders())
            ->getJson('/api/user')
            ->assertUnauthorized()
            ->assertExactJson(['message' => 'Unauthenticated.']);

        $this->resetBrowserCookies();

        $csrfResponse = $this
            ->withHeaders($this->spaHeaders())
            ->get('/sanctum/csrf-cookie');
        $browser = [
            'session_id' => $csrfResponse->getCookie(config('session.cookie'))->getValue(),
            'csrf_token' => urldecode($csrfResponse->getCookie('XSRF-TOKEN', false)->getValue()),
            'ip' => '192.0.2.10',
        ];

        $this->asBrowser($browser)
            ->withHeader('X-XSRF-TOKEN', $browser['csrf_token'])
            ->postJson('/api/logout')
            ->assertUnauthorized()
            ->assertExactJson(['message' => 'Unauthenticated.']);
    }

    public function test_spa_user_can_complete_login_user_logout_flow(): void
    {
        $user = User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);
        $browser = $this->loginBrowser($user);

        $this->assertDatabaseHas('sessions', [
            'id' => $browser['session_id'],
            'user_id' => $user->id,
        ]);

        $this->asBrowser($browser)
            ->getJson('/api/user')
            ->assertOk()
            ->assertJsonPath('data.id', $user->id);

        $logoutResponse = $this->asBrowser($browser)
            ->withHeader('X-XSRF-TOKEN', $browser['csrf_token'])
            ->postJson('/api/logout');

        $logoutResponse
            ->assertNoContent()
            ->assertCookie('XSRF-TOKEN');

        $newCsrfToken = urldecode($logoutResponse->getCookie('XSRF-TOKEN', false)->getValue());

        $this->assertNotSame($browser['csrf_token'], $newCsrfToken);
        $this->assertDatabaseMissing('sessions', ['id' => $browser['session_id']]);

        $this->asBrowser($browser)
            ->getJson('/api/user')
            ->assertUnauthorized()
            ->assertExactJson(['message' => 'Unauthenticated.']);

        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_logout_invalidates_only_the_current_browser_session(): void
    {
        $user = User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);
        $firstBrowser = $this->loginBrowser($user, '192.0.2.10');
        $secondBrowser = $this->loginBrowser($user, '192.0.2.11');

        $this->assertNotSame($firstBrowser['session_id'], $secondBrowser['session_id']);
        $this->assertSame(2, DB::table('sessions')->where('user_id', $user->id)->count());

        $this->asBrowser($firstBrowser)
            ->withHeader('X-XSRF-TOKEN', $firstBrowser['csrf_token'])
            ->postJson('/api/logout')
            ->assertNoContent();

        $this->assertDatabaseMissing('sessions', ['id' => $firstBrowser['session_id']]);
        $this->assertDatabaseHas('sessions', [
            'id' => $secondBrowser['session_id'],
            'user_id' => $user->id,
        ]);

        $this->asBrowser($firstBrowser)
            ->getJson('/api/user')
            ->assertUnauthorized();

        $this->asBrowser($secondBrowser)
            ->getJson('/api/user')
            ->assertOk()
            ->assertJsonPath('data.id', $user->id);

        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    private function loginBrowser(User $user, string $ip = '192.0.2.10'): array
    {
        $this->resetBrowserCookies();

        $csrfResponse = $this
            ->withHeaders($this->spaHeaders())
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->get('/sanctum/csrf-cookie');

        $sessionCookie = $csrfResponse->getCookie(config('session.cookie'))->getValue();
        $csrfToken = urldecode($csrfResponse->getCookie('XSRF-TOKEN', false)->getValue());

        $loginResponse = $this
            ->withCookie(config('session.cookie'), $sessionCookie)
            ->withUnencryptedCookie('XSRF-TOKEN', $csrfToken)
            ->withHeader('X-XSRF-TOKEN', $csrfToken)
            ->withHeaders($this->spaHeaders())
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->postJson('/api/login', [
                'email' => $user->email,
                'password' => 'StrongPassword123!',
            ]);

        $loginResponse->assertOk();

        $authenticatedCsrfToken = urldecode(
            $loginResponse->getCookie('XSRF-TOKEN', false)->getValue(),
        );

        return [
            'session_id' => $loginResponse->getCookie(config('session.cookie'))->getValue(),
            'csrf_token' => $authenticatedCsrfToken,
            'ip' => $ip,
        ];
    }

    private function asBrowser(array $browser): static
    {
        $this->resetBrowserCookies();

        return $this
            ->withCookie(config('session.cookie'), $browser['session_id'])
            ->withUnencryptedCookie('XSRF-TOKEN', $browser['csrf_token'])
            ->withCredentials()
            ->withHeaders($this->spaHeaders())
            ->withServerVariables(['REMOTE_ADDR' => $browser['ip']]);
    }

    private function resetBrowserCookies(): void
    {
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];
        $this->flushHeaders();
        Auth::forgetGuards();
    }

    private function spaHeaders(): array
    {
        return [
            'Origin' => 'http://localhost:5173',
            'Referer' => 'http://localhost:5173/',
        ];
    }
}
