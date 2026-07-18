<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class LoginTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_log_in_with_normalized_credentials(): void
    {
        $user = User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);
        $passwordHash = $user->getRawOriginal('password');

        $response = $this->postLogin([
            'email' => '  NAKHOUL@EXAMPLE.COM  ',
            'password' => 'StrongPassword123!',
        ]);

        $response
            ->assertOk()
            ->assertJsonPath('data.id', $user->id)
            ->assertJsonPath('data.email', 'nakhoul@example.com')
            ->assertJsonMissingPath('data.password')
            ->assertJsonMissingPath('data.remember_token')
            ->assertJsonMissingPath('token')
            ->assertJsonMissingPath('data.token')
            ->assertJsonMissingPath('session_id')
            ->assertJsonMissingPath('csrf_token')
            ->assertHeaderMissing('Authorization');

        $this->assertAuthenticatedAs($user, 'web');
        $this->assertSame($passwordHash, $user->fresh()->getRawOriginal('password'));
        $this->assertTrue(Hash::check('StrongPassword123!', $passwordHash));
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_incorrect_password_and_unknown_email_return_the_same_error(): void
    {
        User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);

        $incorrectPassword = $this->postLogin([
            'email' => 'nakhoul@example.com',
            'password' => 'WrongPassword123!',
        ]);
        $unknownEmail = $this->postLogin([
            'email' => 'unknown@example.com',
            'password' => 'WrongPassword123!',
        ]);

        $incorrectPassword
            ->assertUnprocessable()
            ->assertExactJson($this->invalidCredentialsResponse());
        $unknownEmail
            ->assertUnprocessable()
            ->assertExactJson($this->invalidCredentialsResponse());

        $this->assertGuest('web');
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_login_fields_are_validated(): void
    {
        $this->postLogin([])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['email', 'password']);

        $this->postLogin([
            'email' => 'invalid-email',
            'password' => 'password',
        ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('email');

        $this->assertGuest('web');
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_spa_login_requires_a_valid_csrf_token(): void
    {
        $this->app['env'] = 'local';

        User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);

        $this->postLogin([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ])->assertStatus(419);

        $this->assertGuest('web');
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_repeated_failed_logins_are_rate_limited_by_normalized_email_and_ip(): void
    {
        User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);

        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $email = $attempt % 2 === 0
                ? '  NAKHOUL@EXAMPLE.COM  '
                : 'nakhoul@example.com';

            $this->postLogin([
                'email' => $email,
                'password' => 'WrongPassword123!',
            ], '192.0.2.20')->assertUnprocessable();
        }

        $this->postLogin([
            'email' => 'nakhoul@example.com',
            'password' => 'WrongPassword123!',
        ], '192.0.2.20')
            ->assertTooManyRequests()
            ->assertJsonMissing(['email' => 'nakhoul@example.com']);

        $this->assertGuest('web');
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_successful_login_clears_failed_attempts(): void
    {
        User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);

        for ($attempt = 1; $attempt <= 4; $attempt++) {
            $this->postLogin([
                'email' => 'nakhoul@example.com',
                'password' => 'WrongPassword123!',
            ], '192.0.2.30')->assertUnprocessable();
        }

        $this->postLogin([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ], '192.0.2.30')->assertOk();

        Auth::guard('web')->logout();

        for ($attempt = 1; $attempt <= 2; $attempt++) {
            $this->postLogin([
                'email' => 'nakhoul@example.com',
                'password' => 'WrongPassword123!',
            ], '192.0.2.30')->assertUnprocessable();
        }
    }

    public function test_login_regenerates_and_persists_an_authenticated_database_session(): void
    {
        config()->set('session.driver', 'database');
        $this->app['session']->forgetDrivers();
        $this->app['router']
            ->get('/api/login-test-user', fn () => ['id' => Auth::guard('web')->id()])
            ->middleware(['api', 'auth:sanctum']);

        $user = User::factory()->create([
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
        ]);

        $csrfResponse = $this
            ->withHeaders($this->spaHeaders())
            ->get('/sanctum/csrf-cookie');

        $csrfResponse
            ->assertNoContent()
            ->assertCookie('XSRF-TOKEN')
            ->assertCookie(config('session.cookie'));

        $originalSessionId = DB::table('sessions')->sole()->id;
        $sessionCookie = $csrfResponse->getCookie(config('session.cookie'))->getValue();
        $csrfToken = urldecode($csrfResponse->getCookie('XSRF-TOKEN', false)->getValue());

        $this->app['env'] = 'local';

        $response = $this
            ->withCookie(config('session.cookie'), $sessionCookie)
            ->withUnencryptedCookie('XSRF-TOKEN', $csrfToken)
            ->withHeader('X-XSRF-TOKEN', $csrfToken)
            ->postLogin([
                'email' => 'nakhoul@example.com',
                'password' => 'StrongPassword123!',
            ]);

        $response
            ->assertOk()
            ->assertCookie(config('session.cookie'));

        $authenticatedSessionId = $response->getCookie(config('session.cookie'))->getValue();

        $this->assertNotSame($originalSessionId, $authenticatedSessionId);
        $this->assertDatabaseMissing('sessions', ['id' => $originalSessionId]);
        $this->assertDatabaseHas('sessions', ['user_id' => $user->id]);
        $this->assertDatabaseCount('personal_access_tokens', 0);

        $this
            ->withCookie(config('session.cookie'), $authenticatedSessionId)
            ->withCredentials()
            ->withHeaders($this->spaHeaders())
            ->getJson('/api/login-test-user')
            ->assertOk()
            ->assertJsonPath('id', $user->id);
    }

    private function postLogin(array $payload, string $ip = '192.0.2.10')
    {
        return $this
            ->withCredentials()
            ->withHeaders($this->spaHeaders())
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->postJson('/api/login', $payload);
    }

    private function spaHeaders(): array
    {
        return [
            'Origin' => 'http://localhost:5173',
            'Referer' => 'http://localhost:5173/',
        ];
    }

    private function invalidCredentialsResponse(): array
    {
        return [
            'message' => 'The provided credentials are incorrect.',
            'errors' => [
                'email' => ['The provided credentials are incorrect.'],
            ],
        ];
    }
}
