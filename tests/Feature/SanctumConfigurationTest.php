<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful;
use Tests\TestCase;

class SanctumConfigurationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set([
            'app.frontend_url' => 'http://localhost:5173',
            'cors.allowed_origins' => ['http://localhost:5173'],
            'sanctum.stateful' => ['localhost:5173'],
            'session.driver' => 'database',
        ]);
    }

    public function test_api_routes_and_stateful_middleware_are_registered(): void
    {
        $bootstrap = file_get_contents(base_path('bootstrap/app.php'));

        $this->assertFileExists(base_path('routes/api.php'));
        $this->assertStringContainsString("api: __DIR__.'/../routes/api.php'", $bootstrap);
        $this->assertContains(
            EnsureFrontendRequestsAreStateful::class,
            $this->app['router']->getMiddlewareGroups()['api'],
        );
    }

    public function test_session_and_cors_configuration_supports_the_frontend(): void
    {
        $this->assertSame('database', config('session.driver'));
        $this->assertSame(120, config('session.lifetime'));
        $this->assertTrue(config('session.http_only'));
        $this->assertFalse(config('session.secure'));
        $this->assertSame('lax', config('session.same_site'));
        $this->assertContains(config('session.domain'), [null, '']);
        $this->assertTrue(config('cors.supports_credentials'));
        $this->assertSame(['http://localhost:5173'], config('cors.allowed_origins'));
        $this->assertNotContains('*', config('cors.allowed_origins'));
        $this->assertNotContains('https://unapproved.example', config('cors.allowed_origins'));
    }

    public function test_csrf_cookie_endpoint_uses_database_sessions_without_creating_tokens(): void
    {
        $response = $this
            ->withHeader('Origin', 'http://localhost:5173')
            ->get('/sanctum/csrf-cookie');

        $response
            ->assertNoContent()
            ->assertHeader('Access-Control-Allow-Origin', 'http://localhost:5173')
            ->assertHeader('Access-Control-Allow-Credentials', 'true')
            ->assertHeaderMissing('Authorization')
            ->assertCookie('XSRF-TOKEN')
            ->assertCookie(config('session.cookie'));

        $this->assertSame('', $response->getContent());
        $this->assertDatabaseCount('sessions', 1);
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_unapproved_origins_are_not_approved_by_cors(): void
    {
        $response = $this
            ->withHeader('Origin', 'https://unapproved.example')
            ->get('/sanctum/csrf-cookie');

        $response->assertNoContent();
        $this->assertNotSame(
            'https://unapproved.example',
            $response->headers->get('Access-Control-Allow-Origin'),
        );
    }

    public function test_existing_health_route_remains_functional(): void
    {
        $this->get('/up')->assertOk();
    }
}
