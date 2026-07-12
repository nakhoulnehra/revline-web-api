<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class RegistrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_register_without_being_authenticated(): void
    {
        $response = $this->postJson('/api/register', $this->validPayload());

        $response
            ->assertCreated()
            ->assertJsonPath('data.name', 'Nakhoul Nehra')
            ->assertJsonPath('data.email', 'nakhoul@example.com')
            ->assertJsonPath('data.email_verified_at', null)
            ->assertJsonMissingPath('data.password')
            ->assertJsonMissingPath('data.remember_token')
            ->assertHeaderMissing('Authorization');

        $user = User::sole();

        $this->assertNotSame('StrongPassword123!', $user->getRawOriginal('password'));
        $this->assertTrue(Hash::check('StrongPassword123!', $user->getRawOriginal('password')));
        $this->assertNull($user->email_verified_at);
        $this->assertGuest();
        $this->assertDatabaseCount('sessions', 0);
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_registration_normalizes_email_and_rejects_case_insensitive_duplicates(): void
    {
        User::factory()->create(['email' => 'nakhoul@example.com']);

        $response = $this->postJson('/api/register', $this->validPayload([
            'email' => '  NAKHOUL@EXAMPLE.COM  ',
        ]));

        $response
            ->assertUnprocessable()
            ->assertJsonValidationErrors('email');

        $this->assertDatabaseCount('users', 1);
    }

    public function test_invalid_email_does_not_create_a_user(): void
    {
        $this->postJson('/api/register', $this->validPayload(['email' => 'invalid-email']))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('email');

        $this->assertDatabaseCount('users', 0);
    }

    public function test_password_must_be_confirmed(): void
    {
        $this->postJson('/api/register', $this->validPayload([
            'password_confirmation' => 'DifferentPassword123!',
        ]))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('password');

        $this->assertDatabaseCount('users', 0);
    }

    public function test_required_fields_are_validated(): void
    {
        $this->postJson('/api/register', [])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['name', 'email', 'password']);

        $this->assertDatabaseCount('users', 0);
    }

    public function test_registration_is_limited_to_five_attempts_per_minute_per_ip(): void
    {
        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $this
                ->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])
                ->postJson('/api/register', $this->validPayload([
                    'email' => "user{$attempt}@example.com",
                ]))
                ->assertCreated();
        }

        $this
            ->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])
            ->postJson('/api/register', $this->validPayload([
                'email' => 'user6@example.com',
            ]))
            ->assertTooManyRequests();

        $this->assertDatabaseCount('users', 5);
        $this->assertDatabaseMissing('users', ['email' => 'user6@example.com']);
    }

    private function validPayload(array $overrides = []): array
    {
        return array_merge([
            'name' => 'Nakhoul Nehra',
            'email' => 'nakhoul@example.com',
            'password' => 'StrongPassword123!',
            'password_confirmation' => 'StrongPassword123!',
        ], $overrides);
    }
}
