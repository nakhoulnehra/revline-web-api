<?php

namespace Tests\Feature;

use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class UserModelTest extends TestCase
{
    use RefreshDatabase;

    public function test_plaintext_passwords_are_stored_as_bcrypt_hashes(): void
    {
        $user = User::create([
            'name' => 'Test User',
            'email' => 'user@example.com',
            'password' => 'correct-password',
        ]);

        $storedPassword = $user->getRawOriginal('password');

        $this->assertNotSame('correct-password', $storedPassword);
        $this->assertSame('bcrypt', Hash::info($storedPassword)['algoName']);
        $this->assertTrue(Hash::check('correct-password', $storedPassword));
        $this->assertFalse(Hash::check('incorrect-password', $storedPassword));
    }

    public function test_user_serialization_hides_sensitive_attributes(): void
    {
        $user = User::create([
            'name' => 'Test User',
            'email' => 'user@example.com',
            'password' => 'correct-password',
        ]);
        $user->setRememberToken('remember-token');
        $user->save();

        $serialized = $user->fresh()->toArray();

        $this->assertArrayNotHasKey('password', $serialized);
        $this->assertArrayNotHasKey('remember_token', $serialized);
    }

    public function test_user_resource_exposes_only_safe_attributes(): void
    {
        $user = User::create([
            'name' => 'Test User',
            'email' => 'user@example.com',
            'password' => 'correct-password',
        ]);

        $resource = (new UserResource($user->fresh()))->resolve();

        $this->assertSame([
            'id',
            'name',
            'email',
            'email_verified_at',
            'created_at',
            'updated_at',
        ], array_keys($resource));
    }

    public function test_user_requires_email_verification(): void
    {
        $this->assertInstanceOf(MustVerifyEmail::class, new User);
    }
}
