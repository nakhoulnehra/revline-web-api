<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class AuthenticationSchemaTest extends TestCase
{
    use RefreshDatabase;

    public function test_authentication_tables_migrate_on_an_empty_database(): void
    {
        $this->assertSame(
            ['id', 'name', 'email', 'email_verified_at', 'password', 'remember_token', 'created_at', 'updated_at'],
            Schema::getColumnListing('users'),
        );
        $this->assertSame(
            ['email', 'token', 'created_at'],
            Schema::getColumnListing('password_reset_tokens'),
        );
        $this->assertSame(
            ['id', 'user_id', 'ip_address', 'user_agent', 'payload', 'last_activity'],
            Schema::getColumnListing('sessions'),
        );
        $this->assertSame(
            ['id', 'tokenable_type', 'tokenable_id', 'name', 'token', 'abilities', 'last_used_at', 'expires_at', 'created_at', 'updated_at'],
            Schema::getColumnListing('personal_access_tokens'),
        );
        $this->assertSame(
            ['key', 'value', 'expiration'],
            Schema::getColumnListing('cache'),
        );
        $this->assertSame(
            ['key', 'owner', 'expiration'],
            Schema::getColumnListing('cache_locks'),
        );
    }

    public function test_authentication_indexes_and_constraints_are_present(): void
    {
        $this->assertTrue(Schema::hasIndex('users', ['email'], 'unique'));
        $this->assertTrue(Schema::hasIndex('password_reset_tokens', ['email'], 'primary'));
        $this->assertTrue(Schema::hasIndex('sessions', ['user_id']));
        $this->assertTrue(Schema::hasIndex('sessions', ['last_activity']));
        $this->assertSame([], Schema::getForeignKeys('sessions'));
        $this->assertTrue(Schema::hasIndex('personal_access_tokens', ['tokenable_type', 'tokenable_id']));
        $this->assertTrue(Schema::hasIndex('personal_access_tokens', ['token'], 'unique'));
        $this->assertTrue(Schema::hasIndex('personal_access_tokens', ['expires_at']));
        $this->assertTrue(Schema::hasIndex('cache', ['key'], 'primary'));
        $this->assertTrue(Schema::hasIndex('cache', ['expiration']));
        $this->assertTrue(Schema::hasIndex('cache_locks', ['key'], 'primary'));
        $this->assertTrue(Schema::hasIndex('cache_locks', ['expiration']));
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }
}
