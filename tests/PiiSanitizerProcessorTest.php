<?php

declare(strict_types=1);

namespace Dineshrao275\LogSanitizer\Tests;

use DateTimeImmutable;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;
use Dineshrao275\LogSanitizer\PiiSanitizerProcessor;

class PiiSanitizerProcessorTest extends TestCase
{
    private PiiSanitizerProcessor $processor;

    protected function setUp(): void
    {
        // Fresh processor instance before every test
        $this->processor = new PiiSanitizerProcessor();
    }

    // -------------------------------------------------------
    // Helper: quickly builds a LogRecord with given context
    // -------------------------------------------------------
    private function makeRecord(array $context): LogRecord
    {
        return new LogRecord(
            datetime: new DateTimeImmutable(),
            channel: 'test',
            level: Level::Debug,
            message: 'Test log message',
            context: $context
        );
    }

    // -------------------------------------------------------
    // Test 1: Default sensitive keys are redacted
    // -------------------------------------------------------
    public function test_it_redacts_default_sensitive_keys(): void
    {
        $record = $this->makeRecord([
            'username' => 'dinesh',
            'password' => 'super-secret-123',
            'token'    => 'eyJhbGciOiJIUzI1NiJ9',
            'api_key'  => 'sk-prod-abc123',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals('dinesh', $result->context['username']);      // Safe — untouched
        $this->assertEquals('[REDACTED]', $result->context['password']);  // Redacted
        $this->assertEquals('[REDACTED]', $result->context['token']);     // Redacted
        $this->assertEquals('[REDACTED]', $result->context['api_key']);   // Redacted
    }

    // -------------------------------------------------------
    // Test 2: Custom keys passed by the user are also redacted
    // -------------------------------------------------------
    public function test_it_redacts_custom_keys(): void
    {
        $processor = new PiiSanitizerProcessor(customKeys: ['otp', 'pin_code']);

        $record = $this->makeRecord([
            'otp'      => '482910',
            'pin_code' => '1234',
            'name'     => 'Dinesh',
        ]);

        $result = $processor($record);

        $this->assertEquals('[REDACTED]', $result->context['otp']);
        $this->assertEquals('[REDACTED]', $result->context['pin_code']);
        $this->assertEquals('Dinesh', $result->context['name']);
    }

    // -------------------------------------------------------
    // Test 3: Nested arrays are recursively sanitized
    // -------------------------------------------------------
    public function test_it_sanitizes_nested_arrays(): void
    {
        $record = $this->makeRecord([
            'user' => [
                'id'       => 42,
                'name'     => 'Dinesh',
                'credentials' => [
                    'password' => 'hidden!',
                    'token'    => 'abc.def.ghi',
                ],
            ],
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals(42, $result->context['user']['id']);
        $this->assertEquals('Dinesh', $result->context['user']['name']);
        $this->assertEquals('[REDACTED]', $result->context['user']['credentials']['password']);
        $this->assertEquals('[REDACTED]', $result->context['user']['credentials']['token']);
    }

    // -------------------------------------------------------
    // Test 4: Email addresses inside string values are redacted
    // -------------------------------------------------------
    public function test_it_redacts_emails_inside_string_values(): void
    {
        $record = $this->makeRecord([
            'message' => 'Contact the user at dinesh@example.com for support.',
            'bio'     => 'Email me at hello@test.org or admin@site.com',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals(
            'Contact the user at [REDACTED] for support.',
            $result->context['message']
        );
        $this->assertEquals(
            'Email me at [REDACTED] or [REDACTED]',
            $result->context['bio']
        );
    }

    // -------------------------------------------------------
    // Test 5: Empty context returns the record unchanged
    // -------------------------------------------------------
    public function test_it_handles_empty_context(): void
    {
        $record = $this->makeRecord([]);
        $result = ($this->processor)($record);

        $this->assertSame($record, $result);
    }

    // -------------------------------------------------------
    // Test 6: Custom mask string works correctly
    // -------------------------------------------------------
    public function test_it_uses_custom_mask_string(): void
    {
        $processor = new PiiSanitizerProcessor(mask: '***');

        $record = $this->makeRecord(['password' => 'secret']);
        $result = $processor($record);

        $this->assertEquals('***', $result->context['password']);
    }

    // -------------------------------------------------------
    // Test 7: Non-string values (int, bool, null) are untouched
    // -------------------------------------------------------
    public function test_it_does_not_alter_non_string_values(): void
    {
        $record = $this->makeRecord([
            'user_id'    => 7,
            'is_active'  => true,
            'last_login' => null,
        ]);

        $result = ($this->processor)($record);

        $this->assertSame(7, $result->context['user_id']);
        $this->assertSame(true, $result->context['is_active']);
        $this->assertNull($result->context['last_login']);
    }

    // -------------------------------------------------------
    // Test 8: getRedactedKeys() returns the merged key list
    // -------------------------------------------------------
    public function test_it_returns_redacted_keys_list(): void
    {
        $processor = new PiiSanitizerProcessor(customKeys: ['otp']);
        $keys = $processor->getRedactedKeys();

        $this->assertContains('password', $keys);
        $this->assertContains('otp', $keys);
    }
}