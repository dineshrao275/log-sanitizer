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
        $this->processor = new PiiSanitizerProcessor();
    }

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

    public function test_it_redacts_default_sensitive_keys(): void
    {
        $record = $this->makeRecord([
            'username' => 'dinesh',
            'password' => 'super-secret-123',
            'token'    => 'eyJhbGciOiJIUzI1NiJ9',
            'api_key'  => 'sk-prod-abc123',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals('dinesh', $result->context['username']);
        $this->assertEquals('[REDACTED]', $result->context['password']);
        $this->assertEquals('[REDACTED]', $result->context['token']);
        $this->assertEquals('[REDACTED]', $result->context['api_key']);
    }

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

    public function test_it_handles_empty_context(): void
    {
        $record = $this->makeRecord([]);
        $result = ($this->processor)($record);

        $this->assertSame($record, $result);
    }

    public function test_it_uses_custom_mask_string(): void
    {
        $processor = new PiiSanitizerProcessor(mask: '***');

        $record = $this->makeRecord(['password' => 'secret']);
        $result = $processor($record);

        $this->assertEquals('***', $result->context['password']);
    }

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

    public function test_it_returns_redacted_keys_list(): void
    {
        $processor = new PiiSanitizerProcessor(customKeys: ['otp']);
        $keys = $processor->getRedactedKeys();

        $this->assertContains('password', $keys);
        $this->assertContains('otp', $keys);
    }

    public function test_it_redacts_sensitive_key_with_integer_value(): void
    {
        $record = $this->makeRecord(['password' => 123456]);
        $result = ($this->processor)($record);

        $this->assertEquals('[REDACTED]', $result->context['password']);
    }

    public function test_it_redacts_sensitive_key_with_boolean_value(): void
    {
        $record = $this->makeRecord(['secret' => true]);
        $result = ($this->processor)($record);

        $this->assertEquals('[REDACTED]', $result->context['secret']);
    }

    public function test_it_redacts_sensitive_key_with_null_value(): void
    {
        $record = $this->makeRecord(['token' => null]);
        $result = ($this->processor)($record);

        $this->assertEquals('[REDACTED]', $result->context['token']);
    }

    public function test_it_redacts_new_default_keys(): void
    {
        $record = $this->makeRecord([
            'authorization' => 'Bearer sk-1234',
            'jwt'           => 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
            'otp'           => '482910',
            'pin'           => '1234',
            'email'         => 'user@example.com',
            'phone'         => '+1234567890',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals('[REDACTED]', $result->context['authorization']);
        $this->assertEquals('[REDACTED]', $result->context['jwt']);
        $this->assertEquals('[REDACTED]', $result->context['otp']);
        $this->assertEquals('[REDACTED]', $result->context['pin']);
        $this->assertEquals('[REDACTED]', $result->context['email']);
        $this->assertEquals('[REDACTED]', $result->context['phone']);
    }

    public function test_it_validates_credit_cards_with_luhn(): void
    {
        $record = $this->makeRecord([
            'note' => 'My card is 4111111111111111 and it expires soon.',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals(
            'My card is [REDACTED] and it expires soon.',
            $result->context['note']
        );
    }

    public function test_it_does_not_redact_invalid_card_numbers(): void
    {
        $record = $this->makeRecord([
            'note' => 'Order id 4111111111111112 should not be redacted.',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals(
            'Order id 4111111111111112 should not be redacted.',
            $result->context['note']
        );
    }

    public function test_it_does_not_redact_random_long_numbers(): void
    {
        $record = $this->makeRecord([
            'note' => 'Reference 1234567890123456 is not a valid card.',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals(
            'Reference 1234567890123456 is not a valid card.',
            $result->context['note']
        );
    }

    public function test_it_handles_email_edge_cases(): void
    {
        $record = $this->makeRecord([
            'msg' => 'user+tag@example.com and a@b.co are emails.',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals(
            '[REDACTED] and [REDACTED] are emails.',
            $result->context['msg']
        );
    }

    public function test_it_handles_nested_mixed_arrays(): void
    {
        $record = $this->makeRecord([
            'data' => [
                'user' => [
                    'password' => 123456,
                    'profile' => [
                        'email' => 'test@example.com',
                    ],
                ],
                'meta' => [
                    'session_id' => null,
                    'ip'         => '127.0.0.1',
                ],
            ],
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals('[REDACTED]', $result->context['data']['user']['password']);
        $this->assertEquals('[REDACTED]', $result->context['data']['user']['profile']['email']);
        $this->assertEquals('[REDACTED]', $result->context['data']['meta']['session_id']);
        $this->assertEquals('127.0.0.1', $result->context['data']['meta']['ip']);
    }

    public function test_it_uses_custom_mask_with_pattern_redaction(): void
    {
        $processor = new PiiSanitizerProcessor(mask: '***');

        $record = $this->makeRecord([
            'note'     => 'Email: user@example.com',
            'password' => 'secret',
        ]);

        $result = $processor($record);

        $this->assertEquals('Email: ***', $result->context['note']);
        $this->assertEquals('***', $result->context['password']);
    }

    public function test_it_respects_disabled_email_redaction(): void
    {
        $processor = new PiiSanitizerProcessor(redactEmails: false);

        $record = $this->makeRecord([
            'note' => 'Contact user@example.com',
        ]);

        $result = $processor($record);

        $this->assertEquals('Contact user@example.com', $result->context['note']);
    }

    public function test_it_respects_disabled_credit_card_redaction(): void
    {
        $processor = new PiiSanitizerProcessor(redactCreditCards: false);

        $record = $this->makeRecord([
            'note' => 'Card: 4111111111111111',
        ]);

        $result = $processor($record);

        $this->assertEquals('Card: 4111111111111111', $result->context['note']);
    }

    public function test_it_preserves_log_record_immutability(): void
    {
        $record = $this->makeRecord([
            'password' => 'secret',
            'name'     => 'Dinesh',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals('secret', $record->context['password']);
        $this->assertEquals('[REDACTED]', $result->context['password']);
    }

    public function test_it_handles_credit_cards_with_spaces_and_dashes(): void
    {
        $record = $this->makeRecord([
            'note' => 'Card: 4111-1111-1111-1111 and 4111 1111 1111 1111',
        ]);

        $result = ($this->processor)($record);

        $this->assertEquals(
            'Card: [REDACTED] and [REDACTED]',
            $result->context['note']
        );
    }
}
