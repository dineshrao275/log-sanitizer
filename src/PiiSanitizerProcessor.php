<?php

declare(strict_types=1);

namespace Dineshrao275\LogSanitizer;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

class PiiSanitizerProcessor implements ProcessorInterface
{
    /**
     * Default sensitive key names to redact by key matching.
     */
    private array $defaultKeys = [
        'password',
        'password_confirmation',
        'secret',
        'token',
        'api_key',
        'auth_key',
        'access_token',
        'refresh_token',
        'cvv',
        'cc_number',
        'card_number',
        'ssn',
        'social_security',
        'private_key',
        'client_secret',
        'authorization',
        'bearer',
        'session',
        'session_id',
        'cookie',
        'set_cookie',
        'csrf_token',
        'id_token',
        'jwt',
        'passcode',
        'pin',
        'otp',
        'phone',
        'email',
    ];

    private array $keysToRedact;
    private string $mask;
    private bool $redactEmails;
    private bool $redactCreditCards;

    /**
     * Regex pattern to detect email addresses inside string values.
     */
    private string $emailPattern = '/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/';

    /**
     * Regex pattern to detect credit card numbers (Visa, MasterCard, Amex, etc.)
     */
    private string $creditCardPattern = '/\b(?:\d[ \-]?){12,15}\d\b/';

    /**
     * @param array  $customKeys     Additional keys to redact beyond defaults
     * @param string $mask           The string to replace sensitive values with
     * @param bool   $redactEmails   Whether to scan string values for email patterns
     * @param bool   $redactCreditCards Whether to scan string values for credit card patterns
     */
    public function __construct(
        array $customKeys = [],
        string $mask = '[REDACTED]',
        bool $redactEmails = true,
        bool $redactCreditCards = true
    ) {
        $this->keysToRedact = array_map(
            'strtolower',
            array_unique(array_merge($this->defaultKeys, $customKeys))
        );
        $this->mask = $mask;
        $this->redactEmails = $redactEmails;
        $this->redactCreditCards = $redactCreditCards;
    }

    /**
     * Invoked by Monolog before writing each log record.
     */
    public function __invoke(LogRecord $record): LogRecord
    {
        if (empty($record->context)) {
            return $record;
        }

        return $record->with(context: $this->sanitizeArray($record->context));
    }

    /**
     * Recursively walks through any nested array and sanitizes values.
     */
    private function sanitizeArray(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->sanitizeArray($value);
            } elseif ($this->isKeySensitive($key)) {
                $data[$key] = $this->mask;
            } elseif (is_string($value)) {
                $data[$key] = $this->sanitizeStringValue($value);
            }
        }

        return $data;
    }

    private function isKeySensitive(string|int $key): bool
    {
        return in_array(strtolower((string) $key), $this->keysToRedact, true);
    }

    /**
     * Applies regex patterns to scrub sensitive patterns inside string values.
     */
    private function sanitizeStringValue(string $value): string
    {
        if ($this->redactEmails) {
            $value = preg_replace($this->emailPattern, $this->mask, $value);
        }

        if ($this->redactCreditCards) {
            $value = preg_replace_callback(
                $this->creditCardPattern,
                fn (array $matches): string => $this->luhnCheck(preg_replace('/[ \-]/', '', $matches[0]))
                    ? $this->mask
                    : $matches[0],
                $value
            );
        }

        return $value;
    }

    private function luhnCheck(string $number): bool
    {
        if (!ctype_digit($number)) {
            return false;
        }

        $sum = 0;
        $alt = false;
        for ($i = strlen($number) - 1; $i >= 0; $i--) {
            $digit = (int) $number[$i];
            if ($alt) {
                $digit *= 2;
                if ($digit > 9) {
                    $digit -= 9;
                }
            }
            $sum += $digit;
            $alt = !$alt;
        }

        return $sum % 10 === 0;
    }

    /**
     * Returns the final merged list of keys being redacted.
     * Useful for debugging your configuration.
     */
    public function getRedactedKeys(): array
    {
        return $this->keysToRedact;
    }
}