<?php

declare(strict_types=1);

namespace Dineshrao275\LogSanitizer;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

class PiiSanitizerProcessor implements ProcessorInterface
{
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
    private array $exceptKeys;
    private string $mask;
    private bool $redactEmails;
    private bool $redactCreditCards;
    private string $matchMode;
    private bool $partialMasking;

    private string $emailPattern = '/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/';

    private string $creditCardPattern = '/\b(?:\d[ \-]?){12,15}\d\b/';

    public function __construct(
        array|SanitizerConfig $customKeys = [],
        string $mask = '[REDACTED]',
        bool $redactEmails = true,
        bool $redactCreditCards = true,
    ) {
        if ($customKeys instanceof SanitizerConfig) {
            $config = $customKeys;
        } else {
            $config = new SanitizerConfig(
                customKeys: $customKeys,
                mask: $mask,
                redactEmails: $redactEmails,
                redactCreditCards: $redactCreditCards,
            );
        }

        $this->keysToRedact = array_map(
            fn(string $key): string => $this->normalizeKey($key),
            array_unique(array_merge($this->defaultKeys, $config->getCustomKeys()))
        );
        $this->exceptKeys = array_map(
            fn(string $key): string => $this->normalizeKey($key),
            $config->getExceptKeys()
        );
        $this->mask = $config->getMask();
        $this->redactEmails = $config->shouldRedactEmails();
        $this->redactCreditCards = $config->shouldRedactCreditCards();
        $this->matchMode = $config->getMatchMode();
        $this->partialMasking = $config->isPartialMasking();
    }

    public function __invoke(LogRecord $record): LogRecord
    {
        if (empty($record->context)) {
            return $record;
        }

        return $record->with(context: $this->sanitizeArray($record->context));
    }

    private function sanitizeArray(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->sanitizeArray($value);
            } elseif ($this->isKeyExcluded($key)) {
                continue;
            } elseif ($this->isKeySensitive($key)) {
                $data[$key] = $this->maskValue($value);
            } elseif (is_string($value)) {
                $data[$key] = $this->sanitizeStringValue($value);
            }
        }

        return $data;
    }

    private function normalizeKey(string $key): string
    {
        $key = preg_replace('/([a-z])([A-Z])/', '$1_$2', $key);
        $key = str_replace('-', '_', $key);
        return strtolower($key);
    }

    private function isKeyExcluded(string|int $key): bool
    {
        return in_array($this->normalizeKey((string) $key), $this->exceptKeys, true);
    }

    private function isKeySensitive(string|int $key): bool
    {
        $key = $this->normalizeKey((string) $key);

        if ($this->matchMode === 'contains') {
            foreach ($this->keysToRedact as $sensitiveKey) {
                if (str_contains($key, $sensitiveKey)) {
                    return true;
                }
            }
            return false;
        }

        return in_array($key, $this->keysToRedact, true);
    }

    private function maskValue(mixed $value): string
    {
        if ($this->partialMasking && is_string($value)) {
            return $this->partialMaskValue($value);
        }
        return $this->mask;
    }

    private function sanitizeStringValue(string $value): string
    {
        if ($this->redactEmails) {
            if ($this->partialMasking) {
                $value = preg_replace_callback(
                    $this->emailPattern,
                    fn(array $m): string => $this->partialMaskEmail($m[0]),
                    $value
                );
            } else {
                $value = preg_replace($this->emailPattern, $this->mask, $value);
            }
        }

        if ($this->redactCreditCards) {
            $value = preg_replace_callback(
                $this->creditCardPattern,
                function (array $matches): string {
                    $digits = preg_replace('/[ \-]/', '', $matches[0]);
                    if (!$this->luhnCheck($digits)) {
                        return $matches[0];
                    }
                    return $this->partialMasking
                        ? $this->partialMaskCard($matches[0])
                        : $this->mask;
                },
                $value
            );
        }

        return $value;
    }

    private function partialMaskValue(string $value): string
    {
        if (str_contains($value, '@') && preg_match($this->emailPattern, $value)) {
            return preg_replace_callback(
                $this->emailPattern,
                fn(array $m): string => $this->partialMaskEmail($m[0]),
                $value
            );
        }

        $clean = preg_replace('/[ \-]/', '', $value);
        if (ctype_digit($clean) && strlen($clean) >= 13 && strlen($clean) <= 16 && $this->luhnCheck($clean)) {
            return $this->partialMaskCard($value);
        }

        if (strlen($value) > 6) {
            return substr($value, 0, 2) . str_repeat('*', strlen($value) - 4) . substr($value, -2);
        }

        return $this->mask;
    }

    private function partialMaskEmail(string $email): string
    {
        $atPos = strpos($email, '@');
        if ($atPos === false || $atPos === 0) {
            return $email;
        }
        $name = substr($email, 0, $atPos);
        $domain = substr($email, $atPos);
        return $name[0] . str_repeat('*', max(3, strlen($name) - 1)) . $domain;
    }

    private function partialMaskCard(string $card): string
    {
        $digits = preg_replace('/[ \-]/', '', $card);
        $last4 = substr($digits, -4);
        $masked = str_repeat('*', strlen($digits) - 4) . $last4;

        $result = '';
        $idx = 0;
        for ($i = 0; $i < strlen($card); $i++) {
            if (ctype_digit($card[$i])) {
                $result .= $masked[$idx];
                $idx++;
            } else {
                $result .= $card[$i];
            }
        }
        return $result;
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

    public function getRedactedKeys(): array
    {
        return $this->keysToRedact;
    }
}
