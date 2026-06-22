# log-sanitizer

A lightweight, zero-config Monolog processor that automatically redacts PII and sensitive data (passwords, tokens, emails, credit cards) from your PHP application logs. GDPR-friendly.

## Installation

```bash
composer require dineshrao275/log-sanitizer
```

## Requirements

- PHP 8.2+
- monolog/monolog ^3.0

## Quick Start

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Dineshrao275\LogSanitizer\PiiSanitizerProcessor;

$log = new Logger('app');
$log->pushHandler(new StreamHandler('app.log', \Monolog\Level::Debug));
$log->pushProcessor(new PiiSanitizerProcessor());

$log->info('User login', [
    'username' => 'dinesh',
    'password' => 'secret123',
]);
// password → [REDACTED]
```

## Configuration

### Legacy constructor

```php
$processor = new PiiSanitizerProcessor(
    customKeys:        ['otp', 'pin'],
    mask:              '***',
    redactEmails:      true,
    redactCreditCards: true
);
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `customKeys` | `array` | `[]` | Additional key names to redact beyond defaults |
| `mask` | `string` | `'[REDACTED]'` | Replacement string for redacted values |
| `redactEmails` | `bool` | `true` | Scan string values for email patterns |
| `redactCreditCards` | `bool` | `true` | Scan string values for credit card numbers (Luhn-validated) |

### SanitizerConfig (recommended for advanced use)

```php
use Dineshrao275\LogSanitizer\SanitizerConfig;

$config = SanitizerConfig::default()
    ->withCustomKeys(['otp', 'pin'])
    ->withMask('***')
    ->withoutEmailRedaction()
    ->withoutCreditCardRedaction()
    ->withMatchMode('contains')
    ->withExceptKeys(['email_template'])
    ->withPartialMasking();

$processor = new PiiSanitizerProcessor($config);
```

| Method | Default | Description |
|--------|---------|-------------|
| `withCustomKeys(array)` | `[]` | Additional key names to redact |
| `withMask(string)` | `'[REDACTED]'` | Replacement string |
| `withPartialMasking()` | `false` | Show partial values instead of full mask |
| `withFullMasking()` | `true` | Full mask replacement (default) |
| `withMatchMode('exact'|'contains')` | `'exact'` | How to match keys against the sensitive list |
| `withExceptKeys(array)` | `[]` | Keys to exclude from redaction |
| `withEmailRedaction()` | `true` | Enable email pattern scanning |
| `withoutEmailRedaction()` | - | Disable email pattern scanning |
| `withCreditCardRedaction()` | `true` | Enable credit card pattern scanning |
| `withoutCreditCardRedaction()` | - | Disable credit card pattern scanning |

## Key Match Modes

### Exact mode (default)

Only keys that exactly match a sensitive key are redacted:

```php
'password' => 'secret'   // redacted
'user_password' => 'x'   // not redacted
```

### Contains mode

Any key containing a sensitive word is redacted:

```php
$config = SanitizerConfig::default()->withMatchMode('contains');

'user_password'   => 'secret'  // redacted (contains "password")
'jwt_token'       => 'abc'     // redacted (contains "token")
'stripe_api_key'  => 'sk_...'  // redacted (contains "api_key")
'my_password_reset' => '...'   // redacted (contains "password")
```

### Combining with exceptKeys

```php
$config = SanitizerConfig::default()
    ->withMatchMode('contains')
    ->withExceptKeys(['email_template']);
```

## Key Normalization

Key names are normalized to snake_case for consistent matching. This means `apiKey`, `api-key`, `api_key`, and `API_KEY` are all treated identically:

```php
$processor = new PiiSanitizerProcessor();

'apiKey'       => 'secret'  // redacted (normalizes to "api_key")
'api-key'      => 'secret'  // redacted (normalizes to "api_key")
'API_KEY'      => 'secret'  // redacted (normalizes to "api_key")
'clientSecret' => 'secret'  // redacted (normalizes to "client_secret")
```

## Masking Modes

### Full masking (default)

All matching values are replaced with the configured mask string:

```php
['password' => 'mySecretPass!'] → ['password' => '[REDACTED]']
['email'    => 'dinesh@example.com'] → ['email' => '[REDACTED]']
```

### Partial masking

Show enough context for debugging while protecting sensitive data:

```php
$config = SanitizerConfig::default()->withPartialMasking();

// Sensitive keys
['password' => 'mySecretPass!'] → ['password' => 'my*********s!']
['email'    => 'dinesh@example.com'] → ['email' => 'd*****@example.com']

// Pattern redaction within values
['note' => 'Contact dinesh@example.com'] → ['note' => 'Contact d*****@example.com']
['note' => 'Card: 4111111111111111']    → ['note' => 'Card: ************1111']
['note' => 'Card: 4111-1111-1111-1111'] → ['note' => 'Card: ****-****-****-1111']
```

Non-string values are always fully masked regardless of mode:

```php
['password' => 123456] → ['password' => '[REDACTED]']
['secret' => true]     → ['secret' => '[REDACTED]']
```

## Default Redacted Keys

| Category | Keys |
|----------|------|
| Authentication | `password`, `password_confirmation`, `secret`, `token`, `api_key`, `auth_key`, `access_token`, `refresh_token`, `authorization`, `bearer`, `jwt`, `id_token`, `csrf_token`, `session`, `session_id` |
| Financial | `cvv`, `cc_number`, `card_number`, `pin`, `passcode` |
| Personal | `ssn`, `social_security`, `email`, `phone`, `otp` |
| Infrastructure | `private_key`, `client_secret` |
| Session | `cookie`, `set_cookie` |

## Pattern Redaction

String values are scanned for patterns even when the key is not in the sensitive list:

- **Emails**: Matches `user@example.com`, `user+tag@example.com`, etc.
- **Credit cards**: Validated with the Luhn algorithm to reduce false positives. Supports `4111111111111111`, `4111-1111-1111-1111`, and `4111 1111 1111 1111` formats.

### Disable pattern redaction

```php
$processor = new PiiSanitizerProcessor(
    redactEmails: false,
    redactCreditCards: false
);
```

## Custom Keys

```php
$processor = new PiiSanitizerProcessor(
    customKeys: ['otp', 'pin', 'verification_code']
);
```

## Masking Behavior

Sensitive keys are redacted regardless of value type:

```php
['password' => 123456]     → ['password' => '[REDACTED]']
['secret' => true]         → ['secret' => '[REDACTED]']
['token' => null]          → ['token' => '[REDACTED]']
```

Non-sensitive non-string values are left untouched:

```php
['user_id' => 7, 'is_active' => true, 'last_login' => null]
// unchanged
```

Nested arrays are sanitized recursively:

```php
[
    'user' => [
        'credentials' => ['password' => 'secret']
    ]
]
// → user.credentials.password → [REDACTED]
```

## Security Notes

This package reduces accidental PII logging but should not replace avoiding sensitive logging at source. Always follow least-privilege logging practices.

## Framework Examples

### Laravel

```php
// config/logging.php
use Dineshrao275\LogSanitizer\PiiSanitizerProcessor;

'channels' => [
    'stack' => [
        'driver' => 'stack',
        'channels' => ['single'],
    ],
    'single' => [
        'driver' => 'single',
        'path' => storage_path('logs/laravel.log'),
        'tap' => [App\Logging\SanitizeLog::class],
    ],
],
```

```php
// app/Logging/SanitizeLog.php
namespace App\Logging;

use Dineshrao275\LogSanitizer\PiiSanitizerProcessor;
use Monolog\Logger;

class SanitizeLog
{
    public function __invoke(Logger $logger): void
    {
        $logger->pushProcessor(new PiiSanitizerProcessor());
    }
}
```

### Symfony

```yaml
# config/services.yaml
services:
    Dineshrao275\LogSanitizer\PiiSanitizerProcessor:
        arguments:
            $customKeys: ['otp']
            $redactCreditCards: true

    monolog.processor.pii_sanitizer:
        tags:
            - { name: monolog.processor }
```

## Testing

```bash
vendor/bin/phpunit
```

## License

MIT
