# log-sanitizer

A lightweight, zero-config Monolog processor that automatically redacts 
PII and sensitive data (passwords, tokens, emails, credit cards) from your 
PHP application logs. GDPR-friendly.

## Installation

```bash
composer require dineshrao275/log-sanitizer
```

## Requirements

- PHP 8.2+
- monolog/monolog ^3.0

## Usage

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Dineshrao275\LogSanitizer\PiiSanitizerProcessor;

$log = new Logger('app');
$log->pushHandler(new StreamHandler('app.log', \Monolog\Level::Debug));

// Add the processor
$log->pushProcessor(new PiiSanitizerProcessor());

// Sensitive data is automatically redacted!
$log->info('User login', [
    'username' => 'dinesh',
    'password' => 'secret123',      // → [REDACTED]
    'email'    => 'dinesh@test.com' // → [REDACTED]
]);
```

## Custom Configuration

```php
$log->pushProcessor(new PiiSanitizerProcessor(
    customKeys:        ['otp', 'pin'],  // extra keys to redact
    mask:              '***',           // custom mask string
    redactEmails:      true,            // scan values for emails
    redactCreditCards: true             // scan values for card numbers
));
```

## Default Redacted Keys

`password`, `token`, `api_key`, `secret`, `access_token`, 
`refresh_token`, `cvv`, `card_number`, `ssn`, and more.

## License

MIT