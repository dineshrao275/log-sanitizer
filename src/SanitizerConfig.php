<?php

declare(strict_types=1);

namespace Dineshrao\LogSanitizer;

class SanitizerConfig
{
    private array $customKeys = [];
    private string $mask = '[REDACTED]';
    private bool $redactEmails = true;
    private bool $redactCreditCards = true;
    private string $matchMode = 'exact';
    private array $exceptKeys = [];
    private bool $partialMasking = false;

    public function __construct(
        array $customKeys = [],
        string $mask = '[REDACTED]',
        bool $redactEmails = true,
        bool $redactCreditCards = true,
        string $matchMode = 'exact',
        array $exceptKeys = [],
        bool $partialMasking = false,
    ) {
        $this->customKeys = $customKeys;
        $this->mask = $mask;
        $this->redactEmails = $redactEmails;
        $this->redactCreditCards = $redactCreditCards;
        $this->matchMode = $matchMode;
        $this->exceptKeys = $exceptKeys;
        $this->partialMasking = $partialMasking;
    }

    public static function default(): self
    {
        return new self();
    }

    public function withCustomKeys(array $keys): static
    {
        $clone = clone $this;
        $clone->customKeys = $keys;
        return $clone;
    }

    public function withMask(string $mask): static
    {
        $clone = clone $this;
        $clone->mask = $mask;
        return $clone;
    }

    public function withPartialMasking(): static
    {
        $clone = clone $this;
        $clone->partialMasking = true;
        return $clone;
    }

    public function withFullMasking(): static
    {
        $clone = clone $this;
        $clone->partialMasking = false;
        return $clone;
    }

    public function withMatchMode(string $mode): static
    {
        if (!in_array($mode, ['exact', 'contains'], true)) {
            throw new \InvalidArgumentException("Match mode must be 'exact' or 'contains'");
        }
        $clone = clone $this;
        $clone->matchMode = $mode;
        return $clone;
    }

    public function withExceptKeys(array $keys): static
    {
        $clone = clone $this;
        $clone->exceptKeys = $keys;
        return $clone;
    }

    public function withEmailRedaction(): static
    {
        $clone = clone $this;
        $clone->redactEmails = true;
        return $clone;
    }

    public function withoutEmailRedaction(): static
    {
        $clone = clone $this;
        $clone->redactEmails = false;
        return $clone;
    }

    public function withCreditCardRedaction(): static
    {
        $clone = clone $this;
        $clone->redactCreditCards = true;
        return $clone;
    }

    public function withoutCreditCardRedaction(): static
    {
        $clone = clone $this;
        $clone->redactCreditCards = false;
        return $clone;
    }

    public function getCustomKeys(): array
    {
        return $this->customKeys;
    }

    public function getMask(): string
    {
        return $this->mask;
    }

    public function shouldRedactEmails(): bool
    {
        return $this->redactEmails;
    }

    public function shouldRedactCreditCards(): bool
    {
        return $this->redactCreditCards;
    }

    public function getMatchMode(): string
    {
        return $this->matchMode;
    }

    public function getExceptKeys(): array
    {
        return $this->exceptKeys;
    }

    public function isPartialMasking(): bool
    {
        return $this->partialMasking;
    }

    public function merge(array $customKeys, string $mask, bool $redactEmails, bool $redactCreditCards): static
    {
        $clone = clone $this;
        if ($customKeys !== []) {
            $clone->customKeys = $customKeys;
        }
        $clone->mask = $mask;
        $clone->redactEmails = $redactEmails;
        $clone->redactCreditCards = $redactCreditCards;
        return $clone;
    }
}
