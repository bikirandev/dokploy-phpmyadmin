<?php

declare(strict_types=1);

namespace DbPortal;

use RuntimeException;

/**
 * An error shown to the user with an HTTP status.
 */
final class HttpException extends RuntimeException
{
    public function __construct(public readonly int $status, string $message = '')
    {
        parent::__construct($message);
    }
}
