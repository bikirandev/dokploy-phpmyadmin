<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Marks binary data so it is stored as a BLOB.
 */
final class Blob
{
    public function __construct(public readonly string $bytes)
    {
    }
}
