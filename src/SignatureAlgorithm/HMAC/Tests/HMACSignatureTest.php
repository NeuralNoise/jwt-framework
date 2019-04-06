<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Algorithm\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use PHPUnit\Framework\TestCase;

/**
 * @group HMAC
 * @group Unit
 */
class HMACSignatureTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Wrong key type.
     *
     * @test
     */
    public function invalidKey()
    {
        $key = JWK::create([
            'kty' => 'EC',
        ]);

        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $hmac->sign($key, $data);
    }

    /**
     * @test
     */
    public function signatureHasBadBadLength()
    {
        $key = JWK::create([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        static::assertFalse($hmac->verify($key, $data, \hex2bin('326eb338c465d3587f3349df0b96ba81')));
    }

    /**
     * @test
     */
    public function hS256SignAndVerify()
    {
        $key = JWK::create([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $signature = $hmac->sign($key, $data);

        static::assertEquals(\hex2bin('7ed268ef179f530a4a1c56225c352a6782cf5379085c484b4f355b6744d6f19d'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function hS384SignAndVerify()
    {
        $key = JWK::create([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS384();
        $data = 'Live long and Prosper.';

        $signature = $hmac->sign($key, $data);

        static::assertEquals(\hex2bin('903ce2ef2878090d6117f88210d5a822d260fae66760186cb3326770748b9fa47c2d4531a4d5d868f99bcf7ea45c1ab4'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function hS512SignAndVerify()
    {
        $key = JWK::create([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS512();
        $data = 'Live long and Prosper.';

        $signature = $hmac->sign($key, $data);

        static::assertEquals(\hex2bin('8819a59bacda92a48419c54ef8c20fa821b5c55ebb1a562ca3ff3c8d6b60e288e8127375ce8a5e327f840de4575c4bf230a97e26167e6f6d57fd5324481c969d'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }
}
