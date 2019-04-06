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

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\JWK;

final class HS384 extends HMAC
{
    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    public function name(): string
    {
        return 'HS384';
    }

    protected function checkKey(JWK $key)
    {
        parent::checkKey($key);
        $k = $key->get('k');
        if (mb_strlen($k, '8bit') < 48) {
            throw new \InvalidArgumentException('Invalid key length.');
        }
    }
}
