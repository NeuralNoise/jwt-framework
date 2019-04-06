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

namespace Jose\Component\KeyManagement\KeyAnalyzer;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Ecc\NistCurve;

final class ES512KeyAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag)
    {
        if ('EC' !== $jwk->get('kty')) {
            return;
        }
        if (!$jwk->has('crv')) {
            $bag->add(Message::high('Invalid key. The components "crv" is missing.'));

            return;
        }
        if ('P-521' !== $jwk->get('crv')) {
            return;
        }
        $x = Base64Url::decode($jwk->get('x'));
        $xLength = 8 * \mb_strlen($x, '8bit');
        $y = Base64Url::decode($jwk->get('y'));
        $yLength = 8 * \mb_strlen($y, '8bit');
        if ($yLength !== $xLength) {
            $bag->add(Message::high('Invalid key. The components "x" and "y" shall have the same size.'));
        }
        $xGmp = gmp_init(bin2hex($x), 16);
        $yGmp = gmp_init(bin2hex($y), 16);
        $curve = NistCurve::curve521();
        if (!$curve->contains($xGmp, $yGmp)) {
            $bag->add(Message::high('Invalid key. The point is not on the curve.'));
        }
    }
}
