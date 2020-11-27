<?php

require('./vendor/autoload.php');

use RedisClient\RedisClient;

$Redis = new RedisClient([
    'server' => str_replace('redis://', '', getenv('REDIS_URL')),
    'timeout' => 0.25
]);
$RedisPublisher = new RedisClient([
    'server' => str_replace('redis://', '', getenv('REDIS_URL')),
    'timeout' => 0.25
]);


$Redis->subscribe(['PHP-HELPER-SERVICE'], function ($type, $channel, $message) use ($RedisPublisher) {
    $data = json_decode($message);

    if (!empty($data)) {

        if ($data->pattern === "auth") {

            $g = gmp_init(7);
            $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);
            $x = gmp_import(
                sha1(hex2bin($data->ctx->salt) . sha1(strtoupper($data->ctx->username . ':' . $data->ctx->password), TRUE), TRUE),
                1,
                GMP_LSW_FIRST
            );
            $v = gmp_powm($g, $x, $N);

            $isAuth = (hex2bin($data->ctx->verifier) === str_pad(gmp_export($v, 1, GMP_LSW_FIRST), 32, chr(0), STR_PAD_RIGHT));
            $response = [
                "meta" => [
                    "responseId" => $data->meta->responseId
                ],
                "status" => $isAuth ? 200 : 401,
                "body" => [
                    "isAuth" => $isAuth
                ]
            ];

            $RedisPublisher->publish($data->meta->responseChannel, json_encode($response));
        }
    }

    return true;
});
