<?php

namespace BlessingSkin\AuthService;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * OIDC服务类
 *
 * 此类负责处理OIDC相关的配置和端点
 */
class OidcService
{
    /**
     * 获取OIDC配置
     *
     * @return array OIDC配置
     */
    public function getConfiguration()
    {
        $issuer = option('oauth_issuer', url('/'));

        return [
            'issuer' => $issuer,
            'authorization_endpoint' => url('/oauth/authorize'),
            'token_endpoint' => url('/oauth/token'),
            'userinfo_endpoint' => url('/oauth/userinfo'),
            'jwks_uri' => url('/oauth/jwks'),
            'response_types_supported' => ['code', 'token'],
            'grant_types_supported' => ['authorization_code', 'implicit', 'refresh_token', 'client_credentials', 'password'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'profile', 'email'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
            'claims_supported' => [
                'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time',
                'nonce', 'name', 'email'
            ]
        ];
    }

    /**
     * 获取JWKS（JSON Web Key Set）
     *
     * @return array JWKS
     */
    public function getJwks()
    {
        $publicKey = option('oauth_jwt_public_key');
        $kid = option('oauth_jwt_kid', '1');

        if (!$publicKey) {
            return ['keys' => []];
        }

        $jwks = ['keys' => []];

        // 从公钥中提取所需的参数
        $res = openssl_pkey_get_public($publicKey);
        $detail = openssl_pkey_get_details($res);

        // 构建JWK
        $jwk = [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($detail['rsa']['n'])), '='),
            'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($detail['rsa']['e'])), '=')
        ];

        $jwks['keys'][] = $jwk;

        return $jwks;
    }

    /**
     * 生成随机的nonce值
     *
     * @return string 随机nonce值
     */
    public function generateNonce()
    {
        return Str::random(32);
    }

    /**
     * 验证作用域
     *
     * @param string $scope 请求的作用域
     * @return array 有效的作用域数组
     */
    public function validateScopes($scope)
    {
        $requestedScopes = explode(' ', $scope);
        $validScopes = ['openid', 'profile', 'email'];

        return array_intersect($requestedScopes, $validScopes);
    }
}
