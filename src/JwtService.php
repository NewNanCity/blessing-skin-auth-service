<?php

namespace BlessingSkin\AuthService;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

/**
 * JWT服务类
 *
 * 此类负责JWT令牌的生成和验证
 */
class JwtService
{
    /**
     * 获取活跃的JWT密钥对
     *
     * @return array|null 包含private_key和public_key的数组，如果没有找到则返回null
     */
    public function getActiveKeyPair()
    {
        $privateKey = option('oauth_jwt_private_key');
        $publicKey = option('oauth_jwt_public_key');
        $kid = option('oauth_jwt_kid', '1');

        if (!$privateKey || !$publicKey) {
            return null;
        }

        return [
            'private_key' => $privateKey,
            'public_key' => $publicKey,
            'kid' => $kid
        ];
    }

    /**
     * 根据密钥ID获取公钥
     *
     * @param string $kid 密钥ID
     * @return string|null 公钥，如果没有找到则返回null
     */
    public function getPublicKeyById($kid)
    {
        // 目前我们只支持一个密钥对，所以忽略kid参数
        return option('oauth_jwt_public_key');
    }

    /**
     * 生成新的JWT密钥对
     *
     * @return array 包含private_key和public_key的数组
     */
    public function generateNewKeyPair()
    {
        // 生成新的密钥对
        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        // 生成新的密钥对
        $res = openssl_pkey_new($config);

        // 提取私钥
        openssl_pkey_export($res, $privateKey);

        // 提取公钥
        $publicKey = openssl_pkey_get_details($res)['key'];

        // 生成新的kid
        $kid = (string)time();

        // 存储到选项中
        option(['oauth_jwt_private_key' => $privateKey]);
        option(['oauth_jwt_public_key' => $publicKey]);
        option(['oauth_jwt_kid' => $kid]);

        return [
            'private_key' => $privateKey,
            'public_key' => $publicKey,
            'kid' => $kid
        ];
    }

    /**
     * 生成访问令牌
     *
     * @param int $userId 用户ID
     * @param int $clientId 客户端ID
     * @param string $scopes 作用域
     * @param string $nonce 随机数（可选）
     * @return string 生成的JWT令牌
     */
    public function generateAccessToken($userId, $clientId, $scopes, $nonce = null)
    {
        $keyPair = $this->getActiveKeyPair();

        if (!$keyPair) {
            throw new \Exception('没有可用的JWT密钥对');
        }

        $now = Carbon::now()->timestamp;
        $expiresAt = Carbon::now()->addMinutes(option('oauth_token_lifetime', 60))->timestamp;

        $payload = [
            'iss' => option('oauth_issuer', url('/')),  // 颁发者
            'sub' => (string)$userId,                   // 主题（用户ID）
            'aud' => (string)$clientId,                 // 受众（客户端ID）
            'iat' => $now,                              // 颁发时间
            'exp' => $expiresAt,                        // 过期时间
            'jti' => Str::random(40),                   // JWT ID
            'scope' => $scopes,                         // 作用域
            'token_type' => 'access_token'              // 令牌类型
        ];

        // 如果提供了nonce，添加到payload中
        if ($nonce) {
            $payload['nonce'] = $nonce;
        }

        $jwt = JWT::encode($payload, $keyPair['private_key'], 'RS256', $keyPair['kid']);

        return $jwt;
    }

    /**
     * 生成刷新令牌
     *
     * @param int $userId 用户ID
     * @param int $clientId 客户端ID
     * @param string $accessTokenId 关联的访问令牌ID
     * @return string 生成的JWT令牌
     */
    public function generateRefreshToken($userId, $clientId, $accessTokenId)
    {
        $keyPair = $this->getActiveKeyPair();

        if (!$keyPair) {
            throw new \Exception('没有可用的JWT密钥对');
        }

        $now = Carbon::now()->timestamp;
        $expiresAt = Carbon::now()->addDays(option('oauth_refresh_token_lifetime', 30))->timestamp;

        $payload = [
            'iss' => option('oauth_issuer', url('/')),  // 颁发者
            'sub' => (string)$userId,                   // 主题（用户ID）
            'aud' => (string)$clientId,                 // 受众（客户端ID）
            'iat' => $now,                              // 颁发时间
            'exp' => $expiresAt,                        // 过期时间
            'jti' => Str::random(40),                   // JWT ID
            'token_type' => 'refresh_token',            // 令牌类型
            'access_token_id' => $accessTokenId         // 关联的访问令牌ID
        ];

        $jwt = JWT::encode($payload, $keyPair['private_key'], 'RS256', $keyPair['kid']);

        return $jwt;
    }

    /**
     * 生成ID令牌
     *
     * @param int $userId 用户ID
     * @param int $clientId 客户端ID
     * @param array $userData 用户数据
     * @param string $nonce 随机数
     * @return string 生成的JWT令牌
     */
    public function generateIdToken($userId, $clientId, $userData, $nonce)
    {
        $keyPair = $this->getActiveKeyPair();

        if (!$keyPair) {
            throw new \Exception('没有可用的JWT密钥对');
        }

        $now = Carbon::now()->timestamp;
        $expiresAt = Carbon::now()->addMinutes(option('oauth_id_token_lifetime', 60))->timestamp;

        $payload = [
            'iss' => option('oauth_issuer', url('/')),  // 颁发者
            'sub' => (string)$userId,                   // 主题（用户ID）
            'aud' => (string)$clientId,                 // 受众（客户端ID）
            'iat' => $now,                              // 颁发时间
            'exp' => $expiresAt,                        // 过期时间
            'auth_time' => $now,                        // 认证时间
            'nonce' => $nonce,                          // 随机数
        ];

        // 添加用户信息
        if (isset($userData['email'])) {
            $payload['email'] = $userData['email'];
        }

        if (isset($userData['nickname'])) {
            $payload['name'] = $userData['nickname'];
        }

        $jwt = JWT::encode($payload, $keyPair['private_key'], 'RS256', $keyPair['kid']);

        return $jwt;
    }

    /**
     * 验证JWT令牌
     *
     * @param string $jwt JWT令牌
     * @return object|false 解码后的payload，如果验证失败则返回false
     */
    public function validateToken($jwt)
    {
        try {
            // 先解析JWT头部获取kid
            $tks = explode('.', $jwt);
            if (count($tks) != 3) {
                return false;
            }

            $headb64 = $tks[0];
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64));

            if (!isset($header->kid)) {
                return false;
            }

            $publicKey = $this->getPublicKeyById($header->kid);

            if (!$publicKey) {
                return false;
            }

            $decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));

            return $decoded;
        } catch (\Exception $e) {
            return false;
        }
    }
}
