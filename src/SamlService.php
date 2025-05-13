<?php

namespace BlessingSkin\AuthService;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;
use App\Models\User;

/**
 * SAML服务类
 *
 * 此类负责处理SAML相关的功能
 */
class SamlService
{
    /**
     * 获取SAML设置
     *
     * @return array SAML设置
     */
    public function getSettings()
    {
        $entityId = option('oauth_saml_entity_id', url('/saml/metadata'));
        $acsUrl = url('/saml/acs');
        $sloUrl = url('/saml/slo');
        $nameIdFormat = option('oauth_saml_nameid_format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
        $x509cert = option('oauth_saml_x509cert', '');
        $privateKey = option('oauth_saml_private_key', '');

        return [
            // 如果为true，则会在请求中包含签名
            'strict' => true,

            // 调试模式
            'debug' => false,

            // 服务提供者（SP）配置
            'sp' => [
                // SP实体ID，通常是元数据URL
                'entityId' => $entityId,

                // 断言消费服务URL
                'assertionConsumerService' => [
                    'url' => $acsUrl,
                ],

                // 单点登出服务URL
                'singleLogoutService' => [
                    'url' => $sloUrl,
                ],

                // SP的X.509证书
                'x509cert' => $x509cert,

                // SP的私钥
                'privateKey' => $privateKey,

                // 名称ID格式
                'NameIDFormat' => $nameIdFormat,
            ],

            // 身份提供者（IdP）配置
            'idp' => [
                // IdP实体ID
                'entityId' => option('oauth_saml_idp_entity_id', ''),

                // 单点登录服务URL
                'singleSignOnService' => [
                    'url' => option('oauth_saml_idp_sso_url', ''),
                ],

                // 单点登出服务URL
                'singleLogoutService' => [
                    'url' => option('oauth_saml_idp_slo_url', ''),
                ],

                // IdP的X.509证书
                'x509cert' => option('oauth_saml_idp_x509cert', ''),
            ],

            // 安全设置
            'security' => [
                // 是否签名元数据
                'signMetadata' => false,

                // 是否签名认证请求
                'authnRequestsSigned' => false,

                // 是否签名注销请求
                'logoutRequestSigned' => false,

                // 是否签名注销响应
                'logoutResponseSigned' => false,

                // 是否要求签名断言
                'wantAssertionsSigned' => false,

                // 是否要求签名消息
                'wantMessagesSigned' => false,

                // 是否要求签名名称ID
                'wantNameIdSigned' => false,

                // 认证上下文比较
                'requestedAuthnContextComparison' => 'exact',

                // 签名算法
                'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',

                // 摘要算法
                'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',
            ],

            // 联系人信息
            'contactPerson' => [
                'technical' => [
                    'givenName' => option('site_name'),
                    'emailAddress' => option('site_email', 'admin@example.com')
                ],
                'support' => [
                    'givenName' => option('site_name'),
                    'emailAddress' => option('site_email', 'admin@example.com')
                ],
            ],

            // 组织信息
            'organization' => [
                'en-US' => [
                    'name' => option('site_name'),
                    'displayname' => option('site_name'),
                    'url' => url('/')
                ],
                'zh-CN' => [
                    'name' => option('site_name'),
                    'displayname' => option('site_name'),
                    'url' => url('/')
                ],
            ],
        ];
    }

    /**
     * 获取SAML Auth实例
     *
     * @return \OneLogin\Saml2\Auth
     */
    public function getAuth()
    {
        return new Auth($this->getSettings());
    }

    /**
     * 生成SAML元数据
     *
     * @return string SAML元数据XML
     */
    public function getMetadata()
    {
        try {
            $settings = new Settings($this->getSettings());
            $metadata = $settings->getSPMetadata();
            Utils::validateXML($metadata, 'saml-schema-metadata-2.0.xsd', $settings->isDebugActive());
            return $metadata;
        } catch (\Exception $e) {
            Log::error(trans('BlessingSkin\\AuthService::saml.metadata-generation-failed') . ': ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * 处理SAML响应
     *
     * @param \OneLogin\Saml2\Auth $auth SAML Auth实例
     * @return array 用户信息
     */
    public function processResponse(Auth $auth)
    {
        if (!$auth->isAuthenticated()) {
            throw new \Exception(trans('BlessingSkin\\AuthService::saml.auth-failed'));
        }

        $attributes = $auth->getAttributes();
        $nameId = $auth->getNameId();

        // 获取映射配置
        $emailAttr = option('oauth_saml_attr_email', 'email');
        $nameAttr = option('oauth_saml_attr_name', 'displayName');

        // 提取用户信息
        $email = $nameId;
        if (isset($attributes[$emailAttr]) && !empty($attributes[$emailAttr][0])) {
            $email = $attributes[$emailAttr][0];
        }

        $name = '';
        if (isset($attributes[$nameAttr]) && !empty($attributes[$nameAttr][0])) {
            $name = $attributes[$nameAttr][0];
        }

        // 查找或创建用户
        $user = User::where('email', $email)->first();

        if (!$user && option('oauth_saml_auto_register', false)) {
            // 自动注册用户
            $user = new User();
            $user->email = $email;
            $user->nickname = $name ?: explode('@', $email)[0];
            $user->password = app('hash')->make(str_random(16));
            $user->score = option('user_initial_score');
            $user->permission = option('user_initial_permission');
            $user->register_at = get_datetime_string();
            $user->last_sign_at = get_datetime_string(time() - 86400);
            $user->verified = true;
            $user->save();
        }

        return [
            'user' => $user,
            'attributes' => $attributes,
            'nameId' => $nameId
        ];
    }

    /**
     * 生成自签名证书
     *
     * @return array 包含证书和私钥的数组
     */
    public function generateSelfSignedCertificate()
    {
        $dn = [
            "countryName" => "CN",
            "stateOrProvinceName" => "State",
            "localityName" => "City",
            "organizationName" => option('site_name'),
            "commonName" => parse_url(url('/'), PHP_URL_HOST),
            "emailAddress" => option('site_email', 'admin@example.com')
        ];

        // 生成私钥
        $privateKey = openssl_pkey_new([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        // 生成CSR
        $csr = openssl_csr_new($dn, $privateKey, ['digest_alg' => 'sha256']);

        // 生成自签名证书
        $x509 = openssl_csr_sign($csr, null, $privateKey, 365, ['digest_alg' => 'sha256']);

        // 导出证书
        openssl_x509_export($x509, $certOut);

        // 导出私钥
        openssl_pkey_export($privateKey, $pkeyOut);

        return [
            'certificate' => $certOut,
            'privateKey' => $pkeyOut
        ];
    }
}
