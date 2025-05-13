<?php

use App\Events\PluginWasEnabled;
use App\Events\PluginWasDisabled;
use App\Events\PluginWasDeleted;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Str;

return [
    PluginWasEnabled::class => function () {
        // 创建 OAuth 客户端表
        if (!Schema::hasTable('oauth_clients')) {
            Schema::create('oauth_clients', function (Blueprint $table) {
                $table->increments('id');
                $table->string('name');
                $table->string('client_id', 100)->unique();
                $table->string('client_secret', 100);
                $table->text('redirect_uri');
                $table->text('description')->nullable();
                $table->boolean('revoked')->default(false);
                $table->timestamps();
            });
        }

        // 创建 OAuth 授权码表
        if (!Schema::hasTable('oauth_auth_codes')) {
            Schema::create('oauth_auth_codes', function (Blueprint $table) {
                $table->string('id', 100)->primary();
                $table->integer('user_id');
                $table->integer('client_id');
                $table->text('scopes')->nullable();
                $table->boolean('revoked')->default(false);
                $table->dateTime('expires_at')->nullable();
                $table->string('nonce')->nullable();
            });
        }

        // 创建 OAuth 访问令牌表
        if (!Schema::hasTable('oauth_access_tokens')) {
            Schema::create('oauth_access_tokens', function (Blueprint $table) {
                $table->string('id', 100)->primary();
                $table->integer('user_id')->nullable()->index();
                $table->integer('client_id');
                $table->text('scopes')->nullable();
                $table->boolean('revoked')->default(false);
                $table->dateTime('expires_at')->nullable();
                $table->timestamps();
            });
        }

        // 创建 OAuth 刷新令牌表
        if (!Schema::hasTable('oauth_refresh_tokens')) {
            Schema::create('oauth_refresh_tokens', function (Blueprint $table) {
                $table->string('id', 100)->primary();
                $table->string('access_token_id', 100)->index();
                $table->boolean('revoked')->default(false);
                $table->dateTime('expires_at')->nullable();
            });
        }

        // 创建 OAuth 用户授权表
        if (!Schema::hasTable('oauth_authorizations')) {
            Schema::create('oauth_authorizations', function (Blueprint $table) {
                $table->increments('id');
                $table->integer('user_id')->index();
                $table->integer('client_id')->index();
                $table->timestamps();

                // 一个用户对一个客户端只能有一条授权记录
                $table->unique(['user_id', 'client_id']);
            });
        }

        // 生成初始JWT密钥对（如果不存在）
        if (!option('oauth_jwt_private_key') || !option('oauth_jwt_public_key')) {
            // 生成一对RSA密钥
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

            // 生成kid
            $kid = (string)time();

            // 存储到选项中
            option(['oauth_jwt_private_key' => $privateKey]);
            option(['oauth_jwt_public_key' => $publicKey]);
            option(['oauth_jwt_kid' => $kid]);
        }

        // 设置默认配置
        $items = [
            'oauth_token_lifetime' => '60', // 访问令牌有效期（分钟）
            'oauth_refresh_token_lifetime' => '30', // 刷新令牌有效期（天）
            'oauth_issuer' => url('/'), // 颁发者URL
            'oauth_id_token_lifetime' => '10', // ID令牌有效期（分钟）
        ];

        foreach ($items as $key => $value) {
            if (!option($key)) {
                option([$key => $value]);
            }
        }
    },

    PluginWasDisabled::class => function () {
        // 插件被禁用时不需要做任何事情
    },

    PluginWasDeleted::class => function () {
        // 删除数据表
        Schema::dropIfExists('oauth_authorizations');
        Schema::dropIfExists('oauth_refresh_tokens');
        Schema::dropIfExists('oauth_access_tokens');
        Schema::dropIfExists('oauth_auth_codes');
        Schema::dropIfExists('oauth_clients');

        // 删除配置项
        option(['oauth_issuer' => null]);
        option(['oauth_id_token_lifetime' => null]);
        option(['oauth_token_lifetime' => null]);
        option(['oauth_refresh_token_lifetime' => null]);
        option(['oauth_jwt_private_key' => null]);
        option(['oauth_jwt_public_key' => null]);
        option(['oauth_jwt_kid' => null]);

        // 删除SAML相关配置
        option(['oauth_saml_enabled' => null]);
        option(['oauth_saml_entity_id' => null]);
        option(['oauth_saml_idp_entity_id' => null]);
        option(['oauth_saml_idp_sso_url' => null]);
        option(['oauth_saml_idp_slo_url' => null]);
        option(['oauth_saml_idp_x509cert' => null]);
        option(['oauth_saml_nameid_format' => null]);
        option(['oauth_saml_attr_email' => null]);
        option(['oauth_saml_attr_name' => null]);
        option(['oauth_saml_auto_register' => null]);
        option(['oauth_saml_x509cert' => null]);
        option(['oauth_saml_private_key' => null]);
    },
];
