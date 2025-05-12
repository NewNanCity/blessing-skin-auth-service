<?php

use App\Events\PluginWasEnabled;
use App\Events\PluginWasDisabled;
use App\Events\PluginWasDeleted;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;

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

        // 设置默认配置
        $items = [
            'oauth_token_lifetime' => '60', // 访问令牌有效期（分钟）
            'oauth_refresh_token_lifetime' => '30', // 刷新令牌有效期（天）
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
    },
];
