<?php

/*
|--------------------------------------------------------------------------
| OAuth 插件路由
|--------------------------------------------------------------------------
|
| 这里定义了 OAuth 插件的所有路由
|
*/

// 用户路由
Route::prefix('user/oauth')
    ->middleware(['web', 'auth'])
    ->group(function () {
        Route::get('authorizations', 'UserController@showAuthorizationList');
        Route::delete('authorizations/{id}', 'UserController@revokeAuthorization');
    });

// 管理员路由
Route::prefix('admin/oauth')
    ->middleware(['web', 'auth', 'role:admin'])
    ->group(function () {
        Route::get('clients', 'AdminController@showClientList');
        Route::post('clients', 'AdminController@createClient');
        Route::put('clients/{id}', 'AdminController@updateClient');
        Route::delete('clients/{id}', 'AdminController@deleteClient');
    });

// OAuth 服务路由
Route::prefix('oauth')
    ->middleware(['web'])
    ->group(function () {
        // 授权端点
        Route::get('authorize', 'OAuthController@showAuthorizePage');
        Route::post('authorize', 'OAuthController@handleAuthorize');

        // 令牌端点
        Route::post('token', 'OAuthController@issueToken');

        // 用户信息端点
        Route::get('userinfo', 'OAuthController@getUserInfo');

        // JWKS 端点
        Route::get('jwks', 'OidcController@jwks');
    });

// OIDC 配置端点 (不应有 oauth 前缀)
Route::middleware(['web'])
    ->get('.well-known/openid-configuration', 'OidcController@configuration');

// SAML 路由
Route::prefix('saml')
    ->middleware(['web'])
    ->group(function () {
        // SAML 元数据端点
        Route::get('metadata', 'SamlController@metadata');

        // SAML 登录端点
        Route::get('login', 'SamlController@login');

        // SAML 断言消费服务（ACS）端点
        Route::post('acs', 'SamlController@acs');

        // SAML 单点登出（SLO）端点
        Route::get('slo', 'SamlController@slo');
        Route::post('slo', 'SamlController@slo');
    });

// 管理员 API 路由
Route::prefix('api/admin/oauth')
    ->middleware(['web', 'auth', 'role:admin'])
    ->group(function () {
        Route::post('keys', 'AdminController@generateNewKey');
        Route::post('cleanup', 'AdminController@cleanupTokens');
        Route::post('saml-certificate', 'AdminController@generateSamlCertificate');
    });
