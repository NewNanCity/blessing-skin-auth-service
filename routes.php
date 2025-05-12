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
    });
