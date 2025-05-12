<?php

use App\Services\Hook;
use Blessing\Filter;
use Illuminate\Contracts\Events\Dispatcher;

/**
 * BlessingSkin OAuth 插件入口文件
 *
 * 这个文件是整个插件的入口，在插件被加载时执行
 */
return function (Dispatcher $events, Filter $filter, $plugin) {
    // 注册用户中心菜单项
    Hook::addMenuItem('user', 0, [
        'title' => 'BlessingSkin\\OAuth::general.user-menu',
        'link'  => '/user/oauth/authorizations',
        'icon'  => 'fa-key',
    ]);

    // 注册管理面板菜单项
    Hook::addMenuItem('admin', 0, [
        'title' => 'BlessingSkin\\OAuth::general.admin-menu',
        'link'  => '/admin/oauth/clients',
        'icon'  => 'fa-key',
    ]);

    // 注册路由
    Hook::addRoute(function () {
        Route::namespace('BlessingSkin\\OAuth\\Controllers')
            ->group(__DIR__.'/routes.php');
    });
};
