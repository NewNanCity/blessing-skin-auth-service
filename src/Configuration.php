<?php

namespace BlessingSkin\OAuth;

use App\Services\OptionForm;
use Option;

class Configuration
{
    /**
     * 渲染配置页面
     *
     * @return \Illuminate\View\View
     */
    public function render()
    {
        $form = Option::form('oauth', trans('BlessingSkin\\OAuth::config.title'), function (OptionForm $form) {
            $form->text('oauth_token_lifetime', trans('BlessingSkin\\OAuth::config.token-lifetime'))
                ->hint(trans('BlessingSkin\\OAuth::config.token-lifetime-hint'))
                ->description(trans('BlessingSkin\\OAuth::config.minutes'));

            $form->text('oauth_refresh_token_lifetime', trans('BlessingSkin\\OAuth::config.refresh-token-lifetime'))
                ->hint(trans('BlessingSkin\\OAuth::config.refresh-token-lifetime-hint'))
                ->description(trans('BlessingSkin\\OAuth::config.days'));
        })->handle();

        return view('BlessingSkin\\OAuth::config', compact('form'));
    }
}
