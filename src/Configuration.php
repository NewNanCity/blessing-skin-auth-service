<?php

namespace BlessingSkin\AuthService;

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
        // 基本配置表单
        $basicForm = Option::form('basic', trans('BlessingSkin\\AuthService::config.basic.title'), function (OptionForm $form) {
            $form->text('oauth_token_lifetime', trans('BlessingSkin\\AuthService::config.basic.token-lifetime'))
                ->hint(trans('BlessingSkin\\AuthService::config.basic.token-lifetime-hint'))
                ->description(trans('BlessingSkin\\AuthService::config.minutes'));

            $form->text('oauth_refresh_token_lifetime', trans('BlessingSkin\\AuthService::config.basic.refresh-token-lifetime'))
                ->hint(trans('BlessingSkin\\AuthService::config.basic.refresh-token-lifetime-hint'))
                ->description(trans('BlessingSkin\\AuthService::config.days'));
        })->handle();

        // OIDC配置表单
        $oidcForm = Option::form('oidc', trans('BlessingSkin\\AuthService::config.oidc.title'), function (OptionForm $form) {
            $form->text('oauth_id_token_lifetime', trans('BlessingSkin\\AuthService::config.oidc.id-token-lifetime'))
                ->hint(trans('BlessingSkin\\AuthService::config.oidc.id-token-lifetime-hint'))
                ->description(trans('BlessingSkin\\AuthService::config.minutes'));

            $form->text('oauth_issuer', trans('BlessingSkin\\AuthService::config.oidc.issuer'))
                ->hint(trans('BlessingSkin\\AuthService::config.oidc.issuer-hint'));
        })->handle();

        // JWT密钥管理表单
        $jwtForm = Option::form('jwt', trans('BlessingSkin\\AuthService::config.jwt.title'), function (OptionForm $form) {
            $form->addButton([
                'style' => 'primary',
                'text' => trans('BlessingSkin\\AuthService::config.jwt.generate-new-key'),
                'name' => 'btn-generate-key'
            ])->hint(trans('BlessingSkin\\AuthService::config.jwt.generate-new-key-hint'));

            $form->addButton([
                'style' => 'warning',
                'text' => trans('BlessingSkin\\AuthService::config.jwt.cleanup-tokens'),
                'name' => 'btn-cleanup-tokens'
            ])->hint(trans('BlessingSkin\\AuthService::config.jwt.cleanup-tokens-hint'));
        })->handle();

        // SAML配置表单
        $samlForm = Option::form('saml', trans('BlessingSkin\\AuthService::config.saml.title'), function (OptionForm $form) {
            $form->checkbox('oauth_saml_enabled', trans('BlessingSkin\\AuthService::config.saml.enabled'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.enabled-hint'));

            $form->text('oauth_saml_entity_id', trans('BlessingSkin\\AuthService::config.saml.entity-id'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.entity-id-hint'))
                ->value(url('/saml/metadata'));

            $form->text('oauth_saml_idp_entity_id', trans('BlessingSkin\\AuthService::config.saml.idp-entity-id'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.idp-entity-id-hint'));

            $form->text('oauth_saml_idp_sso_url', trans('BlessingSkin\\AuthService::config.saml.idp-sso-url'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.idp-sso-url-hint'));

            $form->text('oauth_saml_idp_slo_url', trans('BlessingSkin\\AuthService::config.saml.idp-slo-url'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.idp-slo-url-hint'));

            $form->textarea('oauth_saml_idp_x509cert', trans('BlessingSkin\\AuthService::config.saml.idp-x509cert'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.idp-x509cert-hint'))
                ->rows(5);

            $form->select('oauth_saml_nameid_format', trans('BlessingSkin\\AuthService::config.saml.nameid-format'))
                ->option('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', 'Email Address')
                ->option('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', 'Persistent')
                ->option('urn:oasis:names:tc:SAML:2.0:nameid-format:transient', 'Transient')
                ->hint(trans('BlessingSkin\\AuthService::config.saml.nameid-format-hint'));

            $form->text('oauth_saml_attr_email', trans('BlessingSkin\\AuthService::config.saml.attr-email'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.attr-email-hint'))
                ->value('email');

            $form->text('oauth_saml_attr_name', trans('BlessingSkin\\AuthService::config.saml.attr-name'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.attr-name-hint'))
                ->value('displayName');

            $form->checkbox('oauth_saml_auto_register', trans('BlessingSkin\\AuthService::config.saml.auto-register'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml.auto-register-hint'));
        })->handle();

        // SAML证书管理表单
        $samlCertForm = Option::form('saml-cert', trans('BlessingSkin\\AuthService::config.saml-cert.title'), function (OptionForm $form) {
            $form->textarea('oauth_saml_x509cert', trans('BlessingSkin\\AuthService::config.saml-cert.x509cert'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml-cert.x509cert-hint'))
                ->rows(5);

            $form->textarea('oauth_saml_private_key', trans('BlessingSkin\\AuthService::config.saml-cert.private-key'))
                ->hint(trans('BlessingSkin\\AuthService::config.saml-cert.private-key-hint'))
                ->rows(5);

            $form->addButton([
                'style' => 'primary',
                'text' => trans('BlessingSkin\\AuthService::config.saml-cert.generate'),
                'name' => 'btn-generate-saml-cert'
            ])->hint(trans('BlessingSkin\\AuthService::config.saml-cert.generate-hint'));
        })->handle();

        // 添加表单类型
        $basicForm->type('info');
        $oidcForm->type('info');
        $jwtForm->type('warning');
        $samlForm->type('primary');
        $samlCertForm->type('danger');

        // 添加JavaScript文件
        \App\Services\Hook::addScriptFileToPage(
            plugin('blessing-skin-auth-service')->assets('config.js'),
            ['admin/oauth']
        );

        return view('BlessingSkin\\AuthService::config', [
            'forms' => [
                'basic' => $basicForm,
                'oidc' => $oidcForm,
                'jwt' => $jwtForm,
                'saml' => $samlForm,
                'saml_cert' => $samlCertForm
            ]
        ]);
    }
}
