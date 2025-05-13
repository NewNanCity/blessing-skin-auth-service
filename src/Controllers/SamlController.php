<?php

namespace BlessingSkin\AuthService\Controllers;

use BlessingSkin\AuthService\SamlService;
use BlessingSkin\AuthService\Client;
use BlessingSkin\AuthService\Authorization;
use BlessingSkin\AuthService\AuthCode;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use OneLogin\Saml2\Error;

/**
 * SAML 控制器
 *
 * 此控制器处理 SAML 相关的请求
 */
class SamlController extends Controller
{
    /**
     * SAML 服务实例
     *
     * @var \BlessingSkin\AuthService\SamlService
     */
    protected $samlService;

    /**
     * 创建一个新的控制器实例
     *
     * @param  \BlessingSkin\AuthService\SamlService  $samlService
     * @return void
     */
    public function __construct(SamlService $samlService)
    {
        $this->samlService = $samlService;
    }

    /**
     * 显示SAML元数据
     *
     * @return \Illuminate\Http\Response
     */
    public function metadata()
    {
        try {
            $metadata = $this->samlService->getMetadata();
            return response($metadata, 200, ['Content-Type' => 'text/xml']);
        } catch (\Exception $e) {
            Log::error(trans('BlessingSkin\\AuthService::saml.metadata-generation-failed') . ': ' . $e->getMessage());
            abort(500, trans('BlessingSkin\\AuthService::saml.metadata-error'));
        }
    }

    /**
     * 发起SAML认证请求
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        // 检查是否是OAuth客户端请求
        $isOAuthRequest = $request->has('client_id') && $request->has('redirect_uri');

        if ($isOAuthRequest) {
            // 验证OAuth参数
            $request->validate([
                'client_id' => 'required|string',
                'redirect_uri' => 'required|string|url',
                'response_type' => 'required|string|in:code',
                'scope' => 'nullable|string',
                'state' => 'nullable|string',
                'nonce' => 'nullable|string',
            ]);

            // 查找客户端
            $client = Client::where('id', $request->input('client_id'))->first();

            if (!$client) {
                return redirect()->to($request->input('redirect_uri') . '?' . http_build_query([
                    'error' => 'invalid_client',
                    'error_description' => trans('BlessingSkin\\AuthService::oauth.client-not-found'),
                    'state' => $request->input('state'),
                ]));
            }

            // 验证重定向URI
            if ($client->redirect_uri !== $request->input('redirect_uri')) {
                return redirect()->to($request->input('redirect_uri') . '?' . http_build_query([
                    'error' => 'invalid_request',
                    'error_description' => trans('BlessingSkin\\AuthService::oauth.redirect-uri-mismatch'),
                    'state' => $request->input('state'),
                ]));
            }

            // 保存请求参数到会话
            session([
                'saml_client_id' => $client->id,
                'saml_redirect_uri' => $request->input('redirect_uri'),
                'saml_response_type' => $request->input('response_type'),
                'saml_scope' => $request->input('scope', ''),
                'saml_state' => $request->input('state', ''),
                'saml_nonce' => $request->input('nonce', ''),
            ]);
        }

        try {
            $auth = $this->samlService->getAuth();

            // 发起SAML认证请求
            $auth->login();
        } catch (Error $e) {
            Log::error(trans('BlessingSkin\\AuthService::saml.login-request-failed') . ': ' . $e->getMessage());

            return redirect()->to($request->input('redirect_uri') . '?' . http_build_query([
                'error' => 'server_error',
                'error_description' => trans('BlessingSkin\\AuthService::saml.login-error'),
                'state' => $request->input('state'),
            ]));
        }
    }

    /**
     * 处理SAML断言消费服务（ACS）请求
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function acs(Request $request)
    {
        try {
            $auth = $this->samlService->getAuth();

            // 处理SAML响应
            $auth->processResponse();

            $errors = $auth->getErrors();

            if (!empty($errors)) {
                Log::error(trans('BlessingSkin\\AuthService::saml.response-processing-error') . ': ' . implode(', ', $errors));
                throw new \Exception(trans('BlessingSkin\\AuthService::saml.response-processing-error') . ': ' . $auth->getLastErrorReason());
            }

            // 获取用户信息
            $userInfo = $this->samlService->processResponse($auth);

            if (!$userInfo['user']) {
                throw new \Exception(trans('BlessingSkin\\AuthService::saml.user-not-found'));
            }

            // 登录用户
            Auth::login($userInfo['user']);

            // 获取会话中的请求参数
            $clientId = session('saml_client_id');
            $redirectUri = session('saml_redirect_uri');
            $responseType = session('saml_response_type');
            $scope = session('saml_scope');
            $state = session('saml_state');
            $nonce = session('saml_nonce');

            // 清除会话中的请求参数
            session()->forget([
                'saml_client_id',
                'saml_redirect_uri',
                'saml_response_type',
                'saml_scope',
                'saml_state',
                'saml_nonce',
            ]);

            // 查找客户端
            $client = Client::find($clientId);

            if (!$client) {
                throw new \Exception(trans('BlessingSkin\\AuthService::saml.client-not-found'));
            }

            // 创建或更新授权记录
            Authorization::updateOrCreate(
                ['user_id' => Auth::id(), 'client_id' => $client->id],
                ['created_at' => Carbon::now(), 'updated_at' => Carbon::now()]
            );

            // 创建授权码
            $authCode = AuthCode::create([
                'id' => Str::random(40),
                'user_id' => Auth::id(),
                'client_id' => $client->id,
                'scopes' => $scope,
                'revoked' => false,
                'expires_at' => Carbon::now()->addMinutes(10),
                'nonce' => $nonce,
            ]);

            // 重定向回客户端
            return redirect()->to($redirectUri . '?' . http_build_query([
                'code' => $authCode->id,
                'state' => $state,
            ]));
        } catch (\Exception $e) {
            Log::error(trans('BlessingSkin\\AuthService::saml.acs-processing-error') . ': ' . $e->getMessage());

            $redirectUri = session('saml_redirect_uri');
            $state = session('saml_state');

            if ($redirectUri) {
                return redirect()->to($redirectUri . '?' . http_build_query([
                    'error' => 'server_error',
                    'error_description' => trans('BlessingSkin\\AuthService::saml.acs-error'),
                    'state' => $state,
                ]));
            } else {
                return redirect()->route('auth.login')->with('error', trans('BlessingSkin\\AuthService::saml.acs-error') . ': ' . $e->getMessage());
            }
        }
    }

    /**
     * 处理SAML单点登出（SLO）请求
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function slo(Request $request)
    {
        try {
            $auth = $this->samlService->getAuth();

            // 处理SAML SLO请求
            $auth->processSLO();

            $errors = $auth->getErrors();

            if (!empty($errors)) {
                Log::error(trans('BlessingSkin\\AuthService::saml.slo-processing-error') . ': ' . implode(', ', $errors));
                throw new \Exception(trans('BlessingSkin\\AuthService::saml.slo-processing-error') . ': ' . $auth->getLastErrorReason());
            }

            // 登出用户
            Auth::logout();

            return redirect()->route('auth.login')->with('success', trans('BlessingSkin\\AuthService::saml.logout-success'));
        } catch (\Exception $e) {
            Log::error(trans('BlessingSkin\\AuthService::saml.slo-processing-error') . ': ' . $e->getMessage());
            return redirect()->route('auth.login')->with('error', trans('BlessingSkin\\AuthService::saml.slo-error') . ': ' . $e->getMessage());
        }
    }
}
