<?php

namespace BlessingSkin\AuthService\Controllers;

use App\Models\Player;
use App\Models\Texture;
use App\Models\User;
use BlessingSkin\AuthService\AuthCode;
use BlessingSkin\AuthService\Authorization;
use BlessingSkin\AuthService\Client;
use BlessingSkin\AuthService\JwtService;
use BlessingSkin\AuthService\OidcService;
use BlessingSkin\AuthService\RefreshToken;
use BlessingSkin\AuthService\Token;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

/**
 * OAuth 控制器
 *
 * 此控制器处理 OAuth 2.0 授权流程的各个环节，包括：
 * 1. 显示授权页面
 * 2. 处理用户的授权决定
 * 3. 颁发访问令牌和刷新令牌
 * 4. 提供用户信息 API 端点
 */
class OAuthController extends Controller
{
    /**
     * JWT 服务实例
     *
     * @var \BlessingSkin\AuthService\JwtService
     */
    protected $jwtService;

    /**
     * OIDC 服务实例
     *
     * @var \BlessingSkin\AuthService\OidcService
     */
    protected $oidcService;

    /**
     * 创建一个新的控制器实例
     *
     * @param  \BlessingSkin\AuthService\JwtService  $jwtService
     * @param  \BlessingSkin\AuthService\OidcService  $oidcService
     * @return void
     */
    public function __construct(JwtService $jwtService, OidcService $oidcService)
    {
        $this->jwtService = $jwtService;
        $this->oidcService = $oidcService;

        // 添加CSRF保护，但排除令牌端点和用户信息端点
        $this->middleware('web');
        $this->middleware('csrf')->except(['issueToken', 'getUserInfo']);
    }
    /**
     * 显示授权页面
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\View\View|\Illuminate\Http\RedirectResponse
     */
    public function showAuthorizePage(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'client_id' => 'required|string',
            'redirect_uri' => 'required|string|url',
            'response_type' => 'required|string|in:code,token',
            'scope' => 'nullable|string',
            'state' => 'nullable|string',
            'nonce' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return redirect()->to($request->input('redirect_uri', '/'))
                ->withErrors($validator)
                ->withInput();
        }

        $client = Client::where('client_id', $request->input('client_id'))
            ->where('revoked', false)
            ->first();

        if (!$client) {
            return redirect()->to($request->input('redirect_uri'))
                ->with('error', trans('BlessingSkin\\AuthService::oauth.client-not-found'));
        }

        if ($client->redirect_uri !== $request->input('redirect_uri')) {
            return redirect()->to($request->input('redirect_uri'))
                ->with('error', trans('BlessingSkin\\AuthService::oauth.redirect-uri-mismatch'));
        }

        if (!Auth::check()) {
            return redirect()->route('auth.login')
                ->with('redirect', $request->fullUrl());
        }

        return view('BlessingSkin\\AuthService::oauth.authorize', [
            'client' => $client,
            'request' => $request->all(),
        ]);
    }

    /**
     * 处理授权请求
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function handleAuthorize(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'client_id' => 'required|string',
            'redirect_uri' => 'required|string|url',
            'response_type' => 'required|string|in:code,token',
            'scope' => 'nullable|string',
            'state' => 'nullable|string',
            'nonce' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return redirect()->to($request->input('redirect_uri', '/'))
                ->withErrors($validator)
                ->withInput();
        }

        $client = Client::where('client_id', $request->input('client_id'))
            ->where('revoked', false)
            ->first();

        if (!$client) {
            return redirect()->to($request->input('redirect_uri'))
                ->with('error', trans('BlessingSkin\\AuthService::oauth.client-not-found'));
        }

        if ($client->redirect_uri !== $request->input('redirect_uri')) {
            return redirect()->to($request->input('redirect_uri'))
                ->with('error', trans('BlessingSkin\\AuthService::oauth.redirect-uri-mismatch'));
        }

        if (!Auth::check()) {
            return redirect()->route('auth.login')
                ->with('redirect', $request->fullUrl());
        }

        // 用户拒绝授权
        if ($request->input('action') === 'deny') {
            $query = http_build_query([
                'error' => 'access_denied',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.access-denied'),
                'state' => $request->input('state'),
            ]);

            return redirect()->to($client->redirect_uri . '?' . $query);
        }

        // 验证作用域
        $scopes = $request->input('scope', '');
        $validScopes = $this->oidcService->validateScopes($scopes);
        $scopesString = implode(' ', $validScopes);

        // 获取nonce
        $nonce = $request->input('nonce');

        // 创建或更新授权记录
        Authorization::updateOrCreate(
            ['user_id' => Auth::id(), 'client_id' => $client->id],
            ['user_id' => Auth::id(), 'client_id' => $client->id]
        );

        // 根据响应类型处理
        if ($request->input('response_type') === 'code') {
            // 授权码模式
            $authCode = AuthCode::create([
                'id' => Str::random(40),
                'user_id' => Auth::id(),
                'client_id' => $client->id,
                'scopes' => $scopesString,
                'revoked' => false,
                'expires_at' => Carbon::now()->addMinutes(10),
                'nonce' => $nonce,
            ]);

            $query = http_build_query([
                'code' => $authCode->id,
                'state' => $request->input('state'),
            ]);

            return redirect()->to($client->redirect_uri . '?' . $query);
        } else {
            // 隐式授权模式
            try {
                // 生成访问令牌
                $accessToken = $this->jwtService->generateAccessToken(
                    Auth::id(),
                    $client->id,
                    $scopesString
                );
            } catch (\Exception $e) {
                return redirect()->to($client->redirect_uri . '?' . http_build_query([
                    'error' => 'server_error',
                    'error_description' => $e->getMessage(),
                    'state' => $request->input('state'),
                ]));
            }

            // 创建访问令牌记录
            $token = Token::create([
                'id' => $accessToken,
                'user_id' => Auth::id(),
                'client_id' => $client->id,
                'scopes' => $scopesString,
                'revoked' => false,
                'expires_at' => Carbon::now()->addMinutes(option('oauth_token_lifetime', 60)),
            ]);

            // 准备响应参数
            $responseParams = [
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => Carbon::now()->diffInSeconds($token->expires_at),
                'scope' => $token->scopes,
                'state' => $request->input('state'),
            ];

            // 如果请求包含 openid 作用域，生成 ID 令牌
            $isOpenId = in_array('openid', $validScopes);
            if ($isOpenId && $nonce) {
                // 准备用户数据 - 只存储必要信息，其他信息通过userinfo端点获取
                $user = Auth::user();
                $userData = [];

                // 生成 ID 令牌
                try {
                    $idToken = $this->jwtService->generateIdToken(
                        Auth::id(),
                        $client->id,
                        $userData,
                        $nonce
                    );

                    $responseParams['id_token'] = $idToken;
                } catch (\Exception $e) {
                    return redirect()->to($client->redirect_uri . '?' . http_build_query([
                        'error' => 'server_error',
                        'error_description' => $e->getMessage(),
                        'state' => $request->input('state'),
                    ]));
                }
            }

            // 使用URL片段（fragment）而不是查询参数
            return redirect()->to($client->redirect_uri . '#' . http_build_query($responseParams));
        }
    }

    /**
     * 颁发访问令牌
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function issueToken(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'grant_type' => 'required|string|in:authorization_code,refresh_token,client_credentials,password',
            'client_id' => 'required|string',
            'client_secret' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        $client = Client::where('client_id', $request->input('client_id'))
            ->where('client_secret', $request->input('client_secret'))
            ->where('revoked', false)
            ->first();

        if (!$client) {
            return response()->json([
                'error' => 'invalid_client',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-client'),
            ], 401);
        }

        // 根据授权类型分发到不同的处理方法
        switch ($request->input('grant_type')) {
            case 'authorization_code':
                return $this->handleAuthorizationCode($request, $client);
            case 'refresh_token':
                return $this->handleRefreshToken($request, $client);
            case 'client_credentials':
                return $this->handleClientCredentials($request, $client);
            case 'password':
                return $this->handlePassword($request, $client);
            default:
                return response()->json([
                    'error' => 'unsupported_grant_type',
                    'error_description' => trans('BlessingSkin\\AuthService::oauth.unsupported-grant-type'),
                ], 400);
        }
    }

    /**
     * 处理授权码授权类型
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \BlessingSkin\AuthService\Client  $client
     * @return \Illuminate\Http\JsonResponse
     */
    protected function handleAuthorizationCode(Request $request, Client $client)
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string',
            'redirect_uri' => 'required|string|url',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        $authCode = AuthCode::where('id', $request->input('code'))
            ->where('client_id', $client->id)
            ->where('revoked', false)
            ->where('expires_at', '>', Carbon::now())
            ->first();

        if (!$authCode) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-auth-code'),
            ], 400);
        }

        if ($client->redirect_uri !== $request->input('redirect_uri')) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.redirect-uri-mismatch'),
            ], 400);
        }

        // 撤销授权码
        $authCode->update(['revoked' => true]);

        // 获取用户信息
        $user = User::find($authCode->user_id);
        if (!$user) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.user-not-found'),
            ], 400);
        }

        // 检查作用域
        $scopes = explode(' ', $authCode->scopes);
        $isOpenId = in_array('openid', $scopes);

        // 生成访问令牌
        try {
            $accessToken = $this->jwtService->generateAccessToken(
                $authCode->user_id,
                $client->id,
                $authCode->scopes
            );
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => $e->getMessage(),
            ], 500);
        }

        // 创建访问令牌记录
        $token = Token::create([
            'id' => $accessToken,
            'user_id' => $authCode->user_id,
            'client_id' => $client->id,
            'scopes' => $authCode->scopes,
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(option('oauth_token_lifetime', 60)),
        ]);

        // 生成JWT刷新令牌
        try {
            $refreshTokenJwt = $this->jwtService->generateRefreshToken(
                $authCode->user_id,
                $client->id,
                $token->id
            );
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => $e->getMessage(),
            ], 500);
        }

        // 创建刷新令牌记录
        $refreshToken = RefreshToken::create([
            'id' => $refreshTokenJwt,
            'access_token_id' => $token->id,
            'revoked' => false,
            'expires_at' => Carbon::now()->addDays(option('oauth_refresh_token_lifetime', 30)),
        ]);

        // 准备响应
        $response = [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => Carbon::now()->diffInSeconds($token->expires_at),
            'refresh_token' => $refreshTokenJwt,
            'scope' => $token->scopes,
        ];

        // 如果请求包含 openid 作用域，生成 ID 令牌
        if ($isOpenId) {
            // 检查是否有 nonce
            if (empty($authCode->nonce)) {
                return response()->json([
                    'error' => 'invalid_request',
                    'error_description' => trans('BlessingSkin\\AuthService::oauth.missing-nonce'),
                ], 400);
            }

            // 准备用户数据 - 只存储必要信息，其他信息通过userinfo端点获取
            $userData = [];

            // 生成 ID 令牌
            try {
                $idToken = $this->jwtService->generateIdToken(
                    $authCode->user_id,
                    $client->id,
                    $userData,
                    $authCode->nonce
                );

                $response['id_token'] = $idToken;
            } catch (\Exception $e) {
                return response()->json([
                    'error' => 'server_error',
                    'error_description' => $e->getMessage(),
                ], 500);
            }
        }

        return response()->json($response);
    }

    /**
     * 处理刷新令牌授权类型
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \BlessingSkin\AuthService\Client  $client
     * @return \Illuminate\Http\JsonResponse
     */
    protected function handleRefreshToken(Request $request, Client $client)
    {
        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        $refreshTokenJwt = $request->input('refresh_token');

        // 验证JWT刷新令牌
        $payload = $this->jwtService->validateToken($refreshTokenJwt);

        if (!$payload || $payload->token_type !== 'refresh_token') {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-refresh-token'),
            ], 400);
        }

        // 检查令牌是否被撤销
        $refreshToken = RefreshToken::where('id', $refreshTokenJwt)
            ->where('revoked', false)
            ->first();

        if (!$refreshToken) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-refresh-token'),
            ], 400);
        }

        $accessToken = $refreshToken->accessToken;

        if (!$accessToken || $accessToken->client_id !== $client->id) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-refresh-token'),
            ], 400);
        }

        // 检查令牌是否属于当前客户端
        if ($payload->aud !== (string)$client->id) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-refresh-token'),
            ], 400);
        }

        // 撤销旧令牌
        $accessToken->update(['revoked' => true]);
        $refreshToken->update(['revoked' => true]);

        // 获取用户信息
        $user = User::find($accessToken->user_id);
        if (!$user) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.user-not-found'),
            ], 400);
        }

        // 检查作用域
        $scopes = explode(' ', $accessToken->scopes);
        $isOpenId = in_array('openid', $scopes);

        // 生成新的访问令牌
        try {
            $newAccessToken = $this->jwtService->generateAccessToken(
                $accessToken->user_id,
                $client->id,
                $accessToken->scopes
            );
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => $e->getMessage(),
            ], 500);
        }

        // 创建新的访问令牌记录
        $token = Token::create([
            'id' => $newAccessToken,
            'user_id' => $accessToken->user_id,
            'client_id' => $client->id,
            'scopes' => $accessToken->scopes,
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(option('oauth_token_lifetime', 60)),
        ]);

        // 生成新的JWT刷新令牌
        try {
            $newRefreshTokenJwt = $this->jwtService->generateRefreshToken(
                $accessToken->user_id,
                $client->id,
                $token->id
            );
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => $e->getMessage(),
            ], 500);
        }

        // 创建新的刷新令牌记录
        $newRefreshToken = RefreshToken::create([
            'id' => $newRefreshTokenJwt,
            'access_token_id' => $token->id,
            'revoked' => false,
            'expires_at' => Carbon::now()->addDays(option('oauth_refresh_token_lifetime', 30)),
        ]);

        // 准备响应
        $response = [
            'access_token' => $newAccessToken,
            'token_type' => 'Bearer',
            'expires_in' => Carbon::now()->diffInSeconds($token->expires_at),
            'refresh_token' => $newRefreshTokenJwt,
            'scope' => $token->scopes,
        ];

        // 如果请求包含 openid 作用域，生成新的 ID 令牌
        if ($isOpenId) {
            // 获取原始授权码中的nonce
            $authCode = AuthCode::where('user_id', $accessToken->user_id)
                ->where('client_id', $client->id)
                ->orderBy('expires_at', 'desc')
                ->first();

            $nonce = $authCode ? $authCode->nonce : $this->oidcService->generateNonce();

            // 准备用户数据 - 只存储必要信息，其他信息通过userinfo端点获取
            $userData = [];

            // 生成 ID 令牌
            try {
                $idToken = $this->jwtService->generateIdToken(
                    $accessToken->user_id,
                    $client->id,
                    $userData,
                    $nonce
                );

                $response['id_token'] = $idToken;
            } catch (\Exception $e) {
                return response()->json([
                    'error' => 'server_error',
                    'error_description' => $e->getMessage(),
                ], 500);
            }
        }

        return response()->json($response);
    }

    /**
     * 处理客户端凭证授权类型
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \BlessingSkin\AuthService\Client  $client
     * @return \Illuminate\Http\JsonResponse
     */
    protected function handleClientCredentials(Request $request, Client $client)
    {
        $validator = Validator::make($request->all(), [
            'scope' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        // 验证作用域
        $scopes = $request->input('scope', '');
        $validScopes = $this->oidcService->validateScopes($scopes);

        // 客户端凭证模式不应该包含用户相关的作用域
        $validScopes = array_filter($validScopes, function($scope) {
            return !in_array($scope, ['openid', 'profile', 'email']);
        });

        $scopesString = implode(' ', $validScopes);

        // 生成访问令牌
        try {
            $accessToken = $this->jwtService->generateClientCredentialsToken(
                $client->id,
                $scopesString
            );
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => $e->getMessage(),
            ], 500);
        }

        // 创建访问令牌记录
        $token = Token::create([
            'id' => $accessToken,
            'user_id' => null, // 客户端凭证模式没有关联用户
            'client_id' => $client->id,
            'scopes' => $scopesString,
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(option('oauth_token_lifetime', 60)),
        ]);

        // 准备响应
        $response = [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => Carbon::now()->diffInSeconds($token->expires_at),
            'scope' => $token->scopes,
        ];

        return response()->json($response);
    }

    /**
     * 处理密码授权类型
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \BlessingSkin\AuthService\Client  $client
     * @return \Illuminate\Http\JsonResponse
     */
    protected function handlePassword(Request $request, Client $client)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string',
            'password' => 'required|string',
            'scope' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        // 验证用户凭证
        $credentials = [
            'email' => $request->input('username'),
            'password' => $request->input('password'),
        ];

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-credentials'),
            ], 400);
        }

        $user = Auth::user();

        // 验证作用域
        $scopes = $request->input('scope', '');
        $validScopes = $this->oidcService->validateScopes($scopes);
        $scopesString = implode(' ', $validScopes);
        $isOpenId = in_array('openid', $validScopes);

        // 创建或更新授权记录
        Authorization::updateOrCreate(
            ['user_id' => $user->uid, 'client_id' => $client->id],
            ['user_id' => $user->uid, 'client_id' => $client->id]
        );

        // 生成访问令牌
        try {
            $accessToken = $this->jwtService->generateAccessToken(
                $user->uid,
                $client->id,
                $scopesString
            );
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => $e->getMessage(),
            ], 500);
        }

        // 创建访问令牌记录
        $token = Token::create([
            'id' => $accessToken,
            'user_id' => $user->uid,
            'client_id' => $client->id,
            'scopes' => $scopesString,
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(option('oauth_token_lifetime', 60)),
        ]);

        // 生成JWT刷新令牌
        try {
            $refreshTokenJwt = $this->jwtService->generateRefreshToken(
                $user->uid,
                $client->id,
                $token->id
            );
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => $e->getMessage(),
            ], 500);
        }

        // 创建刷新令牌记录
        $refreshToken = RefreshToken::create([
            'id' => $refreshTokenJwt,
            'access_token_id' => $token->id,
            'revoked' => false,
            'expires_at' => Carbon::now()->addDays(option('oauth_refresh_token_lifetime', 30)),
        ]);

        // 准备响应
        $response = [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => Carbon::now()->diffInSeconds($token->expires_at),
            'refresh_token' => $refreshTokenJwt,
            'scope' => $token->scopes,
        ];

        // 如果请求包含 openid 作用域，生成 ID 令牌
        if ($isOpenId) {
            // 生成随机nonce
            $nonce = $this->oidcService->generateNonce();

            // 准备用户数据 - 只存储必要信息，其他信息通过userinfo端点获取
            $userData = [];

            // 生成 ID 令牌
            try {
                $idToken = $this->jwtService->generateIdToken(
                    $user->uid,
                    $client->id,
                    $userData,
                    $nonce
                );

                $response['id_token'] = $idToken;
            } catch (\Exception $e) {
                return response()->json([
                    'error' => 'server_error',
                    'error_description' => $e->getMessage(),
                ], 500);
            }
        }

        return response()->json($response);
    }

    /**
     * 获取用户信息
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function getUserInfo(Request $request)
    {
        // 从 Authorization 头中获取 Bearer 令牌
        $header = $request->header('Authorization', '');
        $bearerToken = null;

        if (strpos($header, 'Bearer ') === 0) {
            $bearerToken = substr($header, 7);
        }

        if (!$bearerToken) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.missing-token'),
            ], 401);
        }

        // 验证JWT令牌
        $payload = $this->jwtService->validateToken($bearerToken);

        if (!$payload) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-token'),
            ], 401);
        }

        // 检查令牌是否被撤销
        $token = Token::where('id', $bearerToken)
            ->where('revoked', false)
            ->first();

        if (!$token) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.invalid-token'),
            ], 401);
        }

        // 获取用户信息
        $user = User::find($payload->sub);

        if (!$user) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => trans('BlessingSkin\\AuthService::oauth.user-not-found'),
            ], 401);
        }

        // 检查作用域
        $scopes = explode(' ', $payload->scope);
        $hasProfile = in_array('profile', $scopes);
        $hasEmail = in_array('email', $scopes);

        // 准备响应
        $response = [
            'sub' => (string)$user->uid,
        ];

        // 根据作用域添加信息
        if ($hasProfile) {
            // 将nickname重命名为display_name，保持一致性
            $response['display_name'] = $user->nickname;
            $response['preferred_username'] = $user->nickname;

            // 添加用户语言设置
            $response['locale'] = $user->locale;

            // 获取用户头像URL
            if ($user->avatar) {
                $texture = Texture::find($user->avatar);
                if ($texture) {
                    try {
                        // 根据测试脚本中的方式生成头像URL
                        $avatarUrl = route('avatar.texture', [
                            'tid' => $user->avatar,
                            'size' => 36,
                            'png' => true
                        ]);
                        $response['picture'] = $avatarUrl;
                        $response['avatar_url'] = $avatarUrl;
                    } catch (\Exception $e) {
                        // 如果出错，使用用户头像URL
                        $avatarUrl = route('avatar.user', [
                            'uid' => $user->uid,
                            'size' => 36,
                            'png' => true
                        ]);
                        $response['picture'] = $avatarUrl;
                        $response['avatar_url'] = $avatarUrl;
                    }
                } else {
                    // 如果材质不存在，使用用户头像URL
                    $avatarUrl = route('avatar.user', [
                        'uid' => $user->uid,
                        'size' => 36,
                        'png' => true
                    ]);
                    $response['picture'] = $avatarUrl;
                    $response['avatar_url'] = $avatarUrl;
                }
            } else {
                // 如果用户没有设置头像，使用默认头像
                $avatarUrl = route('avatar.user', [
                    'uid' => $user->uid,
                    'size' => 36,
                    'png' => true
                ]);
                $response['picture'] = $avatarUrl;
                $response['avatar_url'] = $avatarUrl;
            }

            $response['updated_at'] = $user->updated_at->getTimestamp();

            // 获取用户所有角色信息
            $players = $user->players;
            if ($players && !$players->isEmpty()) {
                $playersData = [];

                foreach ($players as $player) {
                    $playerData = [
                        'uid' => (string)$player->pid,
                        'name' => $player->name,
                    ];

                    // 获取玩家UUID
                    if (Schema::hasTable('uuid')) {
                        $uuid = DB::table('uuid')->where('name', $player->name)->value('uuid');
                        if ($uuid) {
                            $playerData['uuid'] = $uuid;
                        }
                    }

                    // 获取皮肤URL
                    if ($player->tid_skin) {
                        $skinTexture = Texture::find($player->tid_skin);
                        if ($skinTexture) {
                            try {
                                // 使用预览URL作为皮肤URL
                                $playerData['skin_url'] = route('preview.texture', [
                                    'texture' => $skinTexture,
                                    'png' => true
                                ]);
                            } catch (\Exception $e) {
                                // 如果预览生成失败，尝试使用原始材质URL
                                try {
                                    $playerData['skin_url'] = url("/textures/{$skinTexture->hash}");
                                } catch (\Exception $e2) {
                                    // 如果预览和原始材质URL都失败，返回空串
                                    $playerData['skin_url'] = '';
                                }
                            }
                        } else {
                            // 材质不存在，返回空串
                            $playerData['skin_url'] = '';
                        }
                    }

                    // 获取披风URL
                    if ($player->tid_cape) {
                        $capeTexture = Texture::find($player->tid_cape);
                        if ($capeTexture) {
                            try {
                                // 使用预览URL作为披风URL
                                $playerData['cape_url'] = route('preview.texture', [
                                    'texture' => $capeTexture,
                                    'png' => true
                                ]);
                            } catch (\Exception $e) {
                                // 如果预览生成失败，尝试使用原始材质URL
                                try {
                                    $playerData['cape_url'] = url("/textures/{$capeTexture->hash}");
                                } catch (\Exception $e2) {
                                    // 如果预览和原始材质URL都失败，返回空串
                                    $playerData['cape_url'] = '';
                                }
                            }
                        } else {
                            // 材质不存在，返回空串
                            $playerData['cape_url'] = '';
                        }
                    }

                    $playersData[] = $playerData;
                }

                $response['players'] = $playersData;
            }
        }

        if ($hasEmail) {
            $response['email'] = $user->email;
            $response['email_verified'] = (bool)$user->verified;
        }

        return response()->json($response);
    }
}
