<?php

namespace BlessingSkin\AuthService\Controllers;

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
            'response_type' => 'required|string|in:code',
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
            'response_type' => 'required|string|in:code',
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

        // 创建授权码
        $authCode = AuthCode::create([
            'id' => Str::random(40),
            'user_id' => Auth::id(),
            'client_id' => $client->id,
            'scopes' => $scopesString,
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(10),
            'nonce' => $nonce,
        ]);

        // 创建或更新授权记录
        Authorization::updateOrCreate(
            ['user_id' => Auth::id(), 'client_id' => $client->id],
            ['user_id' => Auth::id(), 'client_id' => $client->id]
        );

        $query = http_build_query([
            'code' => $authCode->id,
            'state' => $request->input('state'),
        ]);

        return redirect()->to($client->redirect_uri . '?' . $query);
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
            'grant_type' => 'required|string|in:authorization_code,refresh_token',
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

        if ($request->input('grant_type') === 'authorization_code') {
            return $this->handleAuthorizationCode($request, $client);
        }

        if ($request->input('grant_type') === 'refresh_token') {
            return $this->handleRefreshToken($request, $client);
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

            // 准备用户数据
            $userData = [
                'email' => $user->email,
                'nickname' => $user->nickname,
            ];

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

            // 准备用户数据
            $userData = [
                'email' => $user->email,
                'nickname' => $user->nickname,
            ];

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
            $response['name'] = $user->nickname;
            $response['preferred_username'] = $user->nickname;
            $response['picture'] = $user->avatar;
            $response['updated_at'] = $user->updated_at->getTimestamp();
        }

        if ($hasEmail) {
            $response['email'] = $user->email;
            $response['email_verified'] = (bool)$user->verified;
        }

        return response()->json($response);
    }
}
