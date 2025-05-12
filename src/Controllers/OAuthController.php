<?php

namespace BlessingSkin\OAuth\Controllers;

use App\Models\User;
use BlessingSkin\OAuth\AuthCode;
use BlessingSkin\OAuth\Authorization;
use BlessingSkin\OAuth\Client;
use BlessingSkin\OAuth\RefreshToken;
use BlessingSkin\OAuth\Token;
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
                ->with('error', trans('BlessingSkin\\OAuth::oauth.client-not-found'));
        }

        if ($client->redirect_uri !== $request->input('redirect_uri')) {
            return redirect()->to($request->input('redirect_uri'))
                ->with('error', trans('BlessingSkin\\OAuth::oauth.redirect-uri-mismatch'));
        }

        if (!Auth::check()) {
            return redirect()->route('auth.login')
                ->with('redirect', $request->fullUrl());
        }

        return view('BlessingSkin\\OAuth::oauth.authorize', [
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
                ->with('error', trans('BlessingSkin\\OAuth::oauth.client-not-found'));
        }

        if ($client->redirect_uri !== $request->input('redirect_uri')) {
            return redirect()->to($request->input('redirect_uri'))
                ->with('error', trans('BlessingSkin\\OAuth::oauth.redirect-uri-mismatch'));
        }

        if (!Auth::check()) {
            return redirect()->route('auth.login')
                ->with('redirect', $request->fullUrl());
        }

        // 用户拒绝授权
        if ($request->input('action') === 'deny') {
            $query = http_build_query([
                'error' => 'access_denied',
                'error_description' => trans('BlessingSkin\\OAuth::oauth.access-denied'),
                'state' => $request->input('state'),
            ]);

            return redirect()->to($client->redirect_uri . '?' . $query);
        }

        // 创建授权码
        $authCode = AuthCode::create([
            'id' => Str::random(40),
            'user_id' => Auth::id(),
            'client_id' => $client->id,
            'scopes' => $request->input('scope', ''),
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(10),
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
                'error_description' => trans('BlessingSkin\\OAuth::oauth.invalid-client'),
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
     * @param  \BlessingSkin\OAuth\Client  $client
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
                'error_description' => trans('BlessingSkin\\OAuth::oauth.invalid-auth-code'),
            ], 400);
        }

        if ($client->redirect_uri !== $request->input('redirect_uri')) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\OAuth::oauth.redirect-uri-mismatch'),
            ], 400);
        }

        // 撤销授权码
        $authCode->update(['revoked' => true]);

        // 创建访问令牌
        $token = Token::create([
            'id' => Str::random(40),
            'user_id' => $authCode->user_id,
            'client_id' => $client->id,
            'scopes' => $authCode->scopes,
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(option('oauth_token_lifetime', 60)),
        ]);

        // 创建刷新令牌
        $refreshToken = RefreshToken::create([
            'id' => Str::random(40),
            'access_token_id' => $token->id,
            'revoked' => false,
            'expires_at' => Carbon::now()->addDays(option('oauth_refresh_token_lifetime', 30)),
        ]);

        return response()->json([
            'access_token' => $token->id,
            'token_type' => 'Bearer',
            'expires_in' => Carbon::now()->diffInSeconds($token->expires_at),
            'refresh_token' => $refreshToken->id,
            'scope' => $token->scopes,
        ]);
    }

    /**
     * 处理刷新令牌授权类型
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \BlessingSkin\OAuth\Client  $client
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

        $refreshToken = RefreshToken::where('id', $request->input('refresh_token'))
            ->where('revoked', false)
            ->where('expires_at', '>', Carbon::now())
            ->first();

        if (!$refreshToken) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\OAuth::oauth.invalid-refresh-token'),
            ], 400);
        }

        $accessToken = $refreshToken->accessToken;

        if (!$accessToken || $accessToken->client_id !== $client->id) {
            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => trans('BlessingSkin\\OAuth::oauth.invalid-refresh-token'),
            ], 400);
        }

        // 撤销旧令牌
        $accessToken->update(['revoked' => true]);
        $refreshToken->update(['revoked' => true]);

        // 创建新的访问令牌
        $token = Token::create([
            'id' => Str::random(40),
            'user_id' => $accessToken->user_id,
            'client_id' => $client->id,
            'scopes' => $accessToken->scopes,
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(option('oauth_token_lifetime', 60)),
        ]);

        // 创建新的刷新令牌
        $newRefreshToken = RefreshToken::create([
            'id' => Str::random(40),
            'access_token_id' => $token->id,
            'revoked' => false,
            'expires_at' => Carbon::now()->addDays(option('oauth_refresh_token_lifetime', 30)),
        ]);

        return response()->json([
            'access_token' => $token->id,
            'token_type' => 'Bearer',
            'expires_in' => Carbon::now()->diffInSeconds($token->expires_at),
            'refresh_token' => $newRefreshToken->id,
            'scope' => $token->scopes,
        ]);
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
                'error_description' => trans('BlessingSkin\\OAuth::oauth.missing-token'),
            ], 401);
        }

        $token = Token::where('id', $bearerToken)
            ->where('revoked', false)
            ->where('expires_at', '>', Carbon::now())
            ->first();

        if (!$token) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => trans('BlessingSkin\\OAuth::oauth.invalid-token'),
            ], 401);
        }

        $user = User::find($token->user_id);

        if (!$user) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => trans('BlessingSkin\\OAuth::oauth.user-not-found'),
            ], 401);
        }

        return response()->json([
            'id' => $user->uid,
            'email' => $user->email,
            'nickname' => $user->nickname,
            'score' => $user->score,
            'avatar' => $user->avatar,
            'permission' => $user->permission,
            'verified' => $user->verified,
            'register_at' => $user->register_at->toIso8601String(),
        ]);
    }
}
