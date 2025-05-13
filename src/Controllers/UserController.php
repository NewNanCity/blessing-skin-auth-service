<?php

namespace BlessingSkin\AuthService\Controllers;

use BlessingSkin\AuthService\Authorization;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * OAuth 用户控制器
 *
 * 此控制器处理用户对自己授权的 OAuth 应用的管理，包括：
 * 1. 查看授权列表
 * 2. 撤销授权
 */
class UserController extends Controller
{
    /**
     * 显示用户的授权列表
     *
     * @return \Illuminate\View\View
     */
    public function showAuthorizationList()
    {
        $authorizations = Authorization::with('client')
            ->where('user_id', Auth::id())
            ->get();

        return view('BlessingSkin\\AuthService::user.authorizations', [
            'authorizations' => $authorizations
        ]);
    }

    /**
     * 撤销授权
     *
     * @param  int  $id
     * @return \Illuminate\Http\JsonResponse
     */
    public function revokeAuthorization($id)
    {
        $authorization = Authorization::where('user_id', Auth::id())
            ->findOrFail($id);

        // 撤销所有相关的令牌
        $clientId = $authorization->client_id;
        $userId = Auth::id();

        // 撤销授权码
        \BlessingSkin\AuthService\AuthCode::where('user_id', $userId)
            ->where('client_id', $clientId)
            ->update(['revoked' => true]);

        // 撤销访问令牌
        \BlessingSkin\AuthService\Token::where('user_id', $userId)
            ->where('client_id', $clientId)
            ->update(['revoked' => true]);

        // 删除授权记录
        $authorization->delete();

        return response()->json([
            'code' => 0,
            'message' => trans('BlessingSkin\\AuthService::user.authorization-revoked'),
        ]);
    }
}
