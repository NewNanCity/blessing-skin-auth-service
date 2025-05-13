<?php

namespace BlessingSkin\AuthService\Controllers;

use BlessingSkin\AuthService\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * OAuth 管理员控制器
 *
 * 此控制器处理管理员对所有 OAuth 客户端应用的管理，包括：
 * 1. 查看所有客户端列表
 * 2. 创建新的客户端
 * 3. 更新现有客户端
 * 4. 删除客户端
 */
class AdminController extends Controller
{
    /**
     * 显示所有 OAuth 客户端列表
     *
     * @return \Illuminate\View\View
     */
    public function showClientList()
    {
        $clients = Client::all();

        return view('BlessingSkin\\AuthService::admin.clients', [
            'clients' => $clients
        ]);
    }

    /**
     * 创建新的 OAuth 客户端
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function createClient(Request $request)
    {
        $validator = \Illuminate\Support\Facades\Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'redirect_uri' => 'required|string|url',
            'description' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'code' => 1,
                'message' => $validator->errors()->first(),
            ]);
        }

        $client = Client::create([
            'name' => $request->input('name'),
            'redirect_uri' => $request->input('redirect_uri'),
            'description' => $request->input('description'),
        ]);

        return response()->json([
            'code' => 0,
            'message' => trans('BlessingSkin\\AuthService::admin.client-created'),
            'data' => $client,
        ]);
    }

    /**
     * 更新 OAuth 客户端
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\JsonResponse
     */
    public function updateClient(Request $request, $id)
    {
        $client = Client::findOrFail($id);

        $validator = \Illuminate\Support\Facades\Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'redirect_uri' => 'required|string|url',
            'description' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'code' => 1,
                'message' => $validator->errors()->first(),
            ]);
        }

        $client->update([
            'name' => $request->input('name'),
            'redirect_uri' => $request->input('redirect_uri'),
            'description' => $request->input('description'),
        ]);

        return response()->json([
            'code' => 0,
            'message' => trans('BlessingSkin\\AuthService::admin.client-updated'),
        ]);
    }

    /**
     * 删除 OAuth 客户端
     *
     * @param  int  $id
     * @return \Illuminate\Http\JsonResponse
     */
    public function deleteClient($id)
    {
        $client = Client::findOrFail($id);
        $client->delete();

        return response()->json([
            'code' => 0,
            'message' => trans('BlessingSkin\\AuthService::admin.client-deleted'),
        ]);
    }

    /**
     * 生成新的 JWT 密钥对
     *
     * @param \BlessingSkin\AuthService\JwtService $jwtService
     * @return \Illuminate\Http\JsonResponse
     */
    public function generateNewKey(\BlessingSkin\AuthService\JwtService $jwtService)
    {
        try {
            // 生成新的密钥对
            $jwtService->generateNewKeyPair();

            return response()->json([
                'code' => 0,
                'message' => trans('BlessingSkin\\AuthService::config.key-generated'),
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'code' => 1,
                'message' => $e->getMessage(),
            ]);
        }
    }

    /**
     * 清理过期和已撤销的令牌
     *
     * @param \BlessingSkin\AuthService\TokenCleanupService $cleanupService
     * @return \Illuminate\Http\JsonResponse
     */
    public function cleanupTokens(\BlessingSkin\AuthService\TokenCleanupService $cleanupService)
    {
        try {
            $stats = $cleanupService->cleanupAll();

            return response()->json([
                'code' => 0,
                'message' => trans('BlessingSkin\\AuthService::config.tokens-cleaned', ['count' => $stats['total']]),
                'data' => $stats,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'code' => 1,
                'message' => $e->getMessage(),
            ]);
        }
    }

    /**
     * 生成SAML证书
     *
     * @param \BlessingSkin\AuthService\SamlService $samlService
     * @return \Illuminate\Http\JsonResponse
     */
    public function generateSamlCertificate(\BlessingSkin\AuthService\SamlService $samlService)
    {
        try {
            // 生成自签名证书
            $cert = $samlService->generateSelfSignedCertificate();

            // 存储到选项中
            option(['oauth_saml_x509cert' => $cert['certificate']]);
            option(['oauth_saml_private_key' => $cert['privateKey']]);

            return response()->json([
                'code' => 0,
                'message' => trans('BlessingSkin\\AuthService::config.saml-cert-generated'),
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'code' => 1,
                'message' => $e->getMessage(),
            ]);
        }
    }
}
