<?php

namespace BlessingSkin\AuthService\Controllers;

use BlessingSkin\AuthService\OidcService;
use Illuminate\Http\Request;

/**
 * OIDC 控制器
 *
 * 此控制器处理 OpenID Connect 相关的端点
 */
class OidcController extends Controller
{
    /**
     * OIDC 服务实例
     *
     * @var \BlessingSkin\AuthService\OidcService
     */
    protected $oidcService;

    /**
     * 创建一个新的控制器实例
     *
     * @param  \BlessingSkin\AuthService\OidcService  $oidcService
     * @return void
     */
    public function __construct(OidcService $oidcService)
    {
        $this->oidcService = $oidcService;
    }

    /**
     * 返回 OpenID Connect 配置
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function configuration()
    {
        return response()->json($this->oidcService->getConfiguration());
    }

    /**
     * 返回 JWKS（JSON Web Key Set）
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function jwks()
    {
        return response()->json($this->oidcService->getJwks());
    }
}
