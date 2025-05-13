<?php

namespace BlessingSkin\AuthService;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * 令牌清理服务
 *
 * 此类负责清理过期和已撤销的令牌
 */
class TokenCleanupService
{
    /**
     * 清理过期的授权码
     *
     * @return int 清理的记录数
     */
    public function cleanupExpiredAuthCodes()
    {
        $count = DB::table('oauth_auth_codes')
            ->where('expires_at', '<', Carbon::now())
            ->delete();

        return $count;
    }

    /**
     * 清理已撤销的授权码
     *
     * @return int 清理的记录数
     */
    public function cleanupRevokedAuthCodes()
    {
        $count = DB::table('oauth_auth_codes')
            ->where('revoked', true)
            ->delete();

        return $count;
    }

    /**
     * 清理过期的访问令牌
     *
     * @return int 清理的记录数
     */
    public function cleanupExpiredAccessTokens()
    {
        $count = DB::table('oauth_access_tokens')
            ->where('expires_at', '<', Carbon::now())
            ->delete();

        return $count;
    }

    /**
     * 清理已撤销的访问令牌
     *
     * @return int 清理的记录数
     */
    public function cleanupRevokedAccessTokens()
    {
        $count = DB::table('oauth_access_tokens')
            ->where('revoked', true)
            ->delete();

        return $count;
    }

    /**
     * 清理过期的刷新令牌
     *
     * @return int 清理的记录数
     */
    public function cleanupExpiredRefreshTokens()
    {
        $count = DB::table('oauth_refresh_tokens')
            ->where('expires_at', '<', Carbon::now())
            ->delete();

        return $count;
    }

    /**
     * 清理已撤销的刷新令牌
     *
     * @return int 清理的记录数
     */
    public function cleanupRevokedRefreshTokens()
    {
        $count = DB::table('oauth_refresh_tokens')
            ->where('revoked', true)
            ->delete();

        return $count;
    }

    /**
     * 清理所有过期和已撤销的令牌
     *
     * @return array 清理的记录数统计
     */
    public function cleanupAll()
    {
        $stats = [
            'expired_auth_codes' => $this->cleanupExpiredAuthCodes(),
            'revoked_auth_codes' => $this->cleanupRevokedAuthCodes(),
            'expired_access_tokens' => $this->cleanupExpiredAccessTokens(),
            'revoked_access_tokens' => $this->cleanupRevokedAccessTokens(),
            'expired_refresh_tokens' => $this->cleanupExpiredRefreshTokens(),
            'revoked_refresh_tokens' => $this->cleanupRevokedRefreshTokens(),
        ];

        $total = array_sum($stats);
        $stats['total'] = $total;

        Log::info('OAuth token cleanup completed', $stats);

        return $stats;
    }
}
