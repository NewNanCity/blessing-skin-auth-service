<?php

namespace BlessingSkin\OAuth\Controllers;

use BlessingSkin\OAuth\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

/**
 * OAuth 客户端控制器
 *
 * 此控制器处理用户对自己的 OAuth 客户端应用的管理，包括：
 * 1. 查看客户端列表
 * 2. 创建新的客户端
 * 3. 更新现有客户端
 * 4. 删除客户端
 */
class ClientController extends Controller
{
    /**
     * 显示用户的 OAuth 客户端列表
     *
     * @return \Illuminate\View\View
     */
    public function showClientList()
    {
        $clients = Client::where('user_id', Auth::id())->get();

        return view('BlessingSkin\\OAuth::user.clients', [
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
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'redirect_uri' => 'required|string|url',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'code' => 1,
                'message' => $validator->errors()->first(),
            ]);
        }

        $client = Client::create([
            'user_id' => Auth::id(),
            'name' => $request->input('name'),
            'redirect_uri' => $request->input('redirect_uri'),
        ]);

        return response()->json([
            'code' => 0,
            'message' => trans('BlessingSkin\\OAuth::user.client-created'),
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
        $client = Client::where('user_id', Auth::id())->findOrFail($id);

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'redirect_uri' => 'required|string|url',
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
        ]);

        return response()->json([
            'code' => 0,
            'message' => trans('BlessingSkin\\OAuth::user.client-updated'),
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
        $client = Client::where('user_id', Auth::id())->findOrFail($id);
        $client->delete();

        return response()->json([
            'code' => 0,
            'message' => trans('BlessingSkin\\OAuth::user.client-deleted'),
        ]);
    }
}
