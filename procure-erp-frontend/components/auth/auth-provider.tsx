"use client";

import { useEffect } from 'react';
import { useAuthStore } from '@/stores/authStore';
import { authApi } from '@/lib/api/auth';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // 個別の関数を直接取得することでオブジェクト再作成を回避
  const setLoading = useAuthStore(state => state.setLoading);
  const login = useAuthStore(state => state.login);
  const logout = useAuthStore(state => state.logout); // ログアウト関数を追加
  const setInitialized = useAuthStore(state => state.setInitialized);

  // アプリ起動時に1回だけ実行
  useEffect(() => {
    let isMounted = true;

    async function initAuth() {
      if (!isMounted) return;
      
      // 認証初期化前にフラグをリセット（アプリ再起動時のため）
      setInitialized(false);
      // ローディング開始
      setLoading(true);
      
      try {
        console.log('認証状態を検証中...');
        // バックエンドからプロフィール情報を取得
        const profileResult = await authApi.getProfile();
        
        if (!isMounted) return; // 非同期処理中にアンマウントされた場合の対策
        
        if (profileResult) {
          // 認証済みユーザーの復元
          console.log('認証済みユーザーを復元:', profileResult);
          const token = localStorage.getItem('accessToken') || '';
          login(profileResult, token);
          console.log('認証済み状態を設定完了');
        } else {
          // 認証情報なし - 確実にログアウト状態にする
          console.log('認証済みユーザーなし - ログアウト状態に設定');
          logout(); // 明示的にログアウト処理を実行
        }
      } catch (error: any) {
        // エラー発生（認証エラーなど）
        if (isMounted) {
          console.error('認証状態検証エラー:', error);
          
          // エラー種別に応じた処理
          const status = error?.response?.status;
          if (status === 401 || status === 403) {
            console.log('認証エラー(401/403)を検出 - ログアウト状態に設定');
            logout(); // 明示的にログアウト処理を実行
          } else {
            // その他のエラーでも安全のためログアウト
            console.log('API接続エラー - 安全のためログアウト状態に設定');
            logout();
          }
        }
      } finally {
        // 最終処理（成功/失敗に関わらず実行）
        if (isMounted) {
          // ローディング終了
          setLoading(false);
          // 初期化完了を設定（成功/失敗に関わらず、初期化処理は完了）
          setInitialized(true);
          console.log('認証初期化完了');
        }
      }
    }
    
    // 初期化処理を実行
    initAuth();
    
    // クリーンアップ関数
    return () => {
      isMounted = false;
    };
  }, [setLoading, login, logout, setInitialized]); // 依存配列にlogoutを追加

  return <>{children}</>;
}
