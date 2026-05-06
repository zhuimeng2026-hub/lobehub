import { authEnv } from '@/envs/auth';

import { type GenericProviderDefinition } from '../types';

const WECHAT_MP_AUTHORIZATION_URL =
  'https://open.weixin.qq.com/connect/oauth2/authorize';
const WECHAT_MP_TOKEN_URL =
  'https://api.weixin.qq.com/sns/oauth2/access_token';
const WECHAT_MP_USERINFO_URL = 'https://api.weixin.qq.com/sns/userinfo';

type WeChatMpTokenResponse = {
  access_token?: string;
  errcode?: number;
  errmsg?: string;
  expires_in?: number;
  openid?: string;
  refresh_token?: string;
  scope?: string;
  token_type?: string;
  unionid?: string;
};

const parseWechatMpScopes = (scope: string | undefined) =>
  scope ? scope.split(',').filter(Boolean) : [];

const provider: GenericProviderDefinition<{
  AUTH_WECHAT_MP_APP_ID: string;
  AUTH_WECHAT_MP_SECRET: string;
}> = {
  build: (env) => {
    const clientId = env.AUTH_WECHAT_MP_APP_ID;
    const clientSecret = env.AUTH_WECHAT_MP_SECRET;

    return {
      authorizationUrl: WECHAT_MP_AUTHORIZATION_URL,
      authorizationUrlParams: {
        appid: clientId,
        response_type: 'code',
        scope: 'snsapi_userinfo',
        forcePopup: 'false',
      },
      clientId,
      clientSecret,

      getToken: async ({ code }) => {
        const tokenUrl = new URL(WECHAT_MP_TOKEN_URL);
        tokenUrl.searchParams.set('appid', clientId);
        tokenUrl.searchParams.set('secret', clientSecret);
        tokenUrl.searchParams.set('code', code);
        tokenUrl.searchParams.set('grant_type', 'authorization_code');

        const response = await fetch(tokenUrl, { cache: 'no-store' });
        const data = (await response.json()) as WeChatMpTokenResponse;

        if (!response.ok || data.errcode) {
          throw new Error(
            data.errmsg ?? 'Failed to fetch WeChat Official Account OAuth token',
          );
        }

        if (!data.access_token || !data.openid) {
          throw new Error(
            'WeChat Official Account token response is missing required fields',
          );
        }

        return {
          accessToken: data.access_token,
          accessTokenExpiresAt: data.expires_in
            ? new Date(Date.now() + data.expires_in * 1000)
            : undefined,
          expiresIn: data.expires_in,
          raw: data,
          refreshToken: data.refresh_token,
          refreshTokenExpiresAt: undefined,
          scopes: parseWechatMpScopes(data.scope),
          tokenType: data.token_type ?? 'Bearer',
        };
      },

      getUserInfo: async (tokens) => {
        const accessToken = tokens.accessToken;
        const openId = (
          tokens as { raw?: WeChatMpTokenResponse }
        ).raw?.openid;
        const unionId = (
          tokens as { raw?: WeChatMpTokenResponse }
        ).raw?.unionid;

        if (!accessToken || !openId) {
          return null;
        }

        const url = new URL(WECHAT_MP_USERINFO_URL);
        url.searchParams.set('access_token', accessToken);
        url.searchParams.set('openid', openId);
        url.searchParams.set('lang', 'zh_CN');

        const response = await fetch(url, { cache: 'no-store' });
        if (!response.ok) {
          return null;
        }

        const profile = (await response.json()) as {
          headimgurl?: string;
          nickname?: string;
          unionid?: string;
        };

        const finalUnionId = unionId ?? profile.unionid ?? openId;
        const syntheticEmail = `${finalUnionId}@wechat-mp.lobehub`;

        return {
          email: syntheticEmail,
          emailVerified: false,
          id: finalUnionId,
          image: profile.headimgurl,
          name: profile.nickname ?? finalUnionId,
          ...profile,
        };
      },

      pkce: false,

      providerId: 'wechat-mp',

      responseMode: 'query',

      scopes: ['snsapi_userinfo'],

      tokenUrl: WECHAT_MP_TOKEN_URL,
    };
  },

  checkEnvs: () => {
    return !!(
      authEnv.AUTH_WECHAT_MP_APP_ID && authEnv.AUTH_WECHAT_MP_SECRET
    )
      ? {
          AUTH_WECHAT_MP_APP_ID: authEnv.AUTH_WECHAT_MP_APP_ID,
          AUTH_WECHAT_MP_SECRET: authEnv.AUTH_WECHAT_MP_SECRET,
        }
      : false;
  },
  id: 'wechat-mp',
  type: 'generic',
};

export default provider;
