import { SignJWT } from 'jose';

export async function onRequestGet(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    // CSRF Protection: Verify state
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookies = Object.fromEntries(
        cookieHeader.split(';').map(c => {
            const trimmed = c.trim();
            const idx = trimmed.indexOf('=');
            return idx === -1 ? [trimmed, ''] : [trimmed.slice(0, idx), trimmed.slice(idx + 1)];
        })
    );
    const storedState = cookies['github_oauth_state'];

    if (!code || !state || state !== storedState) {
        return new Response('Invalid state or missing code', { status: 400 });
    }

    const clientId = env.GITHUB_CLIENT_ID;
    const clientSecret = env.GITHUB_CLIENT_SECRET;
    const allowedUser = env.ALLOWED_GITHUB_USER;
    // JWT secret: prefer GITHUB_CLIENT_SECRET, fallback to APP_PASSWORD when GitHub OAuth is not configured
    const serverSecret = clientSecret || env.APP_PASSWORD;

    if (!clientId || !clientSecret || !serverSecret) {
        return new Response('GitHub OAuth or Server Secret not configured', { status: 500 });
    }

    // 1. Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify({
            client_id: clientId,
            client_secret: clientSecret,
            code: code
        })
    });

    const tokenData = await tokenResponse.json();
    if (tokenData.error) {
        return new Response(`GitHub Error: ${tokenData.error_description}`, { status: 400 });
    }

    const accessToken = tokenData.access_token;

    // 2. Fetch User Profile
    const userResponse = await fetch('https://api.github.com/user', {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'User-Agent': 'Cloudflare-DNS-Manager'
        }
    });

    const userData = await userResponse.json();

    // 3. Authorization Check
    if (!allowedUser || userData.login !== allowedUser) {
        return new Response('Unauthorized user', { status: 403 });
    }

    // 4. Generate JWT
    const secret = new TextEncoder().encode(serverSecret);
    const jwt = await new SignJWT({
        admin: true,
        github_user: userData.login,
        avatar: userData.avatar_url
    })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('24h')
        .sign(secret);

    // 5. Redirect back to frontend with token
    return new Response(null, {
        status: 302,
        headers: {
            'Location': `/#auth_token=${jwt}&mode=server`,
            'Set-Cookie': 'github_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
        }
    });
}
