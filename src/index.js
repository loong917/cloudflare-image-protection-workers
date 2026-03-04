import { randomUUID } from 'node:crypto';
import { extname } from 'node:path';
import { generateSignedUrl, verifySignedUrl } from './utils/r2.js';

const BASE_URL = 'https://loongzxl.com';

export default {
	async fetch(request, env) {
		switch (request.method) {
			case 'GET':
				const url = new URL(request.url);
				// Make sure you have the necessary query parameters.
				const access_key_id = url.searchParams.get('key');
				if (!access_key_id) {
					return responseHTML('invalid key');
				}
				const timestamp = url.searchParams.get('timestamp');
				if (!timestamp) {
					return responseHTML('invalid timestamp');
				}
				const sign = url.searchParams.get('sign');
				if (!sign) {
					return responseHTML('invalid sign');
				}
				const access_key_secret = env.ACCESS_KEY_SECRET;
				// 待签名数据
				const arr = url.pathname.split('/');
                const body = arr[arr.length - 1];
				// 验证签名
				const check = await verifySignedUrl(access_key_secret, body, timestamp);
				if (!check) {
					return responseHTML('verify sign failed');
				}
				if (check.code != 1) {
					return responseHTML(check.msg);
				}
				const object = await env.MY_BUCKET.get(key);
				if (object === null) {
					return responseHTML('Object Not Found', 404);
				}
				const headers = new Headers();
				object.writeHttpMetadata(headers);
				headers.set('etag', object.httpEtag);
				return new Response(object.body, {
					headers,
				});
			case 'POST':
				try {
					const formData = await request.formData();
					// 读取文件
					const file = formData.get('file');
					// 处理文件（如果存在）
					if (file instanceof File) {
						const buffer = await file.arrayBuffer();
						const finalKey = randomUUID() + extname(file.name);
						await env.MY_BUCKET.put(finalKey, buffer);
						// 生成签名url
						const access_key_id = env.ACCESS_KEY_ID;
						const access_key_secret = env.ACCESS_KEY_SECRET;
						const signedUrl = await generateSignedUrl(access_key_id, access_key_secret, finalKey);
						const result = {
							data: `${BASE_URL}/cdn/${finalKey}?${signedUrl}`,
						};
						return new Response(JSON.stringify(result, null, 2), {
							headers: { 'Content-Type': 'application/json' },
						});
					} else {
						return new Response(
							JSON.stringify(
								{
									error: 'Not a file',
								},
								null,
								2,
							),
							{ headers: { 'Content-Type': 'application/json' }, status: 500 },
						);
					}
				} catch (error) {
					return new Response(
						JSON.stringify(
							{
								error: error.message,
							},
							null,
							2,
						),
						{ headers: { 'Content-Type': 'application/json' }, status: 500 },
					);
				}
			default:
				return responseHTML('Method Not Allowed', 405);
		}
	},
};

const responseHTML = (msg, status) => {
	const html = `<!DOCTYPE html>
    <body>
      <p style="font-family: -apple-system-font, Arial, sans-serif; font-size: 17px; text-align: center;">${msg}</p>
    </body>`;
	return new Response(html, {
		headers: {
			'content-type': 'text/html;charset=UTF-8',
		},
		status: status ?? 403,
	});
};
