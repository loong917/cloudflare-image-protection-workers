import { createHash } from 'node:crypto';

// How long an token should be valid for, in seconds
const EXPIRY = 60 * 1000;

export async function generateSignedUrl(access_key_id, access_key_secret, body) {
	// timestamp
	const timestamp = new Date().getTime();
	// md5(keysecret+body+timestamp)
	const dataToSigned = `${access_key_secret}${body}${timestamp}`;
	const md5Data = createHash('md5').update(dataToSigned).digest('hex');
	const verifiedData = Buffer.from(md5Data).toString('hex');
	return `key=${access_key_id}&timestamp=${timestamp}&sign=${verifiedData}`
}

export async function verifySignedUrl(access_key_secret, body, timestamp, sign) {
	const assertedTimestamp = Number(timestamp);
	// Signed requests expire after five minute. Note that this value should depend on your specific use case
	if (Date.now() > assertedTimestamp + EXPIRY) {
		return { code: 403, msg: `URL expired at ${new Date(assertedTimestamp + EXPIRY)}` };
	}
	// md5(keysecret+body+timestamp)
	const dataToSigned = `${access_key_secret}${body}${assertedTimestamp}`;
	const md5Data = createHash('md5').update(dataToSigned).digest('hex');
	const verifiedData = Buffer.from(md5Data).toString('hex');
	if (verifiedData != sign) {
		return { code: 403, msg: 'invalid sign' };
	}
	return { code: 1, msg: 'passed' };
}
