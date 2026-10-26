import assert from 'node:assert/strict';
import { test } from 'node:test';
import { maskSecrets, REDACTED, stripBearerTokens } from '../src/redaction.ts';

const picture = (entity_id: string, entity_picture: string) => ({ entity_id, state: 'idle', attributes: { entity_picture } });

test('bearer tokens are stripped wherever the token parameter sits in the URL', () => {
  const cases = [
    ['/api/camera_proxy/camera.a?token=T1', '/api/camera_proxy/camera.a'],
    ['/api/image_proxy/image.a?token=T1&time=5', '/api/image_proxy/image.a?time=5'],
    ['/api/media_player_proxy/media_player.a?cache=1&token=T1', '/api/media_player_proxy/media_player.a?cache=1'],
    ['https://ha.example/api/camera_proxy/camera.a?w=1&token=T1&h=2#x', 'https://ha.example/api/camera_proxy/camera.a?w=1&h=2#x'],
  ];
  for (const [url, stripped] of cases) {
    const domain = /(camera|image|media_player)\.a/.exec(url!)![1]!;
    assert.deepEqual(stripBearerTokens(picture(`${domain}.a`, url!)), picture(`${domain}.a`, stripped!), url);
  }
});

test('access_token goes, and states nested in other values are stripped too', () => {
  const camera = { entity_id: 'camera.porch', attributes: { access_token: 'T1', friendly_name: 'Porch', urls: ['/a?token=T1'] } };
  const trace = { trace: { path: [{ changed_variables: { trigger: { to_state: camera } } }] } };
  assert.deepEqual(stripBearerTokens(trace), {
    trace: { path: [{ changed_variables: { trigger: { to_state: { entity_id: 'camera.porch', attributes: { friendly_name: 'Porch', urls: ['/a'] } } } } }] },
  });
  // A scene config keys each entity's state and attributes by its entity_id.
  const scene = { entities: { 'media_player.den': { state: 'on', access_token: 'T1', entity_picture: '/m?token=T1&c=1' }, 'light.den': { state: 'on', note: '/l?token=T1' } } };
  assert.deepEqual(stripBearerTokens(scene), { entities: { 'media_player.den': { state: 'on', entity_picture: '/m?c=1' }, 'light.den': { state: 'on', note: '/l?token=T1' } } });
});

test('expected leak: tokens outside the attributes of camera, image and media_player states pass through', () => {
  const other = [picture('sensor.webhook', '/hook?token=T1'), { entity_id: 'camera.porch', access_token: 'T1' }, 'plain?token=T1'];
  assert.deepEqual(stripBearerTokens(other), other);
});

const M = REDACTED;

test('values under secret-looking keys are masked, at any depth and whatever their type', () => {
  const config = {
    alias: 'Ping the API',
    password: 'hunter2',
    PassWD: 'hunter2',
    client_secret: 's3cr3t',
    refresh_token: 'rt-1',
    api_key: 'k-1',
    ApiKey: 'k-2',
    Authorization: 'Basic dXNlcjpwYXNz',
    auth: { username: 'bob', password: 'pw' },
    'basic-auth': 'bob:pw',
    bearer: 'b-1',
    credentials: ['c-1'],
    private_key: '-----BEGIN PRIVATE KEY-----',
    cookie: 'session=1',
    webhook_id: 'hook-1',
    pin: 1234,
    actions: [{ action: 'rest_command.ping', data: { headers: { 'X-Auth-Token': 't-1' }, sensor_token: 42 } }],
  };
  assert.deepEqual(maskSecrets(config), {
    alias: 'Ping the API',
    password: M,
    PassWD: M,
    client_secret: M,
    refresh_token: M,
    api_key: M,
    ApiKey: M,
    Authorization: M,
    auth: M,
    'basic-auth': M,
    bearer: M,
    credentials: M,
    private_key: M,
    cookie: M,
    webhook_id: M,
    pin: 1234,
    actions: [{ action: 'rest_command.ping', data: { headers: { 'X-Auth-Token': M }, sensor_token: M } }],
  });
});

test('auth matches only as a whole word of the key; the other listed words match anywhere in it', () => {
  assert.deepEqual(maskSecrets({ author: 'Jane', automation: 'a', tokenizer: 'b' }), { author: 'Jane', automation: 'a', tokenizer: M });
});

test('URL userinfo and Bearer tokens are masked inside any string, leaving the rest', () => {
  const cases = [
    ['https://bob:hunter2@nas.local/api', `https://${M}@nas.local/api`],
    ['rtsp://admin:pw@10.0.0.5:554/stream and http://u@x.example', `rtsp://${M}@10.0.0.5:554/stream and http://${M}@x.example`],
    ['Bearer eyJhbGciOi.J9-_x~+/abc==', `Bearer ${M}`],
    ['curl -H "authorization: bearer abc123" https://x', `curl -H "authorization: bearer ${M}" https://x`],
    ['https://nas.local/api?user=bob', 'https://nas.local/api?user=bob'],
    ['mailto:bob@example.com', 'mailto:bob@example.com'],
    ['the bearer of good news', 'the bearer of good news'],
  ];
  for (const [input, masked] of cases) assert.deepEqual(maskSecrets({ message: input }), { message: masked }, input);
  assert.deepEqual(maskSecrets(['Bearer abc123', 7, null, true]), [`Bearer ${M}`, 7, null, true]);
});

test('expected leak: secrets under innocuous keys or in other string shapes pass through', () => {
  const misses = {
    url: 'https://hooks.example/services/T000/B000/XXXXSECRETPATH',
    query: 'https://api.example/send?api_key=k-1&sig=abc',
    header_line: 'X-Api-Key: k-1',
    basic: 'Basic dXNlcjpwYXNz',
    basicAuth: 'bob:pw',
    oauth: 'o-1',
    letters_only: 'Bearer abcdefghijklmnopqrstuvwxyz',
    message: 'my password is hunter2',
    data: { value: 'sk_live_51H' },
    'sk_live_51H-as-a-key': true,
  };
  assert.deepEqual(maskSecrets(misses), misses);
});
