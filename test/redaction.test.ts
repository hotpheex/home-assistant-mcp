import assert from 'node:assert/strict';
import { test } from 'node:test';
import { stripBearerTokens } from '../src/redaction.ts';

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
});

test('expected leak: tokens outside the attributes of camera, image and media_player states pass through', () => {
  const other = [picture('sensor.webhook', '/hook?token=T1'), { entity_id: 'camera.porch', access_token: 'T1' }, 'plain?token=T1'];
  assert.deepEqual(stripBearerTokens(other), other);
});
