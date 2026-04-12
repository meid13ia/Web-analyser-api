// tests/server.test.js
import request from 'supertest';
import { app } from '../server.js';

describe('Web-analyser-api', () => {
  it('should respond with 404 for non-existent routes', async () => {
    const response = await request(app).get('/nonexistent');
    expect(response.status).toBe(404);
  });

  it('should respond with 400 for missing URL parameter', async () => {
    const response = await request(app).get('/analyse');
    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty('error');
  });

  it('should respond with 200 for valid URL', async () => {
    const response = await request(app).get('/analyse?url=https://example.com');
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('status', 'success');
  });
});