# Web-analyser-api

**OSINT API for analysing any website** — equivalent of web-check.

## Description
Web-analyser-api is a Node.js-based API that allows you to analyse websites for OSINT (Open Source Intelligence) purposes. It provides endpoints to fetch and analyse various aspects of a website, such as its headers, DNS records, SSL certificates, and more.

## Features
- Analyse website headers, DNS records, and SSL certificates.
- Rate limiting to prevent abuse.
- Configurable timeouts and response size limits.
- Support for trusted IPs to bypass rate limits.
- Blocklist for domains/IPs that should not be analysed.

## Installation

### Prerequisites
- Node.js (version >= 18.0.0)
- npm (Node Package Manager)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/meid13ia/Web-analyser-api.git
   cd Web-analyser-api
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   npm start
   ```

   Or, for development with auto-reload:
   ```bash
   npm run dev
   ```

## Configuration

The API can be configured using environment variables. Copy the `.env.example` file to `.env` and modify the variables as needed:

```bash
cp .env.example .env
```

Then, edit the `.env` file to set your desired configuration:

```env
PORT=3000
RATE_LIMIT_MAX=30
RATE_LIMIT_WINDOW_MS=60000
SLOWDOWN_THRESHOLD=20
SLOWDOWN_DELAY_MS=500
TOOL_TIMEOUT_MS=15000
MAX_RESPONSE_BODY_BYTES=2097152
TRUSTED_IPS=192.168.1.1,10.0.0.1
BLOCKED_TARGETS=example.com,127.0.0.1
API_KEY=your-secret-key-here
```

### Environment Variables
- `PORT`: Port on which the server will run (default: `3000`).
- `RATE_LIMIT_MAX`: Maximum number of requests allowed per window (default: `30`).
- `RATE_LIMIT_WINDOW_MS`: Time window for rate limiting in milliseconds (default: `60000` or 1 minute).
- `SLOWDOWN_THRESHOLD`: Number of requests before slowing down responses (default: `20`).
- `SLOWDOWN_DELAY_MS`: Delay added to responses after exceeding the slowdown threshold (default: `500` ms).
- `TOOL_TIMEOUT_MS`: Timeout for each tool request in milliseconds (default: `15000`).
- `MAX_RESPONSE_BODY_BYTES`: Maximum size of the response body in bytes (default: `2097152` or 2 MB).
- `TRUSTED_IPS`: Comma-separated list of IPs that can bypass rate limits.
- `BLOCKED_TARGETS`: Comma-separated list of domains/IPs that should not be analysed.
- `API_KEY`: API key for authentication (default: `default-secret-key`).

## Usage

### Authentication
The API requires an API key for authentication. You can provide the API key in two ways:
1. **Header**: `x-api-key: YOUR_API_KEY`
2. **Query Parameter**: `?api_key=YOUR_API_KEY`

By default, the API key is `default-secret-key`. You can change it by setting the `API_KEY` environment variable.

### API Endpoints

#### `GET /analyse?url=<website_url>`
Analyse a website and return its details.

**Query Parameters:**
- `url` (required): The URL of the website to analyse.
- `api_key` (required): Your API key.

**Example Request with API Key in Header:**
```bash
curl -H "x-api-key: default-secret-key" "http://localhost:3000/analyse?url=https://example.com"
```

**Example Request with API Key in Query Parameter:**
```bash
curl "http://localhost:3000/analyse?url=https://example.com&api_key=default-secret-key"
```

**Example Response:**
```json
{
  "status": "success",
  "data": {
    "headers": {
      "server": "nginx",
      "content-type": "text/html"
    },
    "dns": {
      "a": ["93.184.216.34"],
      "mx": ["mail.example.com"]
    },
    "ssl": {
      "valid": true,
      "issuer": "Let's Encrypt"
    }
  }
}
```

### Error Handling
The API returns appropriate HTTP status codes and error messages for various scenarios:
- `400 Bad Request`: Missing or invalid URL parameter.
- `403 Forbidden`: The target is blocked.
- `429 Too Many Requests`: Rate limit exceeded.
- `500 Internal Server Error`: Server-side error.

## Docker Support

The API can be run using Docker for easy deployment.

### Build the Docker Image
```bash
docker build -t web-analyser-api .
```

### Run the Docker Container
```bash
docker run -p 3000:3000 -d web-analyser-api
```

### Environment Variables in Docker
You can pass environment variables to the Docker container:
```bash
docker run -p 3000:3000 -e PORT=3000 -e RATE_LIMIT_MAX=50 -d web-analyser-api
```

## Testing

To run tests, use the following command:
```bash
npm test
```

### Test Structure
Tests are located in the `tests` directory and use `jest` for testing. Ensure you have `jest` installed:
```bash
npm install --save-dev jest
```

### Running Tests
1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the tests:
   ```bash
   npm test
   ```

3. Expected output:
   ```
   PASS  tests/server.test.js
     Web-analyser-api
       ✓ should respond with 404 for non-existent routes (45 ms)
       ✓ should respond with 400 for missing URL parameter (10 ms)
       ✓ should respond with 200 for valid URL (120 ms)
   
   Test Suites: 1 passed, 1 total
   Tests:       3 passed, 3 total
   ```

## Security

### Authentication
The API currently does not include authentication. For production use, consider adding authentication mechanisms such as API keys or OAuth.

### Rate Limiting
The API includes rate limiting to prevent abuse. Configure `RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW_MS` to adjust the rate limits as needed.

### Input Validation
Ensure that all inputs are validated to prevent injection attacks (e.g., SQL injection, XSS).

## Dependencies

The API uses the following dependencies:
- `express`: Web framework for Node.js.
- `axios`: Promise-based HTTP client for making requests.
- `cheerio`: Fast, flexible, and lean implementation of core jQuery designed specifically for the server.
- `dns`: For DNS lookups.
- `tls`: For SSL certificate analysis.

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a new Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
