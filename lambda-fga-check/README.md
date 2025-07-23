# Lambda FGA Check

This AWS Lambda function (`fga_check.py`) checks user authorization for a given relation and object using OpenFGA.

## Features
- Uses OpenFGA Python SDK for authorization checks
- All configuration is via environment variables (no hardcoded secrets)
- Returns a simple JSON response indicating authorization

## Environment Variables
- `FGA_API_ISSUER`: Auth0 issuer URL
- `FGA_API_AUDIENCE`: FGA API audience
- `FGA_CLIENT_ID`: Auth0 client ID
- `FGA_CLIENT_SECRET`: Auth0 client secret
- `FGA_API_SCHEME`: (optional, default: `https`)
- `FGA_API_HOST`: FGA API host (e.g., `api.us1.fga.dev`)
- `FGA_STORE_ID`: FGA store ID
- `FGA_AUTHORIZATION_MODEL_ID`: (optional) FGA authorization model ID

## Usage
The Lambda expects an event with the following structure:
```
{
  "user": "username",
  "relation": "relation_name",
  "object": "object_name"
}
```

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set the required environment variables (see above).
3. Deploy `fga_check.py` as an AWS Lambda function.

## License
MIT 