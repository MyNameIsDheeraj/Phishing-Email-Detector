# Mesa Security Integration Guide

## Overview

Mesa Security API integration has been successfully added to the Email Threat Intelligence Platform. This service enables advanced email scanning for phishing, malware, spam, and other threats using Mesa Security's threat detection engine.

## Configuration

### 1. API Key Setup

Add your Mesa Security API key to the `.env` file:

```env
MESA_SECURITY_API_KEY=mapi_YOUR_API_KEY_HERE
```

Get your API key from: [Mesa Security Dashboard](https://scan.mesasecurity.com/dashboard)

### 2. Database Schema

The following Mesa Security fields have been added to the `Email` model:

- `mesa_job_id` (String): Job ID returned by Mesa Security
- `mesa_status` (String): Scan status (pending, completed, failed, error)
- `mesa_verdict` (String): Mesa's threat verdict (phishing, malware, spam, clean, etc.)
- `mesa_score` (Integer): Threat score 0-100
- `mesa_details` (JSON): Detailed Mesa scan results
- `mesa_scanned_at` (DateTime): When the Mesa scan completed

## API Endpoints

### 1. Manual Email Scan with Mesa

**Endpoint:** `POST /email/{email_id}/mesa-scan`

Manually trigger a Mesa Security scan for a specific email.

**Response:**
```json
{
  "email_id": 1,
  "mesa_job_id": "550e8400-e29b-41d4-a716-446655440000",
  "mesa_status": "completed",
  "mesa_verdict": "phishing",
  "mesa_score": 85,
  "mesa_details": {
    "threat_score": 85,
    "classification": "phishing",
    "indicators": ["suspicious_links", "spoofed_sender"]
  },
  "overall_threat_score": 82,
  "overall_verdict": "MALICIOUS",
  "message": "Mesa Security scan completed successfully"
}
```

### 2. Get Mesa Scan Results

**Endpoint:** `GET /email/{email_id}/mesa-results`

Retrieve Mesa Security scan results for a specific email.

**Response:**
```json
{
  "email_id": 1,
  "mesa_job_id": "550e8400-e29b-41d4-a716-446655440000",
  "mesa_status": "completed",
  "mesa_verdict": "phishing",
  "mesa_score": 85,
  "mesa_details": { ... },
  "mesa_scanned_at": "2024-06-21T14:30:00.000Z"
}
```

### 3. Check Job Status by ID

**Endpoint:** `GET /mesa/job/{job_id}`

Get the status of a Mesa Security scan job by its job ID.

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "file_name": "email.eml",
  "file_size": 1024,
  "created_at": "2024-06-21T14:30:00Z",
  "result": {
    "verdict": "clean",
    "threat_score": 0
  },
  "rate_limit": {
    "rate_limit": "50",
    "rate_limit_remaining": "49",
    "rate_limit_reset": "2024-06-22T00:00:00Z"
  }
}
```

## Background Processing

When an email is uploaded or analyzed, if Mesa Security API key is configured, it will automatically:

1. **Trigger Background Scan**: Mesa scanning is initiated in the background
2. **Poll Results**: The service polls Mesa until the scan completes (up to 60 seconds)
3. **Store Results**: All Mesa findings are stored in the email record
4. **Update Threat Score**: Mesa results are factored into the overall threat score calculation
5. **Log Events**: All Mesa scanning events are recorded for audit trails

### Threat Score Calculation

Mesa Security results are incorporated into the threat score as follows:

- **Phishing verdict**: +25 points
- **Malware verdict**: +25 points
- **Malicious verdict**: +25 points
- **Spam verdict**: +15 points
- **Suspicious verdict**: +15 points
- **Mesa score > 50**: +6-25 points (based on score)

## Service Class: MesaSecurityService

### Initialization

```python
from app.services.mesa_security import MesaSecurityService

mesa_service = MesaSecurityService()
```

### Methods

#### `scan_email(email_content: bytes, filename: str = "email.eml", save_screenshot: bool = True, save_email: bool = False) -> Dict[str, Any]`

Scan an email file with Mesa Security.

```python
result = await mesa_service.scan_email(
    email_bytes,
    filename="email.eml",
    save_screenshot=True,
    save_email=False
)
```

**Parameters:**
- `email_content` (bytes): Raw email file bytes
- `filename` (str): Name of the email file
- `save_screenshot` (bool): Whether to save email screenshot
- `save_email` (bool): Whether to save email content

**Returns:** Dictionary with scan results or error information

#### `get_job_status(job_id: str) -> Dict[str, Any]`

Get the current status of a Mesa scan job.

```python
status = await mesa_service.get_job_status("550e8400-e29b-41d4-a716-446655440000")
```

**Returns:** Dictionary with job status and results

#### `close()`

Close the HTTP session.

```python
await mesa_service.close()
```

## Health Check

The health check endpoint (`/health`) now includes Mesa Security API configuration status:

```json
{
  "status": "healthy",
  "database": "connected",
  "services": {
    "virustotal": "configured",
    "abuseipdb": "configured",
    "mesa_security": "configured"
  },
  "timestamp": "2024-06-21T14:30:00.000Z"
}
```

## Rate Limiting

Mesa Security API has rate limits of **50 requests per day**. Rate limit information is included in API responses:

- `X-RateLimit-Limit`: Daily request limit
- `X-RateLimit-Remaining`: Remaining requests for the day
- `X-RateLimit-Reset`: Time when limit resets

## Testing

Run the Mesa Security test suite:

```bash
cd backend
source env/bin/activate
python -m pytest tests/test_mesa_security.py -v
```

**Test Coverage:**
- ✅ Service initialization
- ✅ API key validation
- ✅ Email scanning success
- ✅ Malicious email detection
- ✅ Failed submission handling
- ✅ Job status retrieval
- ✅ Session management

## Error Handling

### Missing API Key
```json
{
  "error": "Mesa Security API key not configured"
}
```

### Scan Submission Failed
```json
{
  "error": "Scan submission failed",
  "status": 400,
  "message": "Invalid file format"
}
```

### Job Status Timeout
```json
{
  "error": "Job status check timed out",
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "timeout"
}
```

## Integration with Other Services

Mesa Security scans work alongside:
- **VirusTotal**: URL and file hash analysis
- **AbuseIPDB**: IP reputation checking
- **SPF/DKIM/DMARC**: Email authentication validation
- **Rule-based detector**: Pattern matching and heuristics

All services contribute to the final threat score and verdict.

## Workflow Example

### 1. Upload Email
```bash
curl -F "file=@email.eml" http://localhost:8000/upload-email
```

### 2. System Automatically:
- Parses email content
- Extracts URLs, IPs, attachments
- Runs authentication checks
- **Triggers Mesa Security scan in background**
- Queries VirusTotal and AbuseIPDB
- Calculates composite threat score

### 3. Check Results
```bash
curl http://localhost:8000/email/1/mesa-results
```

### 4. Get Full Report
```bash
curl http://localhost:8000/report/1
```

## Troubleshooting

### Mesa scans not running
- Check that `MESA_SECURITY_API_KEY` is set in `.env`
- Verify API key is valid: `curl -H "x-api-key: YOUR_KEY" https://scan.mesasecurity.com/api/v1/jobs`

### Rate limit exceeded
- Mesa allows 50 requests per day
- Check `X-RateLimit-Remaining` header
- Wait until `X-RateLimit-Reset` time

### Scan timeout
- Default timeout is 60 seconds (30 attempts × 2 seconds)
- Can be customized via `mesa_service.max_retries` and `mesa_service.retry_delay`

### Session errors
- Ensure `httpx` is properly installed: `pip install httpx`
- Check network connectivity to `scan.mesasecurity.com`

## Performance Considerations

- Mesa scans run in background tasks (non-blocking)
- Average scan time: 5-10 seconds
- Polling interval: 2 seconds
- Max polling attempts: 30 (60 seconds total timeout)

## Next Steps

1. ✅ API key is configured in `.env`
2. ✅ Service is integrated and tested
3. ✅ Database schema is updated
4. ✅ Endpoints are functional
5. Consider: Custom result parsing based on Mesa response format
6. Consider: Webhook integration for async notifications
7. Consider: Historical tracking of Mesa scan verdicts

## Support

For Mesa Security API documentation: [Mesa Security API Docs](https://scan.mesasecurity.com/dashboard)

For issues with integration: Check [app/services/mesa_security.py](../app/services/mesa_security.py)
