# Blitz Examples

This directory contains example files to help you get started with Blitz.

## Files

- `basic_request.txt` - Simple GET request with one parameter
- `post_request.txt` - POST request with JSON body and multiple parameters
- `wordlist.txt` - Sample wordlist for testing

## Example 1: Basic ID Fuzzing

Fuzz a user ID parameter:

```bash
0xgenctl blitz run \
  --req examples/basic_request.txt \
  --payloads "1-100" \
  --attack sniper \
  --concurrency 10 \
  --output results.db
```

## Example 2: Login Brute Force (Pitchfork)

Test username/password combinations in parallel:

```bash
# Create usernames.txt
echo -e "admin\nroot\nuser" > usernames.txt

# Create passwords.txt
echo -e "password\n123456\nadmin" > passwords.txt

# Run pitchfork attack
0xgenctl blitz run \
  --req examples/post_request.txt \
  --payload1 usernames.txt \
  --payload2 passwords.txt \
  --attack pitchfork \
  --concurrency 5 \
  --rate 10 \
  --export-html login_results.html
```

## Example 3: SQL Injection Testing

Test for SQL injection with pattern matching:

```bash
0xgenctl blitz run \
  --req examples/basic_request.txt \
  --payloads "' OR 1=1--,admin' --,1' AND '1'='1" \
  --attack sniper \
  --patterns "SQL.*error,mysql_fetch,syntax.*near" \
  --anomaly \
  --export-html sqli_results.html
```

## Example 4: Header Fuzzing

Create a request with header parameter:

```bash
cat > header_request.txt <<EOF
GET /api/data HTTP/1.1
Host: api.example.com
X-API-Key: {{api_key}}
User-Agent: Mozilla/5.0

EOF

# Fuzz the API key
0xgenctl blitz run \
  --req header_request.txt \
  --payloads wordlist.txt \
  --attack sniper \
  --concurrency 20
```

## Example 5: Cluster Bomb Attack

Test all combinations of two parameters:

```bash
0xgenctl blitz run \
  --req post_request.txt \
  --payload1 "admin,user,guest" \
  --payload2 "pass123,password,admin" \
  --attack cluster-bomb \
  --concurrency 10 \
  --anomaly
```

## Example 6: Character Range Fuzzing

Fuzz with character ranges:

```bash
# Test single characters
0xgenctl blitz run \
  --req basic_request.txt \
  --payloads "a-z" \
  --attack sniper

# Test with numbers
0xgenctl blitz run \
  --req basic_request.txt \
  --payloads "0-9" \
  --attack sniper
```

## Example 7: Export Existing Results

If you already have a results database:

```bash
# Export to HTML
0xgenctl blitz export \
  --db results.db \
  --format html \
  --output report.html

# Export to CSV
0xgenctl blitz export \
  --db results.db \
  --format csv \
  --output results.csv

# Export to JSON
0xgenctl blitz export \
  --db results.db \
  --format json \
  --output results.json
```

## Example 8: Rate-Limited Testing

When testing against rate-limited APIs:

```bash
0xgenctl blitz run \
  --req basic_request.txt \
  --payloads wordlist.txt \
  --attack sniper \
  --concurrency 1 \
  --rate 5 \
  --retries 3
```

This will:
- Use 1 worker (sequential)
- Limit to 5 requests per second
- Retry failed requests up to 3 times

## Example 9: Advanced Pattern Matching

Search for sensitive data in responses:

```bash
0xgenctl blitz run \
  --req basic_request.txt \
  --payloads "1-1000" \
  --patterns "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,},\b\d{3}-\d{2}-\d{4}\b" \
  --anomaly \
  --export-html sensitive_data.html
```

This will detect:
- Email addresses
- Social Security Numbers
- And flag them as anomalies

## Tips

1. **Start Small**: Test with a small payload set first to verify your request template is correct
2. **Use Rate Limiting**: Respect the target server's capacity with `--rate`
3. **Enable Anomaly Detection**: Use `--anomaly` to automatically identify interesting responses
4. **Export Results**: Always export to HTML for easy review
5. **Use Concurrency**: Increase `--concurrency` for faster testing (but be respectful)
6. **Pattern Matching**: Use patterns to automatically find errors and sensitive data

## Troubleshooting

**No insertion points found:**
- Check your markers (`{{}}` by default)
- Verify the request template has marked positions

**Connection errors:**
- Reduce `--concurrency`
- Add `--rate` limiting
- Increase `--retries`

**Out of memory:**
- Reduce `--concurrency`
- Check your payload sizes (cluster bomb can generate many combinations)

**No interesting results:**
- Review baseline metrics (they're displayed at the end)
- Check if anomaly detection is enabled
- Try different patterns or payload sets
