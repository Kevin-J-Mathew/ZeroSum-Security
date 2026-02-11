#!/usr/bin/env python3
"""Quick test to verify SSRF context builder fix."""

from src.sentinel.sandbox.vulnerability_contexts import SSRFContextBuilder

# Test SSRF context builder
code = 'def fetch_url(url):\n    return requests.get(url)'
payload = 'http://localhost:8080'

try:
    builder = SSRFContextBuilder(code, payload)
    context = builder.build()
    print('✓ SSRF context builder works!')
    print(f'✓ Generated {len(context.test_harness)} chars of test harness')
    print(f'✓ Success indicators: {context.success_indicators}')
    print('\n✓ Test harness preview (first 200 chars):')
    print(context.test_harness[:200])
except Exception as e:
    print(f'✗ Error: {e}')
    import traceback
    traceback.print_exc()
