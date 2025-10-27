#!/bin/bash

# Test script for full authentication (all 3 layers)
# This script gets fresh TOTP and signature, then immediately tests

set -e

echo "🔐 Testing Qiuth Full Authentication"
echo "===================================="
echo ""

# Get current TOTP
echo "1. Getting current TOTP token..."
TOTP_RESPONSE=$(curl -s http://localhost:3000/totp/current)
TOTP=$(echo $TOTP_RESPONSE | jq -r '.token')
echo "   TOTP: $TOTP"
echo ""

# Get signature
echo "2. Generating signature..."
SIGN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"http://localhost:3000/api/full","body":""}' \
  http://localhost:3000/sign)
TIMESTAMP=$(echo $SIGN_RESPONSE | jq -r '.timestamp')
SIGNATURE=$(echo $SIGN_RESPONSE | jq -r '.signature')
echo "   Timestamp: $TIMESTAMP"
echo "   Signature: ${SIGNATURE:0:50}..."
echo ""

# Make the request
echo "3. Making authenticated request..."
echo ""
echo "   Getting API key from server..."
API_KEY=$(curl -s http://localhost:3000/ | jq -r '.credentials.apiKey')
echo "   API Key: $API_KEY"
echo ""

curl -v \
  -H "X-API-Key: $API_KEY" \
  -H "X-TOTP-Token: $TOTP" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Signature: $SIGNATURE" \
  http://localhost:3000/api/full

echo ""
echo ""
echo "===================================="

