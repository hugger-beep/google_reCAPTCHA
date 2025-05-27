import json
import logging
import traceback
from typing import Dict, Any, List

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def check_cookies(event):
    """Check if valid WAF token or CAPTCHA verification exists in cookies"""
    try:
        # Check headers first
        headers = event.get('headers', {})
        
        # Check for cookies in headers (case-insensitive)
        cookie_header = None
        for key in headers:
            if key.lower() == 'cookie':
                cookie_header = headers[key]
                break
        
        logger.info(f"Cookie header found: {cookie_header}")
        
        if not cookie_header:
            logger.warning("No cookies found in request")
            return False
        
        # Check for required cookies
        has_waf_token = 'aws-waf-token=true' in cookie_header
        has_captcha_verified = 'captcha_verified=true' in cookie_header
        
        logger.info(f"Cookie check: WAF token: {has_waf_token}, CAPTCHA verified: {has_captcha_verified}")
        
        # Return true if either cookie is present
        return has_waf_token or has_captcha_verified
        
    except Exception as e:
        logger.error(f"Cookie check error: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def lambda_handler(event, context):
    """Handler for serving secure HTML content"""
    try:
        # Log the event for debugging
        logger.info(f"Event: {json.dumps(event)}")
        
        # Check for required cookies
        if not check_cookies(event):
            logger.warning("Access denied - missing required cookies")
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-store, no-cache, must-revalidate'
                },
                'body': json.dumps({
                    'message': 'Access denied. CAPTCHA verification required.'
                })
            }
        
        # HTML content with security best practices
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Protected Content</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .container {
                    background-color: #f9f9f9;
                    border-radius: 8px;
                    padding: 30px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 {
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }
                .success-message {
                    background-color: #d4edda;
                    color: #155724;
                    padding: 15px;
                    border-radius: 4px;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success-message">
                    <strong>Success!</strong> You have successfully completed CAPTCHA verification.
                </div>
                <h1>Protected Content</h1>
                <p>This page is secured by AWS WAF and requires CAPTCHA verification to access.</p>
                <p>Your session has been authenticated and you now have access to the protected content.</p>
                <p>The cookies set in your browser will allow you to access protected content without 
                   completing the CAPTCHA again until they expire.</p>
            </div>
        </body>
        </html>
        """
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Cache-Control': 'no-store, no-cache, must-revalidate'
            },
            'body': html_content
        }
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store, no-cache, must-revalidate'
            },
            'body': json.dumps({
                'message': 'Internal server error'
            })
        }
