
import json
import base64
import secrets
import ipaddress
import urllib.request
import urllib.parse
import traceback
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class WAFTokenManager:
    """Manage WAF token operations"""
    def __init__(self, token_expiry_hours: int = 24):
        self.token_expiry_hours = token_expiry_hours

    def create_token_cookie(self, domain: str) -> Dict[str, List[Dict]]:
        """Create WAF token cookie header"""
        try:
            # IMPORTANT: Match exactly what the WAF rule is looking for
            cookie_value = f'aws-waf-token=true; Path=/; Secure; SameSite=None; Max-Age={self.token_expiry_hours * 3600}'
            logger.info(f"Generated cookie: {cookie_value}")
            return {
                'set-cookie': [{
                    'key': 'Set-Cookie',
                    'value': cookie_value
                }]
            }
        except Exception as e:
            logger.error(f"Cookie creation error: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            raise
            
    def create_captcha_cookie(self, domain: str) -> Dict[str, List[Dict]]:
        """Create captcha verification cookie header"""
        try:
            # IMPORTANT: Match exactly what the WAF rule is looking for
            cookie_value = f'captcha_verified=true; Path=/; Secure; SameSite=None; Max-Age={self.token_expiry_hours * 3600}'
            logger.info(f"Generated captcha cookie: {cookie_value}")
            return {
                'set-cookie': [{
                    'key': 'Set-Cookie',
                    'value': cookie_value
                }]
            }
        except Exception as e:
            logger.error(f"Captcha cookie creation error: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            raise

def verify_recaptcha_token(token: str, secret_key: str) -> bool:
    """Verify Google reCAPTCHA token with Google's API"""
    try:
        logger.info(f"Starting reCAPTCHA verification for token length: {len(token)}")
        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        data = {
            'secret': secret_key,
            'response': token
        }
        
        encoded_data = urllib.parse.urlencode(data).encode('utf-8')
        request = urllib.request.Request(recaptcha_url, data=encoded_data, method='POST')
        
        logger.info("Sending request to reCAPTCHA API...")
        response = urllib.request.urlopen(request)
        
        result = json.loads(response.read().decode('utf-8'))
        logger.info(f"reCAPTCHA API response: {json.dumps(result, indent=2)}")
        
        success = result.get('success', False)
        logger.info(f"reCAPTCHA verification result: {success}")
        return success
        
    except Exception as e:
        error_info = {
            'error_type': type(e).__name__,
            'error_message': str(e),
            'stack_trace': traceback.format_exc()
        }
        logger.error(f"reCAPTCHA verification error: {json.dumps(error_info, indent=2)}")
        return False

def is_ip_in_cidrs(ip: str, cidrs: List[str]) -> bool:
    """Check if IP is in any of the allowed CIDR ranges"""
    try:
        logger.info(f"Checking IP {ip} against CIDR ranges: {cidrs}")
        ip_addr = ipaddress.ip_address(ip)
        result = any(ip_addr in ipaddress.ip_network(cidr) for cidr in cidrs)
        logger.info(f"IP check result: {result}")
        return result
    except ValueError as e:
        logger.error(f"IP validation error: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return False

def get_cookies(headers: Dict) -> List[Dict]:
    """Extract cookies from headers"""
    try:
        cookies = headers.get('cookie', [])
        logger.info(f"Extracted cookies: {cookies}")
        return cookies
    except Exception as e:
        logger.error(f"Cookie extraction error: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return []

def check_waf_token(cookies: List[Dict]) -> bool:
    """Check if valid WAF token exists in cookies"""
    try:
        logger.info(f"Checking WAF token in cookies: {cookies}")
        has_token = any('aws-waf-token=true' in cookie.get('value', '') for cookie in cookies)
        logger.info(f"WAF token check result: {has_token}")
        return has_token
    except Exception as e:
        logger.error(f"WAF token check error: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return False

def check_captcha_verified(cookies: List[Dict]) -> bool:
    """Check if valid captcha verification cookie exists"""
    try:
        logger.info(f"Checking captcha verification in cookies: {cookies}")
        has_token = any('captcha_verified=true' in cookie.get('value', '') for cookie in cookies)
        logger.info(f"Captcha verification check result: {has_token}")
        return has_token
    except Exception as e:
        logger.error(f"Captcha verification check error: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return False

def create_error_response(status_code: str, message: str, headers: Dict = None) -> Dict[str, Any]:
    """Create standardized error response"""
    try:
        logger.info(f"Creating error response - Status: {status_code}, Message: {message}")
        
        # Get origin from headers if provided
        origin = '*'
        if headers and 'origin' in headers:
            origin = headers['origin'][0]['value']
            
        response = {
            'status': status_code,
            'statusDescription': message,
            'headers': {
                'content-type': [{
                    'key': 'Content-Type',
                    'value': 'application/json'
                }],
                'cache-control': [{
                    'key': 'Cache-Control',
                    'value': 'no-store, no-cache, must-revalidate'
                }],
                'access-control-allow-origin': [{
                    'key': 'Access-Control-Allow-Origin',
                    'value': origin
                }],
                'access-control-allow-credentials': [{
                    'key': 'Access-Control-Allow-Credentials',
                    'value': 'true'
                }]
            },
            'body': json.dumps({
                'success': False,
                'error': message
            })
        }
        logger.info(f"Generated error response: {json.dumps(response, indent=2)}")
        return response
    except Exception as e:
        logger.error(f"Error response creation failed: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        raise

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handler for both Lambda@Edge and API Gateway"""
    try:
        logger.info("VERIFY CAPTCHA HANDLER: Received event")
        
        # Determine invocation type and normalize request format
        request = {}
        uri = ""
        
        # Handle Lambda@Edge invocation
        if 'Records' in event and len(event.get('Records', [])) > 0 and 'cf' in event['Records'][0]:
            logger.info("Processing Lambda@Edge request")
            request = event['Records'][0]['cf']['request']
            uri = request.get('uri', '')
        
        # Handle API Gateway invocation
        elif 'httpMethod' in event:
            logger.info("Processing API Gateway request")
            request = {
                'method': event.get('httpMethod', ''),
                'uri': event.get('path', ''),
                'headers': {},
                'clientIp': event.get('requestContext', {}).get('identity', {}).get('sourceIp', '')
            }
            
            # Convert API Gateway headers to CloudFront format
            if 'headers' in event and event['headers']:
                for key, value in event['headers'].items():
                    request['headers'][key.lower()] = [{'key': key, 'value': value}]
            
            # Set body from API Gateway format
            if 'body' in event:
                request['body'] = {
                    'data': event['body'],
                    'encoding': 'base64' if event.get('isBase64Encoded', False) else 'text'
                }
            
            uri = request.get('uri', '')
        else:
            # Unknown invocation pattern
            logger.error("Unknown invocation pattern")
            return create_error_response('500', 'Unknown invocation pattern')
        
        # Only handle verify-captcha
        if uri == '/verify-captcha':
            headers = request.get('headers', {})
            client_ip = request.get('clientIp', '')
            host = headers.get('host', [{'value': ''}])[0]['value']
            
            # Configuration
            RECAPTCHA_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'  # change this to your secret key from Google. This key is a demo key for testing from Google
            ALLOWED_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']  # exempt from cookie 
            
            # Initialize WAF token manager
            waf_token_manager = WAFTokenManager()
            
            # Add detailed logging
            logger.info(f"Processing /verify-captcha request - Method: {request.get('method')}")
            
            # Check for existing tokens - check for either cookie
            if check_waf_token(get_cookies(headers)) or check_captcha_verified(get_cookies(headers)):
                logger.info("Valid token found in cookies")
                return request
            
            # Check if IP is in allowed ranges
            if is_ip_in_cidrs(client_ip, ALLOWED_CIDRS):
                logger.info(f"IP {client_ip} is in allowed CIDR ranges")
                return request
            
            # Handle OPTIONS request for CORS
            if request.get('method') == 'OPTIONS':
                logger.info("Handling OPTIONS request")
                
                # Get origin from headers
                origin = '*'
                if 'origin' in headers:
                    origin = headers['origin'][0]['value']
                    
                return {
                    'status': '204',
                    'statusDescription': 'No Content',
                    'headers': {
                        'access-control-allow-origin': [{
                            'key': 'Access-Control-Allow-Origin',
                            'value': origin
                        }],
                        'access-control-allow-methods': [{
                            'key': 'Access-Control-Allow-Methods',
                            'value': 'POST, OPTIONS'
                        }],
                        'access-control-allow-headers': [{
                            'key': 'Access-Control-Allow-Headers',
                            'value': 'Content-Type'
                        }],
                        'access-control-allow-credentials': [{
                            'key': 'Access-Control-Allow-Credentials',
                            'value': 'true'
                        }]
                    }
                }
            
            # Handle GET requests - pass through to let WAF handle it
            if request.get('method') == 'GET':
                logger.info("Handling GET request - passing through to WAF")
                return request

            if request.get('method') != 'POST':
                logger.info(f"Invalid method: {request.get('method')}")
                return create_error_response('405', 'Method Not Allowed', headers)

            # Get and decode the body - handle both formats
            body = request.get('body', {})
            data = None
            
            # Handle Lambda@Edge format (body is an object with data property)
            if isinstance(body, dict) and 'data' in body:
                logger.info("Processing Lambda@Edge body format")
                if not body.get('data'):
                    logger.info("Empty request body received")
                    return create_error_response('400', 'Empty request body', headers)
                
                data = body['data']
                if body.get('encoding') == 'base64':
                    try:
                        data = base64.b64decode(data).decode('utf-8')
                    except Exception as e:
                        logger.error(f"Base64 decode error: {str(e)}")
                        logger.error(f"Exception details: {traceback.format_exc()}")
                        return create_error_response('400', 'Invalid request body encoding', headers)
            
            # Handle API Gateway format (body is a string)
            elif isinstance(body, str):
                logger.info("Processing API Gateway body format (string)")
                data = body
            
            # Handle empty body
            else:
                logger.info("Empty or invalid request body received")
                return create_error_response('400', 'Empty or invalid request body', headers)
                
            logger.info(f"Request body length: {len(data) if data else 0}")

            # Parse body based on content type
            content_type = headers.get('content-type', [{'value': ''}])[0]['value'].lower()
            logger.info(f"Content-Type: {content_type}")
            
            recaptcha_token = None
            original_uri = '/prod/index.html'  # Default to secure HTML endpoint
            
            try:
                # Try JSON parsing first (for new WAF response)
                if 'application/json' in content_type:
                    logger.info("Parsing as JSON")
                    body_data = json.loads(data)
                    logger.info(f"Parsed JSON data: {body_data}")
                    recaptcha_token = body_data.get('token')
                    # Use provided originalUri if available, otherwise use default
                    if 'originalUri' in body_data:
                        original_uri = body_data.get('originalUri')
                    if recaptcha_token:
                        logger.info(f"Extracted token from JSON: {recaptcha_token[:20]}...")
                
                # Try form-encoded parsing (for old WAF response)
                elif 'application/x-www-form-urlencoded' in content_type:
                    logger.info("Parsing as form-encoded data")
                    body_data = dict(urllib.parse.parse_qsl(data))
                    logger.info(f"Parsed form data: {body_data}")
                    recaptcha_token = body_data.get('g-recaptcha-response')
                    # Use provided originalUri if available, otherwise use default
                    if 'originalUri' in body_data:
                        original_uri = body_data.get('originalUri')
                    if recaptcha_token:
                        logger.info(f"Extracted token from form data: {recaptcha_token[:20]}...")
                
                # Try JSON parsing as fallback
                if not recaptcha_token:
                    logger.info("Trying JSON parsing as fallback")
                    try:
                        body_data = json.loads(data)
                        logger.info(f"Fallback JSON parsing successful: {body_data}")
                        recaptcha_token = body_data.get('token') or body_data.get('g-recaptcha-response')
                        # Use provided originalUri if available, otherwise keep current value
                        if 'originalUri' in body_data:
                            original_uri = body_data.get('originalUri')
                        if recaptcha_token:
                            logger.info(f"Extracted token from fallback JSON: {recaptcha_token[:20]}...")
                    except json.JSONDecodeError:
                        logger.info("Failed to parse as JSON")
                
                # Try form parsing as fallback
                if not recaptcha_token:
                    logger.info("Trying form parsing as fallback")
                    try:
                        body_data = dict(urllib.parse.parse_qsl(data))
                        logger.info(f"Fallback form parsing successful: {body_data}")
                        recaptcha_token = body_data.get('g-recaptcha-response') or body_data.get('token')
                        # Use provided originalUri if available, otherwise keep current value
                        if 'originalUri' in body_data:
                            original_uri = body_data.get('originalUri')
                        if recaptcha_token:
                            logger.info(f"Extracted token from fallback form data: {recaptcha_token[:20]}...")
                    except:
                        logger.info("Failed to parse as form data")
                
            except Exception as e:
                logger.error(f"Body parsing error: {str(e)}")
                logger.error(f"Exception details: {traceback.format_exc()}")
                return create_error_response('400', 'Invalid request body format', headers)

            if not recaptcha_token:
                logger.info("Missing CAPTCHA token in request")
                return create_error_response('400', 'Missing CAPTCHA token', headers)

            logger.info(f"Final token length: {len(recaptcha_token)}")
            logger.info(f"Original URI: {original_uri}")
            
            # Verify CAPTCHA token
            verification_result = verify_recaptcha_token(recaptcha_token, RECAPTCHA_SECRET_KEY)
            logger.info(f"CAPTCHA verification result: {verification_result}")

            if verification_result:
                # Set both cookies
                waf_cookie = waf_token_manager.create_token_cookie(host)
                captcha_cookie = waf_token_manager.create_captcha_cookie(host)
                
                # Combine the cookies
                all_cookies = []
                all_cookies.extend(waf_cookie['set-cookie'])
                all_cookies.extend(captcha_cookie['set-cookie'])
                
                # Get origin from request headers
                origin = '*'
                if 'origin' in headers:
                    origin = headers['origin'][0]['value']
                
                # Return response with redirect to the secure HTML page
                response = {
                    'status': '200',
                    'statusDescription': 'OK',
                    'headers': {
                        'set-cookie': all_cookies,
                        'content-type': [{
                            'key': 'Content-Type',
                            'value': 'application/json'
                        }],
                        'cache-control': [{
                            'key': 'Cache-Control',
                            'value': 'no-store, no-cache, must-revalidate'
                        }],
                        'access-control-allow-origin': [{
                            'key': 'Access-Control-Allow-Origin',
                            'value': origin
                        }],
                        'access-control-allow-credentials': [{
                            'key': 'Access-Control-Allow-Credentials',
                            'value': 'true'
                        }]
                    },
                    'body': json.dumps({
                        'success': True,
                        'redirect': '/prod/index.html',  # Redirect to secure HTML endpoint
                        'error': None
                    })
                }
                logger.info(f"Success response: {json.dumps(response, indent=2)}")
                return response
            else:
                return create_error_response('403', 'Invalid CAPTCHA', headers)
        
        # Pass through all other requests
        return request
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return a generic error response
        return create_error_response('500', 'Internal Server Error')

