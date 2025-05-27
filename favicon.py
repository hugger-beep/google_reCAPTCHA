### lambda@edge for favicon.ico 

import json
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Viewer Request Lambda@Edge handler for favicon.ico"""
    try:
        logger.info("FAVICON HANDLER: Received event")
        
        request = event['Records'][0]['cf']['request']
        uri = request.get('uri', '')
        
        # Only handle favicon.ico
        if 'favicon.ico' in uri or uri.endswith('favicon.ico') or uri == '/favicon.ico':
            logger.info("Serving default favicon")
            # Return a transparent 1x1 pixel ICO file as base64
            transparent_ico = "AAABAAEAAQEAAAEAIAAwAAAAFgAAACgAAAABAAAAAgAAAAEAIAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//AAA="
            return {
                'status': '200',
                'statusDescription': 'OK',
                'headers': {
                    'content-type': [{
                        'key': 'Content-Type',
                        'value': 'image/x-icon'
                    }],
                    'cache-control': [{
                        'key': 'Cache-Control',
                        'value': 'public, max-age=86400'
                    }],
                    'access-control-allow-origin': [{
                        'key': 'Access-Control-Allow-Origin',
                        'value': '*'
                    }]
                },
                'bodyEncoding': 'base64',
                'body': transparent_ico
            }
        
        # Pass through all other requests
        return request
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        # Pass through the request on error
        return event['Records'][0]['cf']['request']
