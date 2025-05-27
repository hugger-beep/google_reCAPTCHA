# AWS WAF with Google reCAPTCHA Architecture

## Architecture Diagram

```mermaid
flowchart TB
    %% Define styles
    classDef user fill:#f9f,stroke:#333,stroke-width:2px
    classDef cloudfront fill:#FF9900,stroke:#333,stroke-width:2px,color:white
    classDef waf fill:#3B48CC,stroke:#333,stroke-width:2px,color:white
    classDef apigateway fill:#E7157B,stroke:#333,stroke-width:2px,color:white
    classDef lambda fill:#009900,stroke:#333,stroke-width:2px,color:white
    classDef google fill:#4285F4,stroke:#333,stroke-width:2px,color:white
    classDef policy fill:#232F3E,stroke:#333,stroke-width:2px,color:white
    
    %% Define nodes
    User((User)):::user
    CF[CloudFront Distribution]:::cloudfront
    WAF1[AWS WAF]:::waf
    APIGW[API Gateway]:::apigateway
    WAF2[AWS WAF]:::waf
    RP[Resource Policy]:::policy
    
    %% Define Lambda functions
    LambdaVerify[Lambda@Edge\nverify_captcha.py]:::lambda
    LambdaServe[Lambda\nserve_html.py]:::lambda
    
    %% Define Google reCAPTCHA
    Google[Google reCAPTCHA\nVerification Service]:::google
    
    %% Define CloudFront behaviors
    subgraph CFBehaviors[CloudFront Behaviors]
        direction TB
        B1["/verify-captcha\n→ API Gateway"]
        B2["/serve-html-api\n→ API Gateway"]
        B3["/index.html\n→ API Gateway"]
        B4["/ (Default)\n→ Custom Error Page"]
    end
    
    %% Define API Gateway paths
    subgraph APIPaths[API Gateway Paths]
        direction TB
        P1["/verify-captcha\n→ Lambda"]
        P2["/serve-html-api\n→ Lambda"]
        P3["/index.html\n→ Lambda"]
        P4["/waf-captcha-verification\n→ Lambda"]
    end
    
    %% Define WAF rules
    subgraph WAFRules[WAF Rules]
        direction TB
        R1["Check for Cookies:\n- aws-waf-token=true\n- captcha_verified=true"]
        R2["If No Cookies:\nServe CAPTCHA Page"]
    end
    
    %% Define connections
    User -->|1. Request Protected Content| CF
    CF -->|2. Check Request| WAF1
    WAF1 -->|3a. No Cookies| User
    WAF1 -->|3b. Has Cookies| CF
    
    CF -->|4. Forward Request| APIGW
    APIGW -->|5. Check Request| WAF2
    APIGW -->|6. Apply| RP
    
    %% API Gateway to Lambda connections
    APIGW -->|7a. /verify-captcha| LambdaVerify
    APIGW -->|7b. /serve-html-api| LambdaServe
    
    %% Lambda to Google connection
    LambdaVerify -->|8. Verify Token| Google
    Google -->|9. Verification Result| LambdaVerify
    
    %% Response flow
    LambdaVerify -->|10. Set Cookies & Redirect| APIGW
    LambdaServe -->|11. Serve Protected Content| APIGW
    APIGW -->|12. Response| CF
    CF -->|13. Response to User| User
    
    %% Connect subgraphs
    CF -.-> CFBehaviors
    APIGW -.-> APIPaths
    WAF1 -.-> WAFRules
    
    %% Apply styles
    classDef subgraph fill:#f5f5f5,stroke:#333,stroke-width:1px
    class CFBehaviors,APIPaths,WAFRules subgraph
```

## Detailed Flow

1. **User Request**: User attempts to access protected content
2. **CloudFront Distribution**: Receives the request and forwards it to AWS WAF
3. **AWS WAF (CloudFront)**: 
   - Checks for required cookies (`aws-waf-token=true` or `captcha_verified=true`)
   - If cookies are missing, serves the Google reCAPTCHA challenge page
   - If cookies are present, allows the request to proceed
4. **CloudFront Behaviors**:
   - Routes `/verify-captcha` to API Gateway
   - Routes `/serve-html-api` to API Gateway
   - Routes `/index.html` to API Gateway
   - Default route serves the CAPTCHA challenge page
5. **API Gateway**:
   - Receives requests from CloudFront
   - Routes to appropriate Lambda functions based on path
   - Protected by Resource Policy (allows only CloudFront and specific IPs)
   - Protected by second AWS WAF
6. **Lambda Functions**:
   - `verify_captcha.py`: Verifies reCAPTCHA tokens with Google's API and sets cookies
   - `serve_html.py`: Serves protected content after verifying cookies
7. **Google reCAPTCHA**: Verifies CAPTCHA tokens submitted by users
8. **Response Flow**:
   - After successful verification, cookies are set and user is redirected
   - Protected content is served to authenticated users

## Security Measures

1. **Dual WAF Protection**:
   - WAF at CloudFront level for initial cookie verification
   - WAF at API Gateway level for additional protection
2. **Resource Policy**:
   - Restricts API Gateway access to CloudFront and specific IPs
3. **Cookie Verification**:
   - Both WAF and Lambda functions verify the presence of required cookies
4. **Custom Headers**:
   - CloudFront adds custom headers for API Gateway authorization
5. **HTTPS Throughout**:
   - All communications use HTTPS for encryption

## Implementation Notes

- The solution uses Google reCAPTCHA instead of AWS WAF CAPTCHA
- Cookies are set with appropriate security attributes
- The architecture can be adapted to use other CAPTCHA providers
- The solution includes proper error handling and user feedback
