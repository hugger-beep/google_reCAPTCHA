# AWS WAF with Google reCAPTCHA Architecture

## Architecture Diagram

```mermaid
graph TB
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
    LambdaVerify[Lambda verify_captcha.py]:::lambda
    LambdaServe[Lambda serve_html.py]:::lambda
    Google[Google reCAPTCHA]:::google
    
    %% Define connections
    User -->|1. Request| CF
    CF -->|2. Check| WAF1
    WAF1 -->|3a. No Cookies| User
    WAF1 -->|3b. Has Cookies| CF
    
    CF -->|4. Forward| APIGW
    APIGW -->|5. Check| WAF2
    APIGW -->|6. Apply| RP
    
    APIGW -->|7a. verify-captcha| LambdaVerify
    APIGW -->|7b. serve-html-api| LambdaServe
    
    LambdaVerify -->|8. Verify| Google
    Google -->|9. Result| LambdaVerify
    
    LambdaVerify -->|10. Set Cookies| APIGW
    LambdaServe -->|11. Serve Content| APIGW
    APIGW -->|12. Response| CF
    CF -->|13. Response| User
    
    %% Define subgraphs
    subgraph CFBehaviors[CloudFront Behaviors]
        B1[verify-captcha]
        B2[serve-html-api]
        B3[index.html]
        B4[Default]
    end
    
    subgraph APIPaths[API Gateway Paths]
        P1[verify-captcha]
        P2[serve-html-api]
        P3[index.html]
        P4[waf-captcha-verification]
    end
    
    subgraph WAFRules[WAF Rules]
        R1[Check Cookies]
        R2[Serve CAPTCHA]
    end
    
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
