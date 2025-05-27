# AWS WAF with Google reCAPTCHA Architecture (Split Diagram)

## User Flow Diagram

``` mermaid

graph TB
    User((User))
    CF[CloudFront Distribution]
    WAF1[AWS WAF]
    APIGW[API Gateway]
    WAF2[AWS WAF]
    RP[Resource Policy]
    LambdaVerify[Lambda verify_captcha.py]
    LambdaServe[Lambda serve_html.py]
    Google[Google reCAPTCHA]
    
    User -->|1- Request| CF
    CF -->|2- Check| WAF1
    WAF1 -->|3a- No Cookies| User
    WAF1 -->|3b- Has Cookies| CF
    
    CF -->|4- Forward| APIGW
    APIGW -->|5- Check| WAF2
    APIGW -->|6- Apply| RP
    
    APIGW -->|7a- verify-captcha| LambdaVerify
    APIGW -->|7b- serve-html-api| LambdaServe
    
    LambdaVerify -->|8- Verify| Google
    Google -->|9- Result| LambdaVerify
    
    LambdaVerify -->|10- Set Cookies| APIGW
    LambdaServe -->|11- Serve Content| APIGW
    APIGW -->|12- Response| CF
    CF -->|13- Response| User
    
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
    
    CF -.-> CFBehaviors
    APIGW -.-> APIPaths
    WAF1 -.-> WAFRules
    
    style User fill:#f9f,stroke:#333
    style CF fill:#FF9900,stroke:#333,color:white
    style WAF1 fill:#3B48CC,stroke:#333,color:white
    style WAF2 fill:#3B48CC,stroke:#333,color:white
    style APIGW fill:#E7157B,stroke:#333,color:white
    style LambdaVerify fill:#009900,stroke:#333,color:white
    style LambdaServe fill:#009900,stroke:#333,color:white
    style Google fill:#4285F4,stroke:#333,color:white
    style RP fill:#232F3E,stroke:#333,color:white
    style CFBehaviors fill:#f5f5f5,stroke:#333
    style APIPaths fill:#f5f5f5,stroke:#333
    style WAFRules fill:#f5f5f5,stroke:#333
```

## Architecture Components Diagram

```mermaid
flowchart TB
    %% Define styles
    classDef cloudfront fill:#FF9900,stroke:#333,stroke-width:2px,color:white
    classDef waf fill:#3B48CC,stroke:#333,stroke-width:2px,color:white
    classDef apigateway fill:#E7157B,stroke:#333,stroke-width:2px,color:white
    classDef lambda fill:#009900,stroke:#333,stroke-width:2px,color:white
    classDef policy fill:#232F3E,stroke:#333,stroke-width:2px,color:white
    
    %% Define main components
    CF[CloudFront Distribution]:::cloudfront
    WAF1[AWS WAF]:::waf
    APIGW[API Gateway]:::apigateway
    WAF2[AWS WAF]:::waf
    RP[Resource Policy]:::policy
    
    %% Define Lambda functions
    LambdaVerify[Lambda@Edge\nverify_captcha.py]:::lambda
    LambdaServe[Lambda\nserve_html.py]:::lambda
    
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
    
    %% Define Resource Policy
    subgraph ResourcePolicy[Resource Policy]
        direction TB
        RP1["Allow: CloudFront IPs"]
        RP2["Allow: Specific IPs"]
        RP3["Deny: All Others"]
    end
    
    %% Connect components
    CF --- WAF1
    CF --- APIGW
    APIGW --- WAF2
    APIGW --- RP
    APIGW --- LambdaVerify
    APIGW --- LambdaServe
    
    %% Connect subgraphs
    CF -.-> CFBehaviors
    APIGW -.-> APIPaths
    WAF1 -.-> WAFRules
    RP -.-> ResourcePolicy
    
    %% Apply styles
    classDef subgraph fill:#f5f5f5,stroke:#333,stroke-width:1px
    class CFBehaviors,APIPaths,WAFRules,ResourcePolicy subgraph
```

## Detailed Flow

1. **Initial Request**:
   - User attempts to access protected content
   - CloudFront forwards request to AWS WAF
   - WAF checks for required cookies
   - If cookies are missing, WAF serves the Google reCAPTCHA challenge page

2. **CAPTCHA Verification**:
   - User completes the CAPTCHA challenge
   - JavaScript sends the CAPTCHA token to `/verify-captcha`
   - CloudFront forwards the request to API Gateway
   - API Gateway invokes the `verify_captcha.py` Lambda function
   - Lambda verifies the token with Google reCAPTCHA service
   - If valid, Lambda sets cookies and returns a redirect response

3. **Authenticated Access**:
   - User is redirected with cookies set
   - CloudFront forwards the new request to WAF
   - WAF checks for cookies and allows the request
   - CloudFront forwards to API Gateway based on the path
   - API Gateway invokes the appropriate Lambda function
   - `serve_html.py` verifies cookies again and serves protected content

## Security Measures

1. **Dual WAF Protection**:
   - WAF at CloudFront level for initial cookie verification
   - WAF at API Gateway level for additional protection

2. **Resource Policy**:
   - Restricts API Gateway access to CloudFront and specific IPs
   - Prevents direct access to API Gateway endpoints

3. **Cookie Verification**:
   - Both WAF and Lambda functions verify the presence of required cookies
   - Cookies are set with secure attributes

4. **Custom Headers**:
   - CloudFront adds custom headers for API Gateway authorization

5. **HTTPS Throughout**:
   - All communications use HTTPS for encryption
