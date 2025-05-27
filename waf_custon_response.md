## CAPTCHA Challenge Page

The CAPTCHA challenge page contains the HTML, CSS, and JavaScript needed to:

1. Display the Google reCAPTCHA challenge
2. Verify the CAPTCHA token with the backend
3. Set cookies for authenticated access
4. Redirect to the protected content

Key implementation details:
- Uses Google reCAPTCHA v2
- Sends verification requests to `/verify-captcha` endpoint
- Dynamically builds redirect URLs using the URL constructor
- Includes error handling and user feedback



// one change replace the cloudfront domain 

``` text

<!DOCTYPE html><html><head><title>Verify you are human</title><script src="https://www.google.com/recaptcha/api.js?render=explicit"></script><style>.c{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;font-family:Arial,sans-serif}.f{background:#f9f9f9;padding:2rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.b{margin-top:1rem;padding:.5rem 1rem;background-color:#4CAF50;color:#fff;border:none;border-radius:4px;cursor:pointer}.b:disabled{background-color:#ccc;cursor:not-allowed}.e{color:red;margin-top:1rem;display:none}.l{display:none;margin-top:1rem}</style></head><body><div class="c"><div class="f"><h2>Please verify you are human</h2><form id="f"><div id="rc"></div><div id="e" class="e">Please complete the CAPTCHA</div><div id="l" class="l">Verifying...</div><button type="submit" id="s" class="b" disabled>Submit</button></form></div></div><script>var onloadCallback=function(){grecaptcha.render('rc',{sitekey:'6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',callback:onSubmit})};function onSubmit(t){document.getElementById('s').disabled=false;document.getElementById('e').style.display='none'}document.getElementById('f').addEventListener('submit',function(e){
  e.preventDefault();
  const r=grecaptcha.getResponse();
  if(!r){
    document.getElementById('e').style.display='block';
    return;
  }
  
  document.getElementById('l').style.display='block';
  document.getElementById('s').disabled=true;

// replace below with your cloudfront domain

  fetch('https://xxxxxxx.cloudfront.net/verify-captcha',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({token:r,originalUri:window.location.pathname}),
    credentials:'include'
  })
  .then(r => {
    if(!r.ok) {
      return r.json().then(d => {
        throw new Error(d.error || 'Verification failed');
      });
    }
    return r.json();
  })
  .then(d => {
    console.log('Success response:', d);
    if(d.success) {
      document.getElementById('l').textContent = 'Verification successful! Redirecting...';
      
      // Build the redirect URL dynamically
      // Log the server response for debugging
      console.log('Server response:', d);

      // Force the path to be /serve-html-api regardless of what the server returns
      let redirectUrl = new URL('/serve-html-api', window.location.origin).href;
      
      console.log('Redirect URL:', redirectUrl);
      
      // Add a delay to ensure cookies are set
      setTimeout(function() {
        window.location.href = redirectUrl;
      }, 1000);
    } else {
      throw new Error(d.error || 'Verification failed');
    }
  })
  .catch(x => {
    console.error('Error:', x);
    document.getElementById('e').textContent = x.message;
    document.getElementById('e').style.display = 'block';
    document.getElementById('l').style.display = 'none';
    document.getElementById('s').disabled = false;
    grecaptcha.reset();
  });
});function onExpired(){document.getElementById('s').disabled=true;document.getElementById('e').style.display='none';document.getElementById('l').style.display='none'}</script><script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit" async defer></script></body></html>
```
