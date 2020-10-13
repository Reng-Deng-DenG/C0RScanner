# C0RScanner
Simple CORS Scanner using python3

add your target's url into the target.txt file

```
fuzzme@fuzzme-GL63-8RC:~/C0RScanner$ python3 corscanner.py 
(!) - Application Trust Arbitrary Origin : http://fuzzme.org/chall/1/x.php 
Access-Control-Allow-Origin: attacker.com
Acess-Control-Allow-Credentials: true

(!) - Application Trust null Origin : http://fuzzme.org/chall/1/x.php 
Access-Control-Allow-Origin: null
Acess-Control-Allow-Credentials: true

(!) - Application Trust Any Subdomain : http://fuzzme.org/chall/1/x.php 
Access-Control-Allow-Origin: http://attacker.com.fuzzme.org
Acess-Control-Allow-Credentials: true

```
