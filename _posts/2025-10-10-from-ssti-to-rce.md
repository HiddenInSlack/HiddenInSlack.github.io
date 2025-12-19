---
layout: post
title: "From SSTI to RCE: Another tale of N-day research"
date: 2025-12-19 13:00:00
Author: Iago Abad Barreiro
toc: true
---

## INTRODUCTION

During a Red Team engagement that I did some time ago, I managed to get the credentials of an unprivileged user with access to the Back Office of a Prestashop instance. The Prestashop version in use was affected by a [known vulnerability](https://www.cvedetails.com/cve/CVE-2022-21686/), which consists of a Twig Server Side Template Injection. This vulnerability had no available public exploitation details, and it affected recent versions of Prestashop from 1.7.0.0 to 1.7.8.3.

In this post I will conduct a technical breakdown of this interesting vulnerability, detailing the analysis process along the way, which might (or not) provide the reader with insights on how to perform N-day vulnerability research.

Exploring [some advisories](https://security.snyk.io/vuln/SNYK-PHP-PRESTASHOPPRESTASHOP-2385693), I found the [github commit](https://github.com/PrestaShop/PrestaShop/commit/d02b469ec365822e6a9f017e57f588966248bf21) that fixed the vulnerability, along with some hints about the injection happening in the legacy layout.
 
 
![Alt text](/images/from-ssti-to-rce/image1.png)
_Image 1. CVE-2022-21686 advisory_

After checking the commit, I could see the old code that is supposed to be vulnerable, as well as the implemented fix. Here it seems that the **getLegacyLayout** function located in the file [LayoutExtension.php](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/src/PrestaShopBundle/Twig/LayoutExtension.php#L138) is used to perform some string replacements in the **layout** variable. Considering that all the committed changes were done in this function, it seems obvious that this is the code that somehow led to the vulnerability in the first place.
  
![Alt text](/images/from-ssti-to-rce/image2.png){: #fix }
_Image 2. Removed vulnerable code_

### TL DR

This vulnerability arises when attempting to migrate the old legacy framework that uses Smarty to the new framework that is Symfony, which uses Twig.

Whenever the Symfony framework is used, developers decided to create a sort of connection from Smarty into Twig, so they could reuse the Smarty legacy templating system.

This is what **LayoutExtension.php** is meant to do, render the old Smarty templates (where the injection happens) and insert the results into Twig templates (where the previously injected Twig code finally gets evaluated), obtaining the final HTLM code that is delivered to the user. 

After this investigation, I concluded that the complexity in this bridging system between the old and the new framework is the main reason that precipitated the appearance of this vulnerability.

If you don’t want to dive into the technical details of how the vulnerability happens, go to the [arbitrary file read section](#arbitrary-file-read). For the bravest, keep reading on.

## FINDING THE SSTI

### Prestashop routing system

To begin exploring how to reach the vulnerable code, I needed to understand how routing works in the platform. Checking the [documentation](https://devdocs.prestashop-project.org/1.7/) I saw that from version 1.7.X onwards, Prestashop is migrating its old legacy framework to Symfony. 

![Alt text](/images/from-ssti-to-rce/image3.png)
_Image 3. Prestashop 1.7 architecture_

Here FO refers to the Front Office and BO refers to Back Office, which is the administration panel I got access to. The Front Office exclusively uses the legacy framework; however, the Back Office uses the legacy framework in some cases and Symfony in other cases.

![Alt text](/images/from-ssti-to-rce/image4.png)
_Image 4. Prestashop 1.7 themes_

I could also see that the Twig template injection was only present in Symfony controllers located in the Back Office, since the legacy framework exclusively uses Smarty for templating. Thus, to exploit this vulnerability I first needed to find out where the Symfony framework is used in the Back Office. 

![Alt text](/images/from-ssti-to-rce/image5.png){: #routing }
_Image 5. Prestashop 1.7 migrated Back Office routing_

According to the official documentation, I needed to look for controllers that can be reached through routes that follow the pattern **&lt;BackOffice&gt;/index.php/xxxx/xxxx** and belong to the migrated Back Office routing system. When this routing system is hit, it forwards the request to the Symfony kernel, which looks for the right controller to handle the request. At the end of this process, the controller calls the appropriate Twig template to be rendered.

![Alt text](/images/from-ssti-to-rce/image6.png)
_Image 6. Prestashop 1.7 route declaration_

Symfony routes are defined in several YAML files which follow a tree like structure and are located in the **src/PrestaShopBundle/Resources/config/admin** directory, so it should be easy to figure out which controllers use the Symfony routing system. To find controllers that could potentially allow me to reach the vulnerable code, I just needed to check the YAML files looking for routes that the unprivileged user had permissions to reach.
 
![Alt text](/images/from-ssti-to-rce/image7.png)
_Image 7. Prestashop 1.7 route definition_

### Reaching the vulnerable code

Armed with this information, I began by examining how to access the vulnerable code. To do this, I investigated where the vulnerable function **getLegacyLayout** is called. I observed that it occurs in the file [layout.html.twig](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/src/PrestaShopBundle/Resources/views/Admin/layout.html.twig#L26).
 
![Alt text](/images/from-ssti-to-rce/image8.png){: #layout-twig }
_Image 8. Twig file layout.html.twig source code_

The vulnerable function gets called when the **layout.html.twig** template is rendered. The next natural step was to find out when this Twig template is used.

So far, we know that when we hit valid routes of the kind **&lt;BackOffice&gt;/index.php/xxxx/xxxx**, then the Symfony framework handles the request, finding the right controller and calling the appropriate template to be rendered. 

Turns out that **all the templates** used by Symfony controllers use **layout.html.twig** as a base template, extending its functionality as required. This makes sense since **layout.html.twig** is the base template layout for the Back Office panel when Symfony is used.

To give an example of how this happens, let's use the case shown in [image 5](#routing), which uses the Back Office controller **PreferencesController**. This controller calls the Twig template [preferences.html.twig](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/src/PrestaShopBundle/Resources/views/Admin/Configure/ShopParameters/preferences.html.twig#L25).

![Alt text](/images/from-ssti-to-rce/image9.png) 
_Image 9. Twig file preferences.html.twig source code_

Looking at this piece of code, it is confirmed that the **PreferencesController** Twig template extends the base layout template **layout.html.twig**. This allowed me to determine how to reach the vulnerable code mentioned previously. 

To summarize, whenever a request is handled by Symfony, the corresponding controller will call the appropriate template, which extends the **layout.html.twig** base template. This template will then call the vulnerable function **getLegacyLayout** located in **LayoutExtension.php** as previously shown.

### Finding the injection point

Next, I needed to know where and how the injection happens to determine how to exploit it. Checking the vulnerable **getLegacyLayout** function from class **LayoutExtension** located in [LayoutExtension.php](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/src/PrestaShopBundle/Twig/LayoutExtension.php#L138) the following code can be found:
 
![Alt text](/images/from-ssti-to-rce/image10.png)
_Image 10. LayoutExtension::getLegacyLayout source code_

Inside this function, another function with the same name, but belonging to the class **LegacyContext**, gets called before the supposedly vulnerable code that [got fixed in the commit](#fix) is reached. This class can be found in [LegacyContext.php](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/src/Adapter/LegacyContext.php#L148C1-L149C1).

![Alt text](/images/from-ssti-to-rce/image11.png)
_Image 11. LegacyContext::getLegacyLayout source code_

The **LegacyContext::getLegacyLayout** function first calls the **AdminLegacyLayoutControllerCore** constructor defined in [AdminLegacyLayoutController.php](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/controllers/admin/AdminLegacyLayoutController.php#L37), and right after that, an interesting **AdminLegacyLayoutControllerCore::run** function is called.

To understand the code flow that is happening under the hood, we first need to know the chain of inheritance (class extensions) that the class **AdminLegacyLayoutControllerCore** has, which is displayed in the following diagram:

![Alt text](/images/from-ssti-to-rce/image12.png){: #extensionchain }
_Image 12. AdminLegacyLayoutControllerCore inheritance chain diagram_

In the previous diagram it is shown that the **run** function is not implemented in the class **AdminLegacyLayoutControllerCore** itself, but in one of the parent classes. Thus, when the **AdminLegacyLayoutControllerCore::run** call is made, it actually ends up calling the function [ControllerCore::run](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/classes/controller/Controller.php#L234) following the mentioned chain of class inheritance. 

![Alt text](/images/from-ssti-to-rce/image13.png)
_Image 13. ControllerCore::run source code_

The **ControllerCore::run** function then calls the **display** method using the **$this** keyword, which is used to access the current object properties and methods. But as we saw previously, the “current object” or caller is an **AdminLegacyLayoutControllerCore** object, which according to the [diagram](#extensionchain) does implement the display method. Therefore, the **$this->display()** line calls **AdminLegacyLayoutControllerCore::display**.
 
![Alt text](/images/from-ssti-to-rce/image14.png)
_Image 14. AdminLegacyLayoutControllerCore::display source code_

Inside the **AdminLegacyLayoutControllerCore::display** method another call to the **display** method is made, but this time it points to the parent’s (**AdminController**) implementation.

The **AdminController** class does not implement the **display** function, and so [AdminControllerCore::display](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/classes/controller/AdminController.php#L1749) is called following the inheritance chain.
 
![Alt text](/images/from-ssti-to-rce/image15.png)
_Image 15. AdminControlleCore::display source code_

Here, the **smartyOutputContent** function is called receiving the **layout** variable as input parameter. In our inheritance chain [diagram](#extensionchain), it can be observed that the **smartyOutputContent** function is only implemented in **ControllerCore**, which means that the program flow is headed there.

The **layout** variable is declared in the **AdminControllerCore** class though: 
 
![Alt text](/images/from-ssti-to-rce/image16.png)
_Image 16. AdminControllerCore layout variable_

![Alt text](/images/from-ssti-to-rce/image17.png)
_Image 17. Hang in there_

![Alt text](/images/from-ssti-to-rce/image18.png)
_Image 18. ControllerCore::smartyOutputContent source code_

The function **ControllerCore::smartyOtuputContent** is mainly used to render Smarty templates according to the context, which in our case is the Back Office Smarty main theme [layout.tpl](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/admin-dev/themes/new-theme/template/layout.tpl).

This means that when the **fetch** function is called within **ControllerCore::smartyOutputContent**, the Smarty **layout.tpl** template is going to be fetched and rendered.

![Alt text](/images/from-ssti-to-rce/image19.png) 
_Image 19. layout.tpl source code_

This template then includes the Smarty template [quick_access.tpl](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/admin-dev/themes/new-theme/template/components/layout/quick_access.tpl).

![Alt text](/images/from-ssti-to-rce/image20.png){: #quick-access }
_Image 20. quick_access.tpl source code_

It is here, in the [data-url field](https://github.com/PrestaShop/PrestaShop/blob/1.7.4.2/admin-dev/themes/new-theme/template/components/layout/quick_access.tpl#L38), that **quick_access.tpl** receives the PHP server variable **REQUEST_URI** (which contains the GET parameters sent to the server) and performs some escaping on it, mainly over the characters ' and ". 

This means that we can inject Twig code in this place using GET parameters. We will find the result of the injection in the **data-url** field of the code generated once the **quick_access.tpl** template gets rendered. After this, the **ControllerCore::smartyOutputContent** function exits and the program returns to **LegacyContext::getLegacyLayout**.

Once we get back to the **LegacyContext::getLegacyLayout** function, it can be observed that it returns the content of the **outPutHtml** attribute of the **AdminLegacyLayourControllerCore** class. This field contains our newly rendered Smarty template which contains the **REQUEST_URI** variable where we have injected our arbitrary Twig code sent over GET parameters.
 
![Alt text](/images/from-ssti-to-rce/image21.png)
_Image 21. LegacyContext::getLegacyLayout returns outPutHtml_

Finally, the vulnerable **LayoutExtension::getLegacyLayout** function receives this output and loads it into the **layout** variable. Additional processing is done over this **layout** variable before returning the content to our main [layout.html.twig](#layout-twig) template.

![Alt text](/images/from-ssti-to-rce/image22.png)
_Image 22. layout variable containing Twig injection_

At last, the **layout.html.twig** template gets rendered, resulting in our Twig injection located in the **data-url** HTML field being evaluated. With this procedure, I achieved the goal of identifying how to exploit the SSTI vulnerability.

### Arbitrary file read

Let’s see a practical scenario of how the injection happens and how it can be exploited to achieve arbitrary file read. 

In the engagement, I had access to the module manager endpoint **&lt;BackOffice&gt;/index.php/module/manage**, but I had no permissions to upload a new module. Despite that, this endpoint can be abused to exploit the SSTI as it uses the Symfony framework for routing.

We start by injecting some characters in a GET parameter to see how the application behaves after rendering the Smarty template **quick_access.tpl**.

We then print the output of the rendered Smarty Template before the Twig rendering happens. This way we can see the behavior of the Smarty rendering, what exactly is being fed into the Twig Template Engine and why this vulnerability is exploitable. 

![Alt text](/images/from-ssti-to-rce/image23.png)
_Image 23. Contents of the rendered Smarty template_

It can be seen that the **quick_access.tpl** Smarty template receives the [REQUEST_URI](#quick-access) server variable, which contains our GET parameter **'a'**. 

The characters ' and " are escaped in the Smarty template rendering process (using **escape:'javascript'**	), but nothing is done with {} and (). This means that we can inject Twig code using this combination of characters. We just have to look for a way to bypass the forbidden usage of ' and ", as using them would yield a Twig syntax error.

To accomplish this, we use the following payload as GET parameters:

```
{% raw %}a=/etc/passwd&b={{source(app.request.query.all.a)}}{% endraw %}
```
<p class="text-center text-muted">
  <em>Snippet 1. Arbitrary file read Twig payload</em>
</p>

In our case, two parameters **‘a’** and **‘b’** were leveraged to avoid using something like **source(“/etc/passwd”)** directly. 

*	The parameter **‘b’** uses the **source** Twig function, which injects the content of a given file into the current template without rendering it. This parameter also uses **app.request.query.all**, which allows to access the content of GET parameters from a template. 
*	The parameter **‘a’** contains the path to the file that we want to feed to the **source** function, in this case **/etc/passwd**. 

To clarify, the **app.request** object that is being used in this payload is [available in Symfony default installations](https://symfony.com/doc/current/templates.html#the-app-global-variable), and it is an instance of the class [Request](https://github.com/symfony/symfony/blob/7.0/src/Symfony/Component/HttpFoundation/Request.php). 
 
![Alt text](/images/from-ssti-to-rce/image24.png)
_Image 24. Symfony class Request definition_

![Alt text](/images/from-ssti-to-rce/image25.png)
_Image 25. Symfony’s Request class described in the official documentation_

Again, we print the content of the rendered Smarty template before it is passed to Twig.

![Alt text](/images/from-ssti-to-rce/image26.png)
_Image 26. Contents of the rendered Smarty template containing Twig code_

We can see that our Twig code gets successfully injected into the contents of the Smarty template after the rendering process. This content is then returned to the Twig template [layout.html.twig](#layout-twig), which renders and evaluates our injected Twig code. 

The following image shows the final rendered Twig template containing the output of our injected and evaluated Twig code. 
 
![Alt text](/images/from-ssti-to-rce/image27.png)
_Image 27. Arbitrary file read achieved via Twig injection_

## FROM SSTI TO RCE

Knowing how to achieve arbitrary file read through this vulnerability, I focused on how to leverage it with the objective of getting remote code execution on the server.

There are some well-known Twig SSTI payloads to get remote code execution once an injection of this type has been identified. One such payload is:

```
{% raw %}{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}{% endraw %}
```
<p class="text-center text-muted">
  <em>Snippet 2. Twig payload to achieve RCE</em>
</p>

This Twig SSTI payload leverages access to the **Twig_Environment** class located in **vendor/twig/twig/lib/Twig/Environment.php** (through **_self.env**), to perform actions like [registering a callback for filters](https://twig.symfony.com/doc/1.x/recipes.html#defining-undefined-functions-and-filters-on-the-fly) and execute code.
 
![Alt text](/images/from-ssti-to-rce/image28.png)
_Image 28. Twig documentation on defining functions and filters on the fly_

This is fixed since Twig 1.20 in the [following commit](https://github.com/twigphp/Twig/commit/a8a125ba9b31d20e8ad50e0d1078983ed7fa41a7): 
 
![Alt text](/images/from-ssti-to-rce/image29.png)
_Image 29. Twig_Environment class access restriction_

The **getAttribute** function modified in the commit is called whenever we try to access a class attribute or function from a template using Twig. An example of this could be the following Twig code:

```
{% raw %}{{ exampleclass.exampleattribute }}
{{ exampleclass.excamplefunction(exampleparam) }}{% endraw %}
```
<p class="text-center text-muted">
  <em>Snippet 3. Accessing class attributes and functions from Twig</em>
</p>

The fixing commit adds some additional checks to prevent direct access from a template to sensitive resources in the **Twig_Template** class (notice **_self** is an instance of this class) located in **vendor/twig/twig/lib/Twig/Template.php**. The forbidden resources are:

*	Internal class attributes such as **env**.
*	The sensitive class function **getEnvironment**.
 
![Alt text](/images/from-ssti-to-rce/image30.png)
_Image 30. Twig_Template class definition_
 
![Alt text](/images/from-ssti-to-rce/image31.png)
_Image 31. Twig_Template::getEnvironment function definition_

This means that the following Twig code examples are not allowed:

```
{% raw %}{{ _self.env }}
{{ _self.getEnvironment() }}{% endraw %}
```
<p class="text-center text-muted">
  <em>Snippet 4. Invalid Twig code to access Twig_Environment</em>
</p>

As I said before, this fix is up since Twig version > 1.20, and the Prestashop instance I was dealing with used Twig version 1.35.3, so this code execution pathway was not an option.

**NOTE**: This research was conducted some time ago, and so as of today (I think) there is another known way of achieving code execution that bypasses this fix.

### Secret fragment RCE

I had to investigate how to leverage this SSTI to get RCE in a different way than using the classic payloads. Noticing that the Prestashop instance was running Symfony 5.0.4, which is vulnerable to the secret fragment RCE explained in [this post](https://www.ambionics.io/blog/symfony-secret-fragment), I could then check if the **_fragment** endpoint was reachable to the compromised unprivileged user.
 
![Alt text](/images/from-ssti-to-rce/image32.png)
_Image 32. Back Office routing defined in &lt;BackOffice&gt;/index.php_

When trying to reach the Back Office, Prestashop first checks if the route exists in the Symfony routing system, and if that is not the case, it then tries using the legacy routing system. 

At this point, since I understood how the routing is handled in the platform, I concluded that nothing should prevent me from reaching the **_fragment** endpoint.
 
![Alt text](/images/from-ssti-to-rce/image33.png)
_Image 33. Reaching the Symfony _fragment endpoint_

By abusing the already obtained arbitrary file read capability, I should be able to exfiltrate Symfony's secret to potentially get remote code execution abusing the RCE previously mentioned. But to get Symfony's secret I first needed to know the webroot location. 

Again, using **app.request** I could exfiltrate the global **$_SERVER** PHP variable, which is accessible through **app.request.server**. The **join** Twig function just concatenates a list of strings using any specified separator, which in this case is the character '&#124;'.
 
![Alt text](/images/from-ssti-to-rce/image34.png)
_Image 34. Exfiltrating the webroot location_

After obtaining the location of the webroot, I was able to easily exfiltrate Symfony's secret using the arbitrary file read.

![Alt text](/images/from-ssti-to-rce/image35.png)
_Image 35. Exfiltrating the Symfony secret_

With this secret in my hands, I could finally sign requests for the **_fragment** endpoint and trigger the deserialization that executes arbitrary code. I used [phpggc](https://github.com/ambionics/phpggc) to craft the object to be deserialized and then I signed the request with the leaked Symfony secret, meaning that at this point I had everything I needed to achieve code execution on the server. 
 
![Alt text](/images/from-ssti-to-rce/image36.png)
_Image 36. Trying to achieve RCE through the Symfony secret fragment vulnerability_

Finally, I also had to consider that a valid **_token** is needed to successfully reach the **_fragment** endpoint. This always happens by default in Prestashop when accessing Back Office endpoints. 

The token can be trivially obtained by logging in to the Back Office and retrieving the returned **_token** parameter. 
 
Putting it all together I managed to finally get code execution on the underlying server. 
 
![Alt text](/images/from-ssti-to-rce/image37.png)
_Image 37. Code execution through the Symfony secret fragment vulnerability_

## CONCLUSION

In this post I took a deep dive at CVE-2022-21686 to determine the details of how the vulnerability happens and how to exploit it whenever an unprivileged user with Prestashop Back Office access is compromised.

This vulnerability arises as a result of a migration process from a legacy framework that uses Smarty into the Symfony framework that uses Twig. In the places where Symfony is used, a bridging system was put in place to connect the old Smarty templating system into the Twig templating system. The complexity of this bridging system is what led the developers to introduce the vulnerability in the form of capacity for unprivileged users to inject Twig code.

The affected versions range from Prestashop version 1.7.0.0 to 1.7.8.3 (not included).

Huge shoutout to [Kurosh](https://x.com/_Kudaes_) for his humongous work when reviewing this post. 

This was very fun to research. I hope that someone finds this insightful regarding N-day research methodology, and if you made it to this point, I hope you enjoyed it!