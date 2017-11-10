#写在前面
***
本文通过搜集、分析网上的各种struts2相关资料(所参考资料将会列在最后)意在提供一个较为全面的关于struts2的分析文章，帮助各位理解漏洞产生的原因以及了解相关修复机制，以及结合git上出现的批量利用脚本来打造一个新的利用脚本。当然，由于个人水平原因可能编写的相关内容有所纰漏或者错误。希望各位能够指出。感激不尽。
	
	
#历史出现漏洞
***
截至此时(2017/11/8)出现的Struts2漏洞如下(来源来自apache官网，具体链接见文末)
	
	S2-001 — Remote code exploit on form validation error
			 表单认证失败导致远程代码执行
    S2-002 — Cross site scripting (XSS) vulnerability on <s:url> and <s:a> tags
			 <s:urli>、<s:a>标签中存在XSS
    S2-003 — XWork ParameterInterceptors bypass allows OGNL statement execution
			 绕过XWork参数拦截器导致OGNL语句执行
    S2-004 — Directory traversal vulnerability while serving static content
			 提供的静态内容导致目录遍历
    S2-005 — XWork ParameterInterceptors bypass allows remote command execution
			 绕过XWork参数拦截器导致远程代码执行
    S2-006 — Multiple Cross-Site Scripting (XSS) in XWork generated error pages
			 XWork生成的错误页面包含多处XSS
    S2-007 — User input is evaluated as an OGNL expression when there's a conversion error
			 转换错误导致用户输入可当作OGNL表达式执行
    S2-008 — Multiple critical vulnerabilities in Struts2
			 Struts2存在多处严重漏洞
    S2-009 — ParameterInterceptor vulnerability allows remote command execution
			 参数拦截器漏洞导致远程代码执行
    S2-010 — When using Struts 2 token mechanism for CSRF protection, token check may be bypassed by misusing known session attributes
			 通过滥用会话参数可以绕过Struts2自带的防御CSRF的token
    S2-011 — Long request parameter names might significantly promote the effectiveness of DOS attacks
			 过长的的请求参数名可能提高DOS攻击能力
    S2-012 — Showcase app vulnerability allows remote command execution
			 Showcase应用中的漏洞允许远程代码执行
    S2-013 — A vulnerability, present in the includeParams attribute of the URL and Anchor Tag, allows remote command execution
			 URL的includeParams属性以及Anchor标签中的漏洞导致远程代码执行
    S2-014 — A vulnerability introduced by forcing parameter inclusion in the URL and Anchor Tag allows remote command execution, session access and manipulation and XSS attacks
			 URL中的参数包含以及a标签导致远程代码执行，会话获取及操作以及XSS攻击
    S2-015 — A vulnerability introduced by wildcard matching mechanism or double evaluation of OGNL Expression allows remote command execution.
			 通配符匹配机制或者OGNL表达式二次执行的漏洞导致远程代码执行
    S2-016 — A vulnerability introduced by manipulating parameters prefixed with "action:"/"redirect:"/"redirectAction:" allows remote command execution
			 对参数加上"action:"/"redirect:"/"redirectAction:"前缀导致远程代码执行
    S2-017 — A vulnerability introduced by manipulating parameters prefixed with "redirect:"/"redirectAction:" allows for open redirects
			 参数头前加上"redirect:"/"redirectAction:"前缀导致重定向
    S2-018 — Broken Access Control Vulnerability in Apache Struts2
			 中断的会话控制漏洞
    S2-019 — Dynamic Method Invocation disabled by default
			 默认下动态方法Invocation被禁止
    S2-020 — Upgrade Commons FileUpload to version 1.3.1 (avoids DoS attacks) and adds 'class' to exclude params in ParametersInterceptor (avoid ClassLoader manipulation)
			 默认上传机制存在漏洞导致DoS攻击以及参数拦截器漏洞导致getClass()方法滥用
    S2-021 — Improves excluded params in ParametersInterceptor and CookieInterceptor to avoid ClassLoader manipulation
			 参数拦截器以及Cookie拦截器过滤不完整导致ClassLoader可进行更改
    S2-022 — Extends excluded params in CookieInterceptor to avoid manipulation of Struts' internals
			 Cookie拦截器过滤不完整导致可对Struts内部进行更改
    S2-023 — Generated value of token can be predictable
			 生成的token值可被计算出来
    S2-024 — Wrong excludeParams overrides those defined in DefaultExcludedPatternsChecker
			 错误的excludeParams值会覆盖DefaultExcludePatternsChecker中预定义的值
    S2-025 — Cross-Site Scripting Vulnerability in Debug Mode and in exposed JSP files
			 Debug模式下以及暴露的JSP文件中存在跨站脚本漏洞
    S2-026 — Special top object can be used to access Struts' internals
			 使用特殊的top对象导致可访问Struts内部
    S2-027 — TextParseUtil.translateVariables does not filter malicious OGNL expressions
			 TextParseUtil.translateVariables无法筛选恶意OGNL表达式
    S2-028 — Use of a JRE with broken URLDecoder implementation may lead to XSS vulnerability in Struts 2 based web applications.
			 在基于Struts2的web应用中使用带问题的JRE可能导致XSS
    S2-029 — Forced double OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution.
			 OGNL二次执行: 当在用户原生输入的tag属性中可能会导致远程代码执行
    S2-030 — Possible XSS vulnerability in I18NInterceptor
			 I18NInterceptor中可能存在XSS
    S2-031 — XSLTResult can be used to parse arbitrary stylesheet
			 XSLTResult解析任意样式表
    S2-032 — Remote Code Execution can be performed via method: prefix when Dynamic Method Invocation is enabled.
			 当开启动态方法Invocation时特定前缀可能导致远程代码执行
    S2-033 — Remote Code Execution can be performed when using REST Plugin with ! operator when Dynamic Method Invocation is enabled.
			 动态方法Invocation开启下使用REST插件以及！运算符会导致远程代码执行
    S2-034 — OGNL cache poisoning can lead to DoS vulnerability
			 对OGNL缓存进行投毒可能导致DoS
    S2-035 — Action name clean up is error prone
			 清除Action名导致出错
    S2-036 — Forced double OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution (similar to S2-029)
			 类似S2-029 用户在tag属性中的输入导致远程代码执行
    S2-037 — Remote Code Execution can be performed when using REST Plugin.
			 使用REST插件导致远程代码执行
    S2-038 — It is possible to bypass token validation and perform a CSRF attack
			 绕过token验证导致CSRF
    S2-039 — Getter as action method leads to security bypass
			 action中使用了getter导致绕过安全验证
    S2-040 — Input validation bypass using existing default action method.
			 使用现有默认action方法可能导致绕过输入验证
    S2-041 — Possible DoS attack when using URLValidator
			 使用URLValidator可能导致DoS攻击
    S2-042 — Possible path traversal in the Convention plugin
			 Convention插件中可能存在路径遍历
    S2-043 — Using the Config Browser plugin in production
			 生产环境中使用Config Browser插件可能泄露应用漏洞信息
    S2-044 — Possible DoS attack when using URLValidator
			 使用URLValidator可能导致DoS
    S2-045 — Possible Remote Code Execution when performing file upload based on Jakarta Multipart parser.
			 使用Jakarta Multipart parser进行文件上传时可能导致远程漏洞执行
    S2-046 — Possible RCE when performing file upload based on Jakarta Multipart parser (similar to S2-045)
			 类似S2-045 同样是Jakarta Multipart parser导致的远程漏洞执行
    S2-047 — Possible DoS attack when using URLValidator (similar to S2-044)
			 类似S2-044 使用URLValidator导致DoS攻击
    S2-048 — Possible RCE in the Struts Showcase app in the Struts 1 plugin example in Struts 2.3.x series
			 Struts 2.3.x系列中启用Struts 1中的插件Showcase app导致远程代码执行
    S2-049 — A DoS attack is available for Spring secured actions
			 使用Spring AOP功能可能导致DoS攻击
    S2-050 — A regular expression Denial of Service when using URLValidator (similar to S2-044 & S2-047)
			 (类似S2-044、S2-047)使用URLValidator可能导致DoS(正则过滤不完整)
    S2-051 — A remote attacker may create a DoS attack by sending crafted xml request when using the Struts REST plugin
			 在使用Struts REST插件的时候，通过发送特定的xml请求可能导致DoS
    S2-052 — Possible Remote Code Execution attack when using the Struts REST plugin with XStream handler to handle XML payloads
			 当使用Struts REST插件以及XStream handler处理XML payload时可能导致远程代码执行
    S2-053 — A possible Remote Code Execution attack when using an unintentional expression in Freemarker tag instead of string literals
			 在Freemarker标签中使用无意的表达式可能导致远程代码执行
	
#简单分析
***
阅读过官方文档之后可以把漏洞出现的地方简单归纳一下：		
	
1. 自带的拦截器、匹配机制
2. token机制
3. 插件
4. 标签
5. 方法(Method)、对象(Object)、类(Class)、参数(parameter)
6. Web app
7. 表达式
8. 生成的页面
9. 