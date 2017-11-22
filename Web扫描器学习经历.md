感谢刘璇前辈写的《白帽子讲Web扫描》</br>
实习期间、平时日常进行测试期间用过很多的扫描器，于是乎产生了编写一个更加人性化、更加实用的扫描器的想法。但是苦于没有很系统的了解过，以至于各种功能较为零散，无法串联在一起。这时候刚好看到了刘璇前辈的这本书。只是简单的看了目录，我就觉得，嗯 这就是我想要找的书了。而且书中的很多内容不仅解决了我当初设计功能时的问题，还大大提高了我的知识面， 哦 原来还有这种解决方法的啊！</br>
扫描器类型</br>
按照使用场景区分</br>
1、主动形</br>
软件：AWVS、Nessus、</br>
硬件：绿盟等国内厂家</br>
优点：功能强大</br>
缺点：需要安装、部署，存在单机性能瓶颈、相比于云端形不易于横向扩展</br>
2、被动形</br>
通过中间代理或流量镜像的方式发现可能存在的安全缺陷或漏洞。</br>
常见的两种工作模式：</br>
代理模式：真实流量流经代理服务器，进行被动分析、检测</br>
旁路模式：硬件为主，获取流量镜像进行会话重组和协议解析，匹配安全特征或者动态沙盒进行检测</br>
优点：不产生新流量，不对扫描目标产生额外风险</br>
缺点：被动方式，属于事中对抗、监测 一旦被绕过，难以止损</br>
3、云端形(SaaS)</br>
采用B/S结构，通过云端对目标进行扫描。</br>
例如：百度--云扫描，360--WebScan，安赛--AIScanner</br>
优点：跨平台、 易于横向扩展 进行大规模扫描</br>
缺点：实现复杂、难度较大 例如：云端任务分发和调度、 资源的分配和利用等</br>
</br>
常见扫描器：</br>
1、AWVS</br>
2、Burp Suite</br>
3、Tenable's Passive Vulnerability Scanner</br>
4、作者的TeyeScan(网上找不到 关了？)</br>
5、OWASP的 ZAP</br>
6、AppScan</br>
等等等等 下面的sectoolmarket有更加多的</br>
在线的扫描器测评报告</br>
[sectoolmarket](http://www.sectoolmarket.com/price-and-feature-comparison-of-web-application-scanners-unified-list.html)</br>
漏洞测试平台</br>
Wavsep</br>
部署需要JDK+Tomcat+MySQL</br>
环境</br>
PyQT--Python版本的QT 用于调用C++开发框架 这里主要用的是他的QtWebKit模块(实现对开源浏览器引擎WebKit的封装)</br>
WebKit</br>
三部分组成: WebCore排版引擎核心、JSCore引擎、WebKit移植层</br>
Ghost.py</br>
Python封装的WebKit 便于对浏览器引擎进行交互</br>
Memory_profiler</br>
第三方内存监控模块 用于逐行测量代码的内存使用 相对的会让代码的运行变慢</br>
测试框架</br>
Unittest、Pytest和Nose</br>
Emmm 比较而言 Nose较为容易上手</br>
***
爬虫基础</br>
手爬(手工爬取？)</br>
打开浏览器--输入URL--访问页面--点击所有可点击的按钮--记录下所有的页面--对所记录的页面再次进行访问--对新访问的页面进行记录--重复上面三个步骤直至没有新的页面</br>
优点：与人的日常行为类似、过程便于理解</br>
缺点：细节过程并不知道 工作量大 </br>
列举一下较为详细的B/S客户端(相比而言着重分析爬虫将会经历的步骤)：</br>
1、用户输入一个URL 浏览器从主线程中创建一个子线程 子线程获取URL后进行一下的操作</br>
2、子线程先在本地DNS缓存中查找URL--IP之间的映射(DNS解析) 如果有则直接访问对应的IP 没有则通过DNS服务器进行查询 获取到目标的IP</br>
3、与目标服务器建立连接、 发送HTTP请求 待服务器完成请求的处理后 接收HTTP响应</br>
4、浏览器接收到响应后在本地对响应进行解析、处理、渲染 最终把相应页面呈现给用户</br>
URL</br>
爬虫想要获取到下一个页面就必须获取到URL中的内容</br>
URL结构(摘自Wiki)</br>
    `scheme:[//[user[:password]@]host[:port]][/path][?query][#fragment]`
scheme--模式/协议 告诉浏览器如何处理将要打开的文件 爬虫常见协议HTTP/HTTPS</br>
user:password@-- 访问资源所需要的用户凭证 这个见得最多是在ftp协议里面 HTTP/HTTPS协议里面很少见</br>
host:port-- 主机以及端口(默认80 非默认必须加上 这里可以直接用域名代替 而非主机+端口号)</br>
/path-- 存放的路径 相对路径 以服务器web服务的根文件为起点</br>
?query-- GET方法下查询的参数、 ?为起点 参数之间以&隔开 =后跟参数值 通常会以UTF-8进行编码</br>
 #fragment  指向同一页面中的某个位置</br>
绝对URL? 相对URL?</br>
HTTP协议</br>
作用于应用层</br>
版本-- 1.0 1.1 2.0 (0.9就比较旧了)</br>
HTTP请求</br>
三部分组成： 请求行、 请求报头、 请求正文</br>
1、 请求行</br>
格式</br>
    `Method SP Requests-URI SP HTTP-Version CRLF`</br>
以请求的方法开头， 后面跟请求的URI和协议的版本 之间用空格分开</br>
2、请求报头</br>
又key/value组成 中间: 分开</br>
常见请求头	
	
	Accept:								设置浏览器可以接受的MIME类型
	Accept-Charset:						浏览器可以接受的字符集
	Accept-Encoding:					浏览器能进行解码的数据编码方式		
	Accept-Language:					浏览器所希望的语言种类，当服务器能提供一种以上的语言版本时要用到		
	Authoritarian:						授权信息 通常出现在对服务器发送WWW-Authenticate头的应答当中
	Connection:							表示是否需要持久连接
	Content-Length:						请求消息正文的长度
	Cookie:								
	Host:								初始URL中的主机和端口
	If-Modified-Since:					只有当所请求的内容在指定的日期之后又经过修改才返回 否则返回304"Not Modified"
	Referer:							包含一个URL 表示用户从该URL出发访问当前请求页面
	User-Agent:							浏览器类型
更多的标准、 非标准头看这[https://en.wikipedia.org/wiki/List_of_HTTP_header_fields](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields)</br>
3、请求正文</br>
请求报头中的Content-Type和Content-Length来指定数据类型和数据长度</br>
标准的HTTP请求格式如下</br>
	
	Request   = Request-Line
				* (( general-header
				| request-header
				| entity-header ) CRLF
				CRLF
				[ message-body ]
</br>
	
	GET /js/m.js HTTP/1.1
	Host: cbjs.baidu.com
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0
	Accept: */*
	Accept-Language: zh,zh-CN;q=0.8,en-US;q=0.5,en;q=0.3
	Accept-Encoding: gzip, deflate
	Referer: http://www.codesec.net/view/54372.html
	Cookie: xxxxxxxxxxxxxxxxxxxxxxxx
	Connection: close
	If-Modified-Since: Tue, 21 Nov 2017 12:17:51 GMT
	If-None-Match: "5a14196f-7ed0"
</br>
HTTP相应</br>
三部分组成: 响应行、 响应头、 相应全文</br>
1、 响应行</br>
格式 </br>	
    `HTTP-Version SP Status-Code SP Reason-Phrase CRLF` </br>
HTTP-Version 表示服务器HTTP协议的版本 Status-Code表示服务器发回的响应代码 Reason-Phrase 表示状态代码的文本描述</br>
常见响应代码		
	
	1XX -- 临时响应
		100  继续提出请求 服务器已收到请求的部分 正在等待剩余部分
		101 切换协议 服务器已确认并已准备切换
	2XX -- 成功
		200  成功
		201  请求成功 服务器创建了新的资源
		202  服务器已接受请求 但尚未处理
		203  未授权信息 服务器已经处理了请求 但响应可能是来自另外一个源
		204  无内容 服务区处理了请求 但是没有返回任何内容
		205  重置内容 服务器处理了请求 但没有返回任何内容
		206  部分内容 服务器处理了部分GET请求
	3XX -- 重定向
		表示要完成的请求需要更进一步操作
		300  多种选择 针对请求 服务器可执行多种操作
		301  永久移动 请求的网页已经永久移动到新位置
		302  临时移动 服务器目前从不同位置的网页响应请求 但请求者继续使用原有位置来进行以后的请求
		303  查看其他位置  请求者应当对不同的位置使用单独的GET请求来检索响应 服务器返回此代码
		304  未修改 自动上次请求后 请求的网页未修改过
		305  使用代理 请求者只能使用代理访问请求的页面
		307  临时重定向 服务器目前从不不同位置的网页响应请求 请求者应该继续使用原有位置进行请求
	4XX -- 请求错误
