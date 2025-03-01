## Spring Authorization Server

此项目实现了Spring Authorization Server的0.4.0版本，因此在一次项目中需要在java 8的版本进行开发，所以只能使用此版本。
此项目使用了公钥私钥对称加密，私钥制作方法参看了小伙伴https://bbs.huaweicloud.com/blogs/388775。
请注意我使用的是

``<dependency>

    <groupId>org.springframework.security</groupId>
    
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    
    <version>0.4.0</version>
    
</dependency>``
由于此版本的官方文档比较难找，我将连接放在此处https://docs.spring.io/spring-authorization-server/docs/0.4.0/reference/html/getting-started.html
项目中的用户数据库自行参考java实体构建把，另外还需要默认的数据库表来自于``Spring Authorization Server``在其源码中可以找到sql脚本(在项目中我已上传到资源目录)
最终完成了Spring Authorization Server的授权中心开发，在完结此项目中查阅了很多其他小伙伴的项目和博客感谢他们。
