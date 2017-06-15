package cn.mldn.shiro.base;

import java.sql.JDBCType;

import org.apache.shiro.realm.jdbc.JdbcRealm;


public class TestShiro {
	public static void main(String[] args) {
			
		// 明确的表示现在进行认证信息处理的操作通过ini文件来进行读取，该配置文件在classpath中
		org.apache.shiro.util.Factory<org.apache.shiro.mgt.SecurityManager> factory = new org.apache.shiro.config.IniSecurityManagerFactory(
				"classpath:shiro.ini");
		// 如果要进行用户名和密码的检测，那么就必须取得SecurityManager接口对象
		// 此时实际上SecuritManager可以管理的用户的认证信息只在shiro.ini文件中进行了定义
		org.apache.shiro.mgt.SecurityManager securityManager = factory
				.getInstance();
		// 将所有的用户的认证信息交给一个统一的安全工具处理类，以后所有的处理由此类负责
		org.apache.shiro.SecurityUtils.setSecurityManager(securityManager);
		// 如果要进行用户的认证检测处理那么需要取得Subject接口对象
		org.apache.shiro.subject.Subject subject = org.apache.shiro.SecurityUtils
				.getSubject();
		// 处理用户名和密码需要进行包装处理
		org.apache.shiro.authc.UsernamePasswordToken token = new org.apache.shiro.authc.UsernamePasswordToken(
				"mermaid", "hello");
		subject.login(token);
		// 用户登录之后，每一个用户信息都使用Subject接口对象来描述
		System.out.println(subject.getPrincipal()); 	// 用户名
	}
}
