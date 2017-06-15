package cn.mldn.shiro.realm;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.Resource;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.cas.CasToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidator;

import cn.mldn.shiro.service.IMemberService;

public class MemberRealm extends CasRealm {
	@Resource
	private IMemberService memberService;
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
			throws AuthenticationException {
		
		System.out.println("=================================== 1、进行认证操作处理 ======================================");
		// CAS认证之后需要返回用户名和票根数据，那么现在需要进行两方面的处理，一方面是进行票根检测，另外一方面是进行用户名的数据返回
		CasToken casToken = (CasToken) token ; 	// 接收CAS返回的Token数据
		if(casToken == null){	// 没有返回CAS的认证的Token信息，则表示认证出现问题
			return null ;	// 此处没有认证信息返回
		}
		String ticket = (String) casToken.getCredentials() ;	// 取得认证的票根数据
		// 如果此时返回的CAS票根不正确，那么将出现错误
		if(!org.apache.shiro.util.StringUtils.hasText(ticket)){	// 现在需要进行票根数据的检测处理
			return null ; 	// 此时没有认证信息返回
		}
		TicketValidator ticketValidator = super.ensureTicketValidator() ;	// 需要确保票根是正确的
		try{
			// 现在可以确一个CAS的检测结果
			Assertion casAssertion = ticketValidator.validate(ticket, super.getCasService()) ;	// 进行票根验证处理
			// 通过cas还可以获取用户名
			AttributePrincipal casPrincipal = casAssertion.getPrincipal() ;	// 获取用户信息
			String mid = casPrincipal.getName() ;	// 获取用户名
			// 需要设置一个集合，以返回所有的所需要的信息
			List principals = CollectionUtils.asList(mid,casPrincipal.getAttributes()) ;	// 获得用户信息
			PrincipalCollection collection = new SimplePrincipalCollection(principals, super.getName()) ;
			return new SimpleAuthenticationInfo(collection, ticket);
		} catch (Exception e){
			e.printStackTrace();
		}
		return super.doGetAuthenticationInfo(token);
	}
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		System.out.println("++++++++++++++ 2、进行授权操作处理 ++++++++++++++");
		// 该操作的主要目的是取得授权信息，说的直白一点就是角色和权限数据
		SimpleAuthorizationInfo auth = new SimpleAuthorizationInfo();
		// 执行到此方法的时候一定是已经进行过用户认证处理了（用户名和密码一定是正确的）
		String mid = (String) principals.getPrimaryPrincipal(); // 取得用户名
		Map<String, Set<String>> map = this.memberService.getRoleAndAction(mid);
		auth.setRoles(map.get("allRoles")); // 保存所有的角色
		auth.setStringPermissions(map.get("allActions")); // 保存所有的权限
		return auth;
	}
}
