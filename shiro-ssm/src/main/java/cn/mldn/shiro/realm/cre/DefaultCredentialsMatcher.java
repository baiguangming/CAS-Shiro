package cn.mldn.shiro.realm.cre;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

import cn.mldn.util.enctype.PasswordUtil;
/**
 * 主要是负责密文的认证信息的比对处理操作
 * @author mldn
 */
public class DefaultCredentialsMatcher extends SimpleCredentialsMatcher {
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token,
			AuthenticationInfo info) {
		// 对原始的数据进行加密处理
		Object tokenCredentials = PasswordUtil.getPassword(super.toString(token.getCredentials())) ;
		Object accountCredentials = super.getCredentials(info) ;	// 取得Realm返回的认证操作
		return super.equals(tokenCredentials, accountCredentials) ;
	}
}
