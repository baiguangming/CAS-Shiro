package cn.mldn.shiro.service;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;

public interface IEmpService {
	@RequiresAuthentication
	public void add() ;
	@RequiresRoles("dept")
	public void edit() ;
	@RequiresPermissions("news:add")
	public void delete() ;
}
