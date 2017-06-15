package cn.mldn.shiro.service;

import java.util.Map;
import java.util.Set;

import cn.mldn.shiro.vo.Member;

public interface IMemberService {
	/**
	 * 根据用户编号取得用户的ID信息
	 * @param mid 用户编号
 	 * @return 取得了用户数据则返回VO，否则返回null
	 */
	public Member get(String mid) ;
	/**
	 * 是根据用户编号查询出用户对应的所有角色和权限数据，执行如下调用：<br>
	 * 1、执行IRoleDAO.findAllIdByMember()；<br>
	 * 2、执行IActionDAO.findAllIdByMember()；<br>
	 * @param mid 用户编号
	 * @return 返回的内容包括如下数据：<br>
	 * 1、key = allRoles、value = Role标记集合；<br>
	 * 2、key = allActions、value = Action标记集合。<br>
	 */
	public Map<String,Set<String>> getRoleAndAction(String mid) ;
}
