package cn.mldn.shiro.dao;

import java.util.Set;

public interface IRoleDAO {
	/**
	 * 根据用户的编号查询出所有的角色的ID（标记信息）
	 * @param mid 用户编号
	 * @return 全部的用户角色
	 */
	public Set<String> findAllIdByMember(String mid) ;
}
