package cn.mldn.shiro.dao;

import java.util.Set;

public interface IActionDAO {
	/**
	 * 根据用户编号查询出该用户具备的所有权限数据
	 * @param mid 用户编号
	 * @return 所有权限标记
	 */
	public Set<String> findAllIdByMember(String mid) ;
}
