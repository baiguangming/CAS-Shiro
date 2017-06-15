package cn.mldn.shiro.dao;

import cn.mldn.shiro.vo.Member;

public interface IMemberDAO {
	/**
	 * 根据用户编号查询用户对应的完整信息
	 * @param mid 用户编号
	 * @return 如果有用户则以VO返回，如果没有返回null
	 */
	public Member findById(String mid) ;
}
