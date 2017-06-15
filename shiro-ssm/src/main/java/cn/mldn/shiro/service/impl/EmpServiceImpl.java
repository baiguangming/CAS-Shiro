package cn.mldn.shiro.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import cn.mldn.shiro.service.IEmpService;
@Service
public class EmpServiceImpl implements IEmpService {
	private Logger log = LoggerFactory.getLogger(super.getClass());
	@Override
	public void add() {
		this.log.info("**************** 【EmpService.add()】 ****************");
	}

	@Override
	public void edit() {
		this.log.info("**************** 【EmpService.edit()】 ****************");
	}

	@Override
	public void delete() {
		this.log.info("**************** 【EmpService.delete()】 ****************");
	}

}
