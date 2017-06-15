package cn.mldn.shiro.action;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

//@Controller
public class PageAction {
	//@RequestMapping("/loginPage")
	public ModelAndView login() {
		ModelAndView mav = new ModelAndView("/login.jsp");
		return mav;
	}
}
