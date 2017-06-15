package cn.mldn.shiro.realm.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
// 覆写已有的登录检测过滤器
public class DefaultFormAuthenticationFilter extends FormAuthenticationFilter {
	private String randname = "rand" ;	// session生成的验证码
	private String randparam = "code" ;	// 用户输入的验证码的参数名称
	@Override
	protected boolean onAccessDenied(ServletRequest request,
			ServletResponse response) throws Exception {	// 进行访问拒绝的处理
		// 1、首先应该想办法获取输入的验证码内容
		HttpServletRequest req = (HttpServletRequest) request ;
		HttpSession session = req.getSession() ;
		String rand = (String) session.getAttribute(this.randname) ;
		// 2、接收用户输入的参数
		String code = request.getParameter(this.randparam) ;	// 用户的输入验证码信息
		if (rand == null || code == null || "".equals(code) || "".equals(rand)) {
			req.setAttribute("error", "验证码不允许为空！");
			return true ;
		} else {	// 不为空，则要进行验证码的内容检测
			if (!rand.equalsIgnoreCase(code)) {	// 验证码有错误
				req.setAttribute("error", "验证码输入错误！");
				return true ;
			}
		}
		return super.onAccessDenied(request, response) ;	// 交给原始的实现处理
	}
	public void setRandparam(String randparam) {
		this.randparam = randparam;
	}
	public void setRandname(String randname) {
		this.randname = randname;
	}
}
