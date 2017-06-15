package cn.mldn.shiro.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;

@SuppressWarnings("serial")
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		// 现在假设通过表单传递到Servlet上的参数有两个
		String mid = req.getParameter("mid") ;
		String password = req.getParameter("password") ;
		// 在WEB项目启动的时候实际上会自动进行一些环境的配置项。
		UsernamePasswordToken token = new UsernamePasswordToken(mid, password) ;
		String path = "/login.jsp" ; 	// 定义一个默认的跳转路径
		try {
			SecurityUtils.getSubject().login(token); 	// 实现登录了
			path = "/pages/welcome.jsp" ;	// 现在登录成功了，则应该跳转到指定的路径
		} catch (Exception e) {
			req.setAttribute("error", e.getMessage());
			e.printStackTrace();
		}
		req.getRequestDispatcher(path).forward(req, resp);
	}
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		this.doGet(req, resp);
	}
}
