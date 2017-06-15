<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>
<shiro:guest>
	未登录的用户可见。
</shiro:guest>
<shiro:notAuthenticated>
<%!
	public static final String LOGIN_URL = "login.jsp" ;
%>
<%
	String obj = (String) request.getAttribute("error") ;
if (obj != null) {
	if (obj.contains("UnknownAccountException")) {
%>
		该账户不存在！
<%
	}
}
%>
<h1><%=obj%></h1>
<form action="<%=LOGIN_URL%>" method="post">
	用户名：<input type="text" name="mid" id="mid"><br>
	密&nbsp;码：<input type="password" name="password" id="password"><br>
	验证码：<input type="text" name="code" id="code" size="4" maxlength="4"><img src="image.jsp"><br>
	<input type="checkbox" name="rememberme" value="true">记住密码<br>
	<input type="submit" value="登录">
</form>  
</shiro:notAuthenticated>
</body>
</html>