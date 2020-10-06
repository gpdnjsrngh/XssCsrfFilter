package util;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

public class CSRFFilter extends OncePerRequestFilter {
	private static final Logger logger = LoggerFactory.getLogger(CSRFFilter.class);

	@Override
	public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		logger.debug("========================= " + "START checkCSRF >>>>");
		
		String url = request.getRequestURL().toString().trim();
		String uri = request.getRequestURI().toString().trim();
		String referrer = request.getHeader("REFERER");
		
		String prefix = url.replace(request.getServletPath(), "");
		
		// CSRF 공격 필터링에서 통과되는 경우
		// (1) 앱에서 접근할 때(referrer==null)
		// (2) request와 동일한 host, port, context 에서 요청하는 경우
		if(referrer==null
				||referrer.length()==0
				||referrer.startsWith(prefix)) {
			logger.debug("REQUEST URI : " + uri);
			logger.debug("REFERRER : " + referrer);
			logger.debug( "<<<< checkCSRF END" + "========================= ");
			filterChain.doFilter(request, response);
		}
		
		// CSRF 공격이 의심되는 경우
		// (1) request와 다른 host 또는 port 또는 context 에서 요청하는 경우 
		else {
			logger.error("CSRF: Sucessfully defended against CSRF attacks.");
			logger.error("REQUEST URI : " + uri);
			logger.error("REFERRER : " + referrer);
			response.sendRedirect(request.getContextPath() + "/error/error.jsp");
			logger.debug( "<<<< checkCSRF END" + "========================= ");
		}
		
	}

}