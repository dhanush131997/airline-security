package com.capgemini.airlinereservationsystemsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.capgemini.airlinereservationsystemsecurity.filter.CustomUsernamePasswordAuthenticationFilter;
import com.capgemini.airlinereservationsystemsecurity.handlers.UserLogoutSuccessHandler;
import com.capgemini.airlinereservationsystemsecurity.security.AirlineManagmentSystemAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class AirlineManagementSystemSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private AirlineManagmentSystemAuthenticationEntryPoint  airlineAuthenticationEntryPoint;
	
	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	
	@Autowired
	private AuthenticationFailureHandler authenticationFailureHandler;
	
	@Autowired
	private UserLogoutSuccessHandler userLogoutSuccessHandler;
	
	@Bean
	public UsernamePasswordAuthenticationFilter getUsernamePasswordAuthenticationFilter() throws Exception{
		CustomUsernamePasswordAuthenticationFilter filter = new CustomUsernamePasswordAuthenticationFilter();
		filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		filter.setAuthenticationFailureHandler(authenticationFailureHandler);
		filter.setAuthenticationManager(authenticationManager());
		return filter;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder login) throws Exception {
		login.userDetailsService(userDetailsService);
	}
	
	@Override
	protected void configure(HttpSecurity http)throws Exception {
		http.csrf().disable()
		.exceptionHandling()
		.authenticationEntryPoint(airlineAuthenticationEntryPoint)
		.and()
		.authorizeRequests()
		.antMatchers("/forgot-password").permitAll()
		.and()
		.authorizeRequests()
		.antMatchers("/change-password").permitAll()
		.and()
		.authorizeRequests()
		.antMatchers("/getAllFlights").permitAll()
		.and()
		.authorizeRequests()
		.antMatchers("getFlightDetails").permitAll()
		.and()
		.authorizeRequests()
		.antMatchers("/register").permitAll()
		.and()
		.authorizeRequests()
		.antMatchers("/flightRegister").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/updateFlight").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/updateUser").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/getAllUsers").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/deleteFlight").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/getUser").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/getAllFlights").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/ticketBooking").hasRole("USER")
		.and()
		.authorizeRequests()
		.antMatchers("/getTicket").hasRole("USER")
		.and()
		.authorizeRequests()
		.antMatchers("/deleteTicket").hasRole("USER")
		.and()
		.addFilterBefore(getUsernamePasswordAuthenticationFilter(), CustomUsernamePasswordAuthenticationFilter.class)
		.logout()
		.logoutSuccessHandler(userLogoutSuccessHandler)
		.and()
		.cors();
		
	}
}
