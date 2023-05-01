package ma.projet.demo.config;

import org.springframework.context.annotation.Bean; 
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;



@Configuration
public class ProjectSecurityConfig {

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests((auth) -> auth.requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards")
				.authenticated().requestMatchers("/notices", "/contact").permitAll())
				.formLogin((form) -> form.loginPage("/login").permitAll().defaultSuccessUrl("/myAccount"))
				.logout((logout) -> logout.logoutSuccessUrl("/login")).httpBasic(Customizer.withDefaults()).csrf()
				.disable();
		return http.build();

	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
