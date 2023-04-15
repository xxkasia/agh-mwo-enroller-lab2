package security;

import com.company.enroller.persistence.ParticipantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    @Value("${security.secret}")
    String secret;
    @Value("${security.issuer}")
    String issuer;
    @Value("${security.token_expiration_in_seconds}")
    int tokenExpiration;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    ParticipantService participantService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .addFilterBefore(new JWTAuthenticationFilter(authenticationManager(), secret, issuer, tokenExpiration), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(participantProvider).passwordEncoder(passwordEncoder);
    }
}
