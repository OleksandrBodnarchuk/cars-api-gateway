package pl.alex.api_gateway;

import javax.naming.AuthenticationException;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import pl.alex.api_gateway.AuthHeaderFilter.Config;

@Slf4j
@Component
class AuthHeaderFilter extends AbstractGatewayFilterFactory<Config> {

  private final JwtService jwtService;

  public AuthHeaderFilter(JwtService jwtService) {
    super(Config.class);
    this.jwtService = jwtService;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      try {
        log.info("Incoming request: {} {}", exchange.getRequest().getMethod().name(),
            exchange.getRequest().getPath());
        String accessToken = exchange.getRequest().getHeaders().get(config.getHeaderName())
            .stream()
            .findFirst()
            .orElseThrow();
        if (accessToken.contains("Bearer")) {
          accessToken = accessToken.replace("Bearer ", "").trim();
        }
        if (jwtService.isTokenExpired(accessToken)) {
          log.error("Token expired");
          throw new AuthenticationException();
        }
        return chain.filter(exchange);
      } catch (Exception ex) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
      }
    };
  }


  @Getter
  @Setter
  @Builder
  static class Config {

    private String headerName;
  }
}
