package pl.alex.api_gateway;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
class JwtService {

  @Value("${jwt.secret}")
  private String secret;
  @Value("${jwt.expiration:7200000}")
  private long expiration;

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public boolean isTokenExpired(String token) {
    return extractAllClaims(token).getExpiration().before(new Date());
  }

  private Date extractExpiration(String token) {
    return extractAllClaims(token).getExpiration();
  }

  private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(getPublicSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  private SecretKey getPublicSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(this.secret);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}

